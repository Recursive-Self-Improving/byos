package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
)

type AccountCredentials struct {
	Issuer               string          `json:"issuer,omitempty"`
	Subject              string          `json:"subject,omitempty"`
	Email                string          `json:"email,omitempty"`
	AccessToken          string          `json:"access_token,omitempty"`
	RefreshToken         string          `json:"refresh_token,omitempty"`
	IDToken              string          `json:"id_token,omitempty"`
	TokenEndpoint        string          `json:"token_endpoint,omitempty"`
	RawIdentity          json.RawMessage `json:"raw_identity,omitempty"`
	OpaqueToken          string          `json:"opaque_token,omitempty"`
	OpaqueTokenExpiresAt *time.Time      `json:"opaque_token_expires_at,omitempty"`
}

// AccountIdentityFingerprintInput is an explicit provider-scoped identity.
// Callers must select the provider; credentials, tokens, and model names are
// never inspected to infer it.
type AccountIdentityFingerprintInput struct {
	Provider    provider.Kind
	Issuer      string
	Subject     string
	OpaqueToken string
}

type Account struct {
	Provider      provider.Kind
	ID            string
	Label         string
	Enabled       bool
	Status        string
	Credentials   AccountCredentials
	ExpiresAt     *time.Time
	LastRefreshAt *time.Time
	LastError     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type AccountRepository struct {
	db   *sql.DB
	keys appcrypto.Keys
}

func NewAccountRepository(db *sql.DB, keys appcrypto.Keys) *AccountRepository {
	return &AccountRepository{db: db, keys: keys}
}

func (r *AccountRepository) UpsertLogin(ctx context.Context, account Account) (Account, error) {
	if !account.Provider.Valid() {
		return Account{}, fmt.Errorf("account provider: %w", provider.ErrInvalidKind)
	}
	fingerprint, err := r.IdentityFingerprint(AccountIdentityFingerprintInput{
		Provider: account.Provider, Issuer: account.Credentials.Issuer, Subject: account.Credentials.Subject, OpaqueToken: account.Credentials.OpaqueToken,
	})
	if err != nil {
		return Account{}, err
	}
	payload, err := json.Marshal(account.Credentials)
	if err != nil {
		return Account{}, fmt.Errorf("encode credentials: %w", err)
	}
	encrypted, err := appcrypto.Encrypt(r.keys.OAuth(), payload)
	if err != nil {
		return Account{}, err
	}
	now := time.Now().UTC()
	id, err := randomID("acct_")
	if err != nil {
		return Account{}, err
	}
	status := account.Status
	if status == "" {
		status = "ready"
	}
	var expires any
	if account.ExpiresAt != nil {
		expires = account.ExpiresAt.Unix()
	}
	result, err := r.db.ExecContext(ctx, `INSERT INTO accounts(id, provider, identity_fingerprint, label, enabled, status, credentials_encrypted, expires_at, last_refresh_at, last_error, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(identity_fingerprint) DO UPDATE SET credentials_encrypted=excluded.credentials_encrypted, status=excluded.status, expires_at=excluded.expires_at, last_refresh_at=excluded.last_refresh_at, last_error=excluded.last_error, updated_at=excluded.updated_at
		WHERE accounts.provider=excluded.provider`,
		id, account.Provider, fingerprint[:], account.Label, boolInt(defaultTrue(account.Enabled, account.ID == "")), status, encrypted, expires, nullableUnix(account.LastRefreshAt), nullString(account.LastError), now.Unix(), now.Unix())
	if err != nil {
		return Account{}, fmt.Errorf("upsert account: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return Account{}, err
	}
	return r.GetByFingerprint(ctx, fingerprint)
}

// IdentityFingerprint derives a stable provider-scoped account identity. The
// xAI input is deliberately unchanged (issuer NUL subject), preserving legacy
// bytes and deduplication. Devin uses "devin" NUL opaque-token.
func (r *AccountRepository) IdentityFingerprint(input AccountIdentityFingerprintInput) ([32]byte, error) {
	switch input.Provider {
	case provider.XAI:
		if input.Issuer == "" || input.Subject == "" {
			return [32]byte{}, errors.New("verified issuer and subject are required")
		}
		return r.keys.IdentityFingerprint(input.Issuer, input.Subject), nil
	case provider.Devin:
		if input.OpaqueToken == "" {
			return [32]byte{}, errors.New("devin opaque token is required")
		}
		return r.keys.IdentityFingerprint(provider.Devin.String(), input.OpaqueToken), nil
	default:
		return [32]byte{}, fmt.Errorf("account provider: %w", provider.ErrInvalidKind)
	}
}

func (r *AccountRepository) Get(ctx context.Context, id string) (Account, error) {
	return r.scan(r.db.QueryRowContext(ctx, accountSelect+" WHERE id=?", id))
}
func (r *AccountRepository) GetByFingerprint(ctx context.Context, fingerprint [32]byte) (Account, error) {
	return r.scan(r.db.QueryRowContext(ctx, accountSelect+" WHERE identity_fingerprint=?", fingerprint[:]))
}
func (r *AccountRepository) List(ctx context.Context) ([]Account, error) {
	rows, err := r.db.QueryContext(ctx, accountSelect+" ORDER BY created_at, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []Account
	for rows.Next() {
		account, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}
func (r *AccountRepository) Update(ctx context.Context, id, label string, enabled bool) error {
	result, err := r.db.ExecContext(ctx, `UPDATE accounts SET label=?, enabled=?, updated_at=unixepoch() WHERE id=?`, label, boolInt(enabled), id)
	if err != nil {
		return err
	}
	return requireAffected(result)
}
func (r *AccountRepository) MarkReloginRequired(ctx context.Context, id string, kind provider.Kind) error {
	if !kind.Valid() {
		return fmt.Errorf("account provider: %w", provider.ErrInvalidKind)
	}
	result, err := r.db.ExecContext(ctx, `UPDATE accounts SET enabled=0,status='relogin_required',last_error='authentication expired; reconnect required',updated_at=unixepoch() WHERE id=? AND provider=?`, id, kind)
	if err != nil {
		return err
	}
	return requireAffected(result)
}
func (r *AccountRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM accounts WHERE id=?`, id)
	if err != nil {
		return err
	}
	return requireAffected(result)
}

const accountSelect = `SELECT id, provider, label, enabled, status, credentials_encrypted, expires_at, last_refresh_at, COALESCE(last_error,''), created_at, updated_at FROM accounts`

type scanner interface{ Scan(...any) error }

func (r *AccountRepository) scan(row scanner) (Account, error) {
	var account Account
	var enabled int
	var encrypted string
	var expires, refreshed sql.NullInt64
	var created, updated int64
	if err := row.Scan(&account.ID, &account.Provider, &account.Label, &enabled, &account.Status, &encrypted, &expires, &refreshed, &account.LastError, &created, &updated); err != nil {
		return Account{}, err
	}
	if !account.Provider.Valid() {
		return Account{}, fmt.Errorf("account provider: %w", provider.ErrInvalidKind)
	}
	plaintext, err := appcrypto.Decrypt(r.keys.OAuth(), encrypted)
	if err != nil {
		return Account{}, err
	}
	if err := json.Unmarshal(plaintext, &account.Credentials); err != nil {
		return Account{}, errors.New("decode encrypted account credentials")
	}
	account.Enabled = enabled != 0
	account.CreatedAt = time.Unix(created, 0).UTC()
	account.UpdatedAt = time.Unix(updated, 0).UTC()
	account.ExpiresAt = timePtr(expires)
	account.LastRefreshAt = timePtr(refreshed)
	return account, nil
}

func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func defaultTrue(value, fresh bool) bool { return value || fresh }
func nullableUnix(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.Unix()
}
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func timePtr(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	t := time.Unix(value.Int64, 0).UTC()
	return &t
}
func requireAffected(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}
