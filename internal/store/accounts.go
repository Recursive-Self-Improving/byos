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

	appcrypto "byoo/internal/crypto"
)

type AccountCredentials struct {
	Issuer        string          `json:"issuer"`
	Subject       string          `json:"subject"`
	Email         string          `json:"email,omitempty"`
	AccessToken   string          `json:"access_token"`
	RefreshToken  string          `json:"refresh_token,omitempty"`
	IDToken       string          `json:"id_token,omitempty"`
	TokenEndpoint string          `json:"token_endpoint"`
	RawIdentity   json.RawMessage `json:"raw_identity,omitempty"`
}

type Account struct {
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
	if account.Credentials.Issuer == "" || account.Credentials.Subject == "" {
		return Account{}, errors.New("verified issuer and subject are required")
	}
	payload, err := json.Marshal(account.Credentials)
	if err != nil {
		return Account{}, fmt.Errorf("encode credentials: %w", err)
	}
	encrypted, err := appcrypto.Encrypt(r.keys.OAuth(), payload)
	if err != nil {
		return Account{}, err
	}
	fingerprint := r.keys.IdentityFingerprint(account.Credentials.Issuer, account.Credentials.Subject)
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
	_, err = r.db.ExecContext(ctx, `INSERT INTO accounts(id, identity_fingerprint, label, enabled, status, credentials_encrypted, expires_at, last_refresh_at, last_error, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(identity_fingerprint) DO UPDATE SET credentials_encrypted=excluded.credentials_encrypted, status=excluded.status, expires_at=excluded.expires_at, last_refresh_at=excluded.last_refresh_at, last_error=excluded.last_error, updated_at=excluded.updated_at`,
		id, fingerprint[:], account.Label, boolInt(defaultTrue(account.Enabled, account.ID == "")), status, encrypted, expires, nullableUnix(account.LastRefreshAt), nullString(account.LastError), now.Unix(), now.Unix())
	if err != nil {
		return Account{}, fmt.Errorf("upsert account: %w", err)
	}
	return r.GetByFingerprint(ctx, fingerprint)
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
func (r *AccountRepository) MarkReloginRequired(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `UPDATE accounts SET enabled=0,status='relogin_required',last_error='authentication expired; reconnect required',updated_at=unixepoch() WHERE id=?`, id)
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

const accountSelect = `SELECT id, label, enabled, status, credentials_encrypted, expires_at, last_refresh_at, COALESCE(last_error,''), created_at, updated_at FROM accounts`

type scanner interface{ Scan(...any) error }

func (r *AccountRepository) scan(row scanner) (Account, error) {
	var account Account
	var enabled int
	var encrypted string
	var expires, refreshed sql.NullInt64
	var created, updated int64
	if err := row.Scan(&account.ID, &account.Label, &enabled, &account.Status, &encrypted, &expires, &refreshed, &account.LastError, &created, &updated); err != nil {
		return Account{}, err
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
