package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
)

const oauthAuthorizationRetention = 24 * time.Hour

type OAuthFlowType string

const (
	OAuthFlowDevice       OAuthFlowType = "device"
	OAuthFlowCallbackPKCE OAuthFlowType = "callback_pkce"
)

func (f OAuthFlowType) Valid() bool {
	return f == OAuthFlowDevice || f == OAuthFlowCallbackPKCE
}

type OAuthAuthorization struct {
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresIn    int       `json:"expires_in,omitempty"`
	AuthorizedAt time.Time `json:"authorized_at,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// OAuthPendingPayload is durable only while a callback-PKCE session is pending.
// It deliberately excludes raw state, authorization code, and user identity JWTs.
type OAuthPendingPayload struct {
	Verifier    string
	RedirectURI string
	ExpiresAt   time.Time
}

type oauthPendingPayloadWire struct {
	Verifier    string    `json:"verifier"`
	RedirectURI string    `json:"redirect_uri"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func encodeOAuthPendingPayload(pending *OAuthPendingPayload) *oauthPendingPayloadWire {
	if pending == nil {
		return nil
	}
	return &oauthPendingPayloadWire{
		Verifier:    pending.Verifier,
		RedirectURI: pending.RedirectURI,
		ExpiresAt:   pending.ExpiresAt,
	}
}

func decodeOAuthPendingPayload(raw json.RawMessage) (*OAuthPendingPayload, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	pending := new(OAuthPendingPayload)
	for _, field := range []struct {
		key         string
		destination any
	}{
		{"verifier", &pending.Verifier},
		{"redirect_uri", &pending.RedirectURI},
		{"expires_at", &pending.ExpiresAt},
	} {
		if value, ok := fields[field.key]; ok {
			if err := json.Unmarshal(value, field.destination); err != nil {
				return nil, err
			}
		}
	}
	return pending, nil
}

type OAuthSession struct {
	Provider provider.Kind
	FlowType OAuthFlowType

	// State is encrypted only for the legacy device flow. Callback state is
	// represented durably only by StateHash and is never recoverable as plaintext.
	State     string
	StateHash []byte

	DeviceCode, UserCode, VerificationURI, VerificationURIComplete, TokenEndpoint string
	Pending                                                                       *OAuthPendingPayload
	PollInterval                                                                  time.Duration
	ExpiresAt                                                                     time.Time
	Status, SanitizedError, AccountID                                             string
	Authorization                                                                 *OAuthAuthorization
	CreatedAt, UpdatedAt                                                          time.Time
}

type oauthEncryptedPayload struct {
	State                   string               `json:"state,omitempty"`
	DeviceCode              string               `json:"device_code,omitempty"`
	UserCode                string               `json:"user_code,omitempty"`
	VerificationURI         string               `json:"verification_uri,omitempty"`
	VerificationURIComplete string               `json:"verification_uri_complete,omitempty"`
	TokenEndpoint           string               `json:"token_endpoint,omitempty"`
	Pending                 *OAuthPendingPayload `json:"pending,omitempty"`
	Authorization           *OAuthAuthorization  `json:"authorization,omitempty"`
	AccountID               string               `json:"account_id,omitempty"`
}

type oauthEncryptedPayloadWire struct {
	State                   string                   `json:"state,omitempty"`
	DeviceCode              string                   `json:"device_code,omitempty"`
	UserCode                string                   `json:"user_code,omitempty"`
	VerificationURI         string                   `json:"verification_uri,omitempty"`
	VerificationURIComplete string                   `json:"verification_uri_complete,omitempty"`
	TokenEndpoint           string                   `json:"token_endpoint,omitempty"`
	Pending                 *oauthPendingPayloadWire `json:"pending,omitempty"`
	Authorization           *OAuthAuthorization      `json:"authorization,omitempty"`
	AccountID               string                   `json:"account_id,omitempty"`
}

func decodeOAuthAuthorization(raw json.RawMessage, allowLegacyKeys bool) (*OAuthAuthorization, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	authorization := new(OAuthAuthorization)
	for _, field := range []struct {
		canonicalKey string
		legacyKey    string
		destination  any
	}{
		{"access_token", "AccessToken", &authorization.AccessToken},
		{"refresh_token", "RefreshToken", &authorization.RefreshToken},
		{"id_token", "IDToken", &authorization.IDToken},
		{"token_type", "TokenType", &authorization.TokenType},
		{"expires_in", "ExpiresIn", &authorization.ExpiresIn},
		{"authorized_at", "AuthorizedAt", &authorization.AuthorizedAt},
		{"expires_at", "ExpiresAt", &authorization.ExpiresAt},
	} {
		value, ok := fields[field.canonicalKey]
		if !ok && allowLegacyKeys {
			value, ok = fields[field.legacyKey]
		}
		if ok {
			if err := json.Unmarshal(value, field.destination); err != nil {
				return nil, err
			}
		}
	}
	return authorization, nil
}

func decodeOAuthEncryptedPayload(data []byte, allowLegacyDevice bool) (oauthEncryptedPayload, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return oauthEncryptedPayload{}, err
	}
	var canonical oauthEncryptedPayload
	decode := func(key string, destination any) error {
		raw, ok := fields[key]
		if !ok {
			return nil
		}
		return json.Unmarshal(raw, destination)
	}
	for _, field := range []struct {
		key         string
		destination any
	}{
		{"state", &canonical.State},
		{"device_code", &canonical.DeviceCode},
		{"user_code", &canonical.UserCode},
		{"verification_uri", &canonical.VerificationURI},
		{"verification_uri_complete", &canonical.VerificationURIComplete},
		{"token_endpoint", &canonical.TokenEndpoint},
		{"pending", nil},
		{"authorization", nil},
		{"account_id", &canonical.AccountID},
	} {
		if field.key == "pending" || field.key == "authorization" {
			continue
		}
		if err := decode(field.key, field.destination); err != nil {
			return oauthEncryptedPayload{}, err
		}
	}
	if raw, ok := fields["pending"]; ok {
		var err error
		canonical.Pending, err = decodeOAuthPendingPayload(raw)
		if err != nil {
			return oauthEncryptedPayload{}, err
		}
	}
	if raw, ok := fields["authorization"]; ok {
		var err error
		canonical.Authorization, err = decodeOAuthAuthorization(raw, false)
		if err != nil {
			return oauthEncryptedPayload{}, err
		}
	}
	if !allowLegacyDevice {
		canonical.State = ""
		canonical.DeviceCode = ""
		canonical.UserCode = ""
		canonical.VerificationURI = ""
		canonical.VerificationURIComplete = ""
		canonical.TokenEndpoint = ""
		return canonical, nil
	}
	for _, field := range []struct {
		canonicalKey string
		legacyKey    string
		destination  any
	}{
		{"state", "State", &canonical.State},
		{"device_code", "DeviceCode", &canonical.DeviceCode},
		{"user_code", "UserCode", &canonical.UserCode},
		{"verification_uri", "VerificationURI", &canonical.VerificationURI},
		{"verification_uri_complete", "VerificationURIComplete", &canonical.VerificationURIComplete},
		{"token_endpoint", "TokenEndpoint", &canonical.TokenEndpoint},
		{"authorization", "Authorization", nil},
		{"account_id", "AccountID", &canonical.AccountID},
	} {
		if _, ok := fields[field.canonicalKey]; ok {
			continue
		}
		if field.canonicalKey == "authorization" {
			raw, ok := fields[field.legacyKey]
			if !ok {
				continue
			}
			var err error
			canonical.Authorization, err = decodeOAuthAuthorization(raw, true)
			if err != nil {
				return oauthEncryptedPayload{}, err
			}
			continue
		}
		if err := decode(field.legacyKey, field.destination); err != nil {
			return oauthEncryptedPayload{}, err
		}
	}
	return canonical, nil
}

type OAuthSessionRepository struct {
	db  *sql.DB
	key [32]byte
}

func NewOAuthSessionRepository(db *sql.DB, keys appcrypto.Keys) *OAuthSessionRepository {
	return &OAuthSessionRepository{db: db, key: keys.OAuth()}
}

func stateHash(state string) [32]byte { return sha256.Sum256([]byte(state)) }

func validateOAuthKey(kind provider.Kind, flow OAuthFlowType, state string) error {
	if !kind.Valid() {
		return fmt.Errorf("invalid oauth provider %q", kind)
	}
	if !flow.Valid() {
		return fmt.Errorf("invalid oauth flow type %q", flow)
	}
	if state == "" {
		return errors.New("oauth state is required")
	}
	return nil
}

func (r *OAuthSessionRepository) Create(ctx context.Context, value OAuthSession) error {
	if err := validateOAuthKey(value.Provider, value.FlowType, value.State); err != nil {
		return err
	}
	if value.Status != "" && value.Status != "pending" {
		return errors.New("new oauth session must be pending")
	}
	if value.ExpiresAt.IsZero() {
		return errors.New("oauth session expiry is required")
	}
	switch value.FlowType {
	case OAuthFlowDevice:
		if value.Pending != nil {
			return errors.New("device oauth session cannot contain callback payload")
		}
	case OAuthFlowCallbackPKCE:
		if value.Pending == nil || value.Pending.Verifier == "" || value.Pending.RedirectURI == "" || value.Pending.ExpiresAt.IsZero() {
			return errors.New("callback oauth verifier, redirect URI, and expiry are required")
		}
		if value.DeviceCode != "" || value.UserCode != "" || value.VerificationURI != "" || value.VerificationURIComplete != "" || value.TokenEndpoint != "" || value.Authorization != nil {
			return errors.New("callback oauth session contains device-flow payload")
		}
	}
	now := time.Now().UTC()
	value.Status = "pending"
	value.CreatedAt = now
	value.UpdatedAt = now
	encrypted, err := r.encrypt(value)
	if err != nil {
		return err
	}
	hash := stateHash(value.State)
	_, err = r.db.ExecContext(ctx, `INSERT INTO oauth_sessions(state_hash,provider,flow_type,payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error) VALUES(?,?,?,?,?,?,?,?,?,?)`, hash[:], value.Provider, value.FlowType, encrypted, value.Status, int64(value.PollInterval/time.Second), value.ExpiresAt.Unix(), now.Unix(), now.Unix(), nullString(value.SanitizedError))
	return err
}

func (r *OAuthSessionRepository) Get(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state string) (OAuthSession, error) {
	if err := validateOAuthKey(kind, flow, state); err != nil {
		return OAuthSession{}, err
	}
	hash := stateHash(state)
	value, err := r.scan(r.db.QueryRowContext(ctx, oauthSessionSelect+` WHERE state_hash=? AND provider=? AND flow_type=?`, hash[:], kind, flow))
	if err == nil && flow == OAuthFlowDevice {
		value.State = state
	}
	return value, err
}

func (r *OAuthSessionRepository) GetPending(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state string, now time.Time) (OAuthSession, error) {
	value, err := r.Get(ctx, kind, flow, state)
	if err != nil {
		return OAuthSession{}, err
	}
	if value.Status != "pending" || !now.Before(value.ExpiresAt) {
		return OAuthSession{}, sql.ErrNoRows
	}
	return value, nil
}

func (r *OAuthSessionRepository) GetResumable(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state string, now time.Time) (OAuthSession, error) {
	value, err := r.Get(ctx, kind, flow, state)
	if err != nil {
		return OAuthSession{}, err
	}
	if flow == OAuthFlowDevice && value.Status == "authorized" {
		return value, nil
	}
	if value.Status != "pending" || !now.Before(value.ExpiresAt) {
		return OAuthSession{}, sql.ErrNoRows
	}
	return value, nil
}

func (r *OAuthSessionRepository) ListPending(ctx context.Context, kind provider.Kind, flow OAuthFlowType, now time.Time) ([]OAuthSession, error) {
	if !kind.Valid() || !flow.Valid() {
		return nil, errors.New("valid oauth provider and flow type are required")
	}
	return r.list(ctx, oauthSessionSelect+` WHERE provider=? AND flow_type=? AND status='pending' AND expires_at>? ORDER BY created_at`, kind, flow, now.Unix())
}

func (r *OAuthSessionRepository) ListResumable(ctx context.Context, kind provider.Kind, flow OAuthFlowType, now time.Time) ([]OAuthSession, error) {
	if !kind.Valid() || !flow.Valid() {
		return nil, errors.New("valid oauth provider and flow type are required")
	}
	if flow == OAuthFlowDevice {
		return r.list(ctx, oauthSessionSelect+` WHERE provider=? AND flow_type=? AND ((status='pending' AND expires_at>?) OR status='authorized') ORDER BY created_at`, kind, flow, now.Unix())
	}
	return r.list(ctx, oauthSessionSelect+` WHERE provider=? AND flow_type=? AND ((status='pending' AND expires_at>?) OR status='consumed') ORDER BY created_at`, kind, flow, now.Unix())
}

func (r *OAuthSessionRepository) Authorize(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state string, authorization OAuthAuthorization, now time.Time) error {
	if flow != OAuthFlowDevice {
		return sql.ErrNoRows
	}
	if authorization.AccessToken == "" {
		return errors.New("oauth authorization access token is required")
	}
	return r.mutate(ctx, kind, flow, state, now, []string{"pending"}, func(value *OAuthSession) error {
		if !now.Before(value.ExpiresAt) {
			return sql.ErrNoRows
		}
		value.Status = "authorized"
		value.SanitizedError = ""
		value.Authorization = &authorization
		return nil
	})
}

// Consume atomically makes a callback attempt non-retryable and returns its
// verifier only after the secret-free consumed row has committed.
func (r *OAuthSessionRepository) Consume(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state string, now time.Time) (OAuthPendingPayload, error) {
	if flow != OAuthFlowCallbackPKCE {
		return OAuthPendingPayload{}, sql.ErrNoRows
	}
	var consumed OAuthPendingPayload
	err := r.mutate(ctx, kind, flow, state, now, []string{"pending"}, func(value *OAuthSession) error {
		if !now.Before(value.ExpiresAt) || value.Pending == nil || value.Pending.Verifier == "" || value.Pending.RedirectURI == "" {
			return sql.ErrNoRows
		}
		consumed = *value.Pending
		value.Status = "consumed"
		value.Pending = nil
		value.SanitizedError = ""
		return nil
	})
	if err != nil {
		return OAuthPendingPayload{}, err
	}
	return consumed, nil
}

func (r *OAuthSessionRepository) Complete(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state, accountID string, now time.Time) error {
	if accountID == "" {
		return errors.New("completed oauth session account ID is required")
	}
	from := "authorized"
	if flow == OAuthFlowCallbackPKCE {
		from = "consumed"
	}
	return r.mutate(ctx, kind, flow, state, now, []string{from}, func(value *OAuthSession) error {
		value.Status = "completed"
		value.SanitizedError = ""
		value.AccountID = accountID
		disposeOAuthSecrets(value)
		return nil
	})
}

func (r *OAuthSessionRepository) Fail(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state, sanitized string, now time.Time) error {
	from := []string{"pending", "authorized"}
	if flow == OAuthFlowCallbackPKCE {
		from = []string{"consumed"}
	}
	return r.terminal(ctx, kind, flow, state, "failed", sanitized, now, from)
}

func (r *OAuthSessionRepository) Cancel(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state, sanitized string, now time.Time) error {
	return r.terminal(ctx, kind, flow, state, "cancelled", sanitized, now, []string{"pending", "authorized"})
}

// FailConsumedByHash is the restart-recovery path for callback attempts whose
// raw state was intentionally never persisted. It cannot exchange or consume.
func (r *OAuthSessionRepository) FailConsumedByHash(ctx context.Context, kind provider.Kind, flow OAuthFlowType, hash []byte, sanitized string, now time.Time) error {
	if !kind.Valid() || flow != OAuthFlowCallbackPKCE || len(hash) != sha256.Size {
		return sql.ErrNoRows
	}
	result, err := r.db.ExecContext(ctx, `UPDATE oauth_sessions SET status='failed',updated_at=?,sanitized_error=? WHERE state_hash=? AND provider=? AND flow_type=? AND status='consumed'`, now.UTC().Unix(), nullString(sanitized), hash, kind, flow)
	if err != nil {
		return err
	}
	return requireAffected(result)
}

func (r *OAuthSessionRepository) Expire(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state, sanitized string, now time.Time) error {
	return r.terminal(ctx, kind, flow, state, "expired", sanitized, now, []string{"pending", "authorized"})
}

func (r *OAuthSessionRepository) terminal(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state, to, sanitized string, now time.Time, from []string) error {
	return r.mutate(ctx, kind, flow, state, now, from, func(value *OAuthSession) error {
		value.Status = to
		value.SanitizedError = sanitized
		value.AccountID = ""
		disposeOAuthSecrets(value)
		return nil
	})
}

func disposeOAuthSecrets(value *OAuthSession) {
	value.DeviceCode = ""
	value.UserCode = ""
	value.VerificationURI = ""
	value.VerificationURIComplete = ""
	value.TokenEndpoint = ""
	value.Pending = nil
	value.Authorization = nil
}

func (r *OAuthSessionRepository) Cleanup(ctx context.Context, before time.Time) (int64, error) {
	authorizedBefore := before.Add(-oauthAuthorizationRetention)
	result, err := r.db.ExecContext(ctx, `DELETE FROM oauth_sessions WHERE rowid IN (SELECT rowid FROM oauth_sessions WHERE (status='pending' AND expires_at<?) OR (status='authorized' AND updated_at<?) OR (status IN ('completed','failed','expired','cancelled') AND updated_at<?) LIMIT ?)`, before.Unix(), authorizedBefore.Unix(), before.Unix(), cleanupBatchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type oauthSessionScanner interface {
	Scan(...any) error
}

const oauthSessionSelect = `SELECT state_hash,provider,flow_type,payload_encrypted,status,poll_interval_seconds,expires_at,created_at,updated_at,sanitized_error FROM oauth_sessions`

func (r *OAuthSessionRepository) scan(row oauthSessionScanner) (OAuthSession, error) {
	var value OAuthSession
	var encrypted, status string
	var pollInterval, expiresAt, createdAt, updatedAt int64
	var sanitized sql.NullString
	if err := row.Scan(&value.StateHash, &value.Provider, &value.FlowType, &encrypted, &status, &pollInterval, &expiresAt, &createdAt, &updatedAt, &sanitized); err != nil {
		return OAuthSession{}, err
	}
	if !value.Provider.Valid() || !value.FlowType.Valid() {
		return OAuthSession{}, errors.New("invalid persisted oauth provider or flow type")
	}
	plain, err := appcrypto.Decrypt(r.key, encrypted)
	if err != nil {
		return OAuthSession{}, err
	}
	payload, err := decodeOAuthEncryptedPayload(plain, value.Provider == provider.XAI && value.FlowType == OAuthFlowDevice)
	if err != nil {
		return OAuthSession{}, errors.New("decode encrypted oauth session")
	}
	value.State = payload.State
	value.DeviceCode = payload.DeviceCode
	value.UserCode = payload.UserCode
	value.VerificationURI = payload.VerificationURI
	value.VerificationURIComplete = payload.VerificationURIComplete
	value.TokenEndpoint = payload.TokenEndpoint
	value.Pending = payload.Pending
	value.Authorization = payload.Authorization
	value.AccountID = payload.AccountID
	value.Status = status
	value.PollInterval = time.Duration(pollInterval) * time.Second
	value.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	value.CreatedAt = time.Unix(createdAt, 0).UTC()
	value.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	value.SanitizedError = sanitized.String
	return value, nil
}

func (r *OAuthSessionRepository) encrypt(value OAuthSession) (string, error) {
	state := ""
	if value.FlowType == OAuthFlowDevice {
		state = value.State
	}
	payload, err := json.Marshal(oauthEncryptedPayloadWire{
		State:                   state,
		DeviceCode:              value.DeviceCode,
		UserCode:                value.UserCode,
		VerificationURI:         value.VerificationURI,
		VerificationURIComplete: value.VerificationURIComplete,
		TokenEndpoint:           value.TokenEndpoint,
		Pending:                 encodeOAuthPendingPayload(value.Pending),
		Authorization:           value.Authorization,
		AccountID:               value.AccountID,
	})
	if err != nil {
		return "", err
	}
	return appcrypto.Encrypt(r.key, payload)
}

func (r *OAuthSessionRepository) list(ctx context.Context, query string, args ...any) ([]OAuthSession, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []OAuthSession
	for rows.Next() {
		value, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, value)
	}
	return sessions, rows.Err()
}

func (r *OAuthSessionRepository) mutate(ctx context.Context, kind provider.Kind, flow OAuthFlowType, state string, now time.Time, from []string, mutate func(*OAuthSession) error) error {
	if err := validateOAuthKey(kind, flow, state); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	hash := stateHash(state)
	value, err := r.scan(tx.QueryRowContext(ctx, oauthSessionSelect+` WHERE state_hash=? AND provider=? AND flow_type=?`, hash[:], kind, flow))
	if err != nil {
		return err
	}
	if !containsOAuthStatus(from, value.Status) {
		return sql.ErrNoRows
	}
	originalStatus := value.Status
	if err := mutate(&value); err != nil {
		return err
	}
	value.UpdatedAt = now.UTC()
	encrypted, err := r.encrypt(value)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE oauth_sessions SET payload_encrypted=?,status=?,updated_at=?,sanitized_error=? WHERE state_hash=? AND provider=? AND flow_type=? AND status=?`, encrypted, value.Status, value.UpdatedAt.Unix(), nullString(value.SanitizedError), hash[:], kind, flow, originalStatus)
	if err != nil {
		return err
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	return tx.Commit()
}

func containsOAuthStatus(statuses []string, status string) bool {
	for _, candidate := range statuses {
		if candidate == status {
			return true
		}
	}
	return false
}
