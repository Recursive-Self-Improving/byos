package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	appcrypto "byos/internal/crypto"
)

const adminSessionTokenBytes = 32

// AdminSession is the server-side state associated with an opaque browser
// session token. The token itself is never persisted.
type AdminSession struct {
	CSRFSecret [32]byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

// CreatedAdminSession contains the one-time plaintext token that is sent to the
// browser and the server-side state stored for it.
type CreatedAdminSession struct {
	Token   string
	Session AdminSession
}

// AdminSessionRepository persists revocable Web UI sessions. Session tokens
// are hashed and CSRF secrets are encrypted before they reach SQLite.
type AdminSessionRepository struct {
	db  *sql.DB
	key [32]byte
}

func NewAdminSessionRepository(db *sql.DB, keys appcrypto.Keys) *AdminSessionRepository {
	return &AdminSessionRepository{db: db, key: keys.WebSession()}
}

func (r *AdminSessionRepository) Create(ctx context.Context, createdAt, expiresAt time.Time) (CreatedAdminSession, error) {
	createdAt = time.Unix(createdAt.Unix(), 0).UTC()
	expiresAt = time.Unix(expiresAt.Unix(), 0).UTC()
	if !expiresAt.After(createdAt) {
		return CreatedAdminSession{}, errors.New("admin session expiry must follow creation")
	}

	tokenBytes := make([]byte, adminSessionTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return CreatedAdminSession{}, fmt.Errorf("generate admin session token: %w", err)
	}
	var csrfSecret [32]byte
	if _, err := rand.Read(csrfSecret[:]); err != nil {
		return CreatedAdminSession{}, fmt.Errorf("generate admin session CSRF secret: %w", err)
	}
	encrypted, err := appcrypto.Encrypt(r.key, csrfSecret[:])
	if err != nil {
		return CreatedAdminSession{}, fmt.Errorf("encrypt admin session CSRF secret: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))
	if _, err := r.db.ExecContext(ctx, `INSERT INTO admin_sessions(id_hash,csrf_secret_encrypted,created_at,expires_at) VALUES(?,?,?,?)`, hash[:], encrypted, createdAt.Unix(), expiresAt.Unix()); err != nil {
		return CreatedAdminSession{}, fmt.Errorf("create admin session: %w", err)
	}
	return CreatedAdminSession{
		Token: token,
		Session: AdminSession{
			CSRFSecret: csrfSecret,
			CreatedAt:  createdAt,
			ExpiresAt:  expiresAt,
		},
	}, nil
}

func (r *AdminSessionRepository) Get(ctx context.Context, token string, now time.Time) (AdminSession, error) {
	hash := sha256.Sum256([]byte(token))
	var encrypted string
	var created, expires int64
	if err := r.db.QueryRowContext(ctx, `SELECT csrf_secret_encrypted,created_at,expires_at FROM admin_sessions WHERE id_hash=? AND revoked_at IS NULL AND expires_at>?`, hash[:], now.Unix()).Scan(&encrypted, &created, &expires); err != nil {
		return AdminSession{}, err
	}
	secret, err := appcrypto.Decrypt(r.key, encrypted)
	if err != nil {
		return AdminSession{}, fmt.Errorf("decrypt admin session CSRF secret: %w", err)
	}
	if len(secret) != len(AdminSession{}.CSRFSecret) {
		return AdminSession{}, errors.New("invalid admin session CSRF secret")
	}
	var csrfSecret [32]byte
	copy(csrfSecret[:], secret)
	return AdminSession{
		CSRFSecret: csrfSecret,
		CreatedAt:  time.Unix(created, 0).UTC(),
		ExpiresAt:  time.Unix(expires, 0).UTC(),
	}, nil
}

func (r *AdminSessionRepository) Revoke(ctx context.Context, token string, now time.Time) error {
	hash := sha256.Sum256([]byte(token))
	result, err := r.db.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at=? WHERE id_hash=? AND revoked_at IS NULL`, now.Unix(), hash[:])
	if err != nil {
		return fmt.Errorf("revoke admin session: %w", err)
	}
	if err := requireAffected(result); err != nil {
		return err
	}
	return nil
}

func (r *AdminSessionRepository) Cleanup(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE rowid IN (SELECT rowid FROM admin_sessions WHERE expires_at<=? OR (revoked_at IS NOT NULL AND revoked_at<=?) LIMIT ?)`, before.Unix(), before.Unix(), cleanupBatchSize)
	if err != nil {
		return 0, fmt.Errorf("clean admin sessions: %w", err)
	}
	return result.RowsAffected()
}
