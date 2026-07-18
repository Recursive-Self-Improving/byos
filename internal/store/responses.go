package store

import (
	"context"
	"database/sql"
	"time"

	appcrypto "byoo/internal/crypto"
)

type ResponseSession struct {
	ResponseID, UpstreamResponseID, PreviousResponseID, Model, PreferredAccountID string
	Input, Output                                                                 []byte
	Store                                                                         bool
	CreatedAt, ExpiresAt                                                          time.Time
}
type ResponseRepository struct {
	db  *sql.DB
	key [32]byte
}

func NewResponseRepository(db *sql.DB, keys appcrypto.Keys) *ResponseRepository {
	return &ResponseRepository{db: db, key: keys.Transcript()}
}
func (r *ResponseRepository) Put(ctx context.Context, v ResponseSession) error {
	input, err := appcrypto.Encrypt(r.key, v.Input)
	if err != nil {
		return err
	}
	output, err := appcrypto.Encrypt(r.key, v.Output)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO response_sessions(response_id,upstream_response_id,previous_response_id,model,preferred_account_id,input_encrypted,output_encrypted,store,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, v.ResponseID, nullString(v.UpstreamResponseID), nullString(v.PreviousResponseID), v.Model, nullString(v.PreferredAccountID), input, output, boolInt(v.Store), v.CreatedAt.Unix(), v.ExpiresAt.Unix())
	return err
}
func (r *ResponseRepository) Get(ctx context.Context, id string, now time.Time) (ResponseSession, error) {
	var v ResponseSession
	var upstream, previous, account sql.NullString
	var input, output string
	var stored int
	var created, expires int64
	if err := r.db.QueryRowContext(ctx, `SELECT response_id,upstream_response_id,previous_response_id,model,preferred_account_id,input_encrypted,output_encrypted,store,created_at,expires_at FROM response_sessions WHERE response_id=? AND expires_at>?`, id, now.Unix()).Scan(&v.ResponseID, &upstream, &previous, &v.Model, &account, &input, &output, &stored, &created, &expires); err != nil {
		return ResponseSession{}, err
	}
	v.UpstreamResponseID = upstream.String
	v.PreviousResponseID = previous.String
	v.PreferredAccountID = account.String
	v.Store = stored != 0
	v.CreatedAt = time.Unix(created, 0).UTC()
	v.ExpiresAt = time.Unix(expires, 0).UTC()
	var err error
	if v.Input, err = appcrypto.Decrypt(r.key, input); err != nil {
		return ResponseSession{}, err
	}
	if v.Output, err = appcrypto.Decrypt(r.key, output); err != nil {
		return ResponseSession{}, err
	}
	return v, nil
}

func (r *ResponseRepository) GetLink(ctx context.Context, id string, now time.Time) (previousID, preferredAccountID string, err error) {
	var previous, account sql.NullString
	err = r.db.QueryRowContext(ctx, `SELECT previous_response_id,preferred_account_id FROM response_sessions WHERE response_id=? AND expires_at>?`, id, now.Unix()).Scan(&previous, &account)
	return previous.String, account.String, err
}
func (r *ResponseRepository) Cleanup(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM response_sessions WHERE rowid IN (SELECT rowid FROM response_sessions WHERE expires_at<? LIMIT ?)`, before.Unix(), cleanupBatchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
