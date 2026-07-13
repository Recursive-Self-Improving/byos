package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type ModelCapability struct {
	AccountID, Model, DisplayName  string
	Supported                      bool
	SupportsBackendSearch          *bool
	ContextWindow, MaxOutputTokens int64
	ReasoningEfforts               []string
	DiscoveredAt                   time.Time
	Stale                          bool
}
type ModelCapabilityRepository struct{ db *sql.DB }

func NewModelCapabilityRepository(db *sql.DB) *ModelCapabilityRepository {
	return &ModelCapabilityRepository{db: db}
}
func (r *ModelCapabilityRepository) Replace(ctx context.Context, accountID string, values []ModelCapability) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_model_capabilities WHERE account_id=?`, accountID); err != nil {
		return err
	}
	for _, value := range values {
		efforts, _ := json.Marshal(value.ReasoningEfforts)
		var search any
		if value.SupportsBackendSearch != nil {
			search = boolInt(*value.SupportsBackendSearch)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO account_model_capabilities(account_id,model,supported,supports_backend_search,display_name,context_window,max_output_tokens,reasoning_efforts,discovered_at,stale) VALUES(?,?,?,?,?,?,?,?,?,?)`, accountID, value.Model, boolInt(value.Supported), search, nullString(value.DisplayName), value.ContextWindow, value.MaxOutputTokens, string(efforts), value.DiscoveredAt.Unix(), boolInt(value.Stale)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (r *ModelCapabilityRepository) List(ctx context.Context, accountID string) ([]ModelCapability, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT account_id,model,COALESCE(display_name,''),supported,supports_backend_search,COALESCE(context_window,0),COALESCE(max_output_tokens,0),COALESCE(reasoning_efforts,'[]'),discovered_at,stale FROM account_model_capabilities WHERE account_id=? ORDER BY model`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ModelCapability
	for rows.Next() {
		var v ModelCapability
		var supported, stale int
		var search sql.NullInt64
		var efforts string
		var discovered int64
		if err := rows.Scan(&v.AccountID, &v.Model, &v.DisplayName, &supported, &search, &v.ContextWindow, &v.MaxOutputTokens, &efforts, &discovered, &stale); err != nil {
			return nil, err
		}
		v.Supported = supported != 0
		v.Stale = stale != 0
		v.DiscoveredAt = time.Unix(discovered, 0).UTC()
		if search.Valid {
			b := search.Int64 != 0
			v.SupportsBackendSearch = &b
		}
		_ = json.Unmarshal([]byte(efforts), &v.ReasoningEfforts)
		result = append(result, v)
	}
	return result, rows.Err()
}
