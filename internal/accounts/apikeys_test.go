package accounts

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"supergrok-api/internal/store"
)

func TestAPIKeyLifecycleAndLastUseRateLimit(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repo := store.NewAPIKeyRepository(database.DB)
	service := NewAPIKeyService(repo)
	now := time.Now().UTC().Truncate(time.Second).Add(123 * time.Millisecond)
	service.now = func() time.Time { return now }
	created, err := service.Create(ctx, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Plaintext, APIKeyPrefix) || len(created.Plaintext) < APIKeyPrefixLength() {
		t.Fatalf("invalid plaintext format %q", created.Plaintext)
	}
	listed, err := service.List(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list = %+v, %v", listed, err)
	}
	if !created.Key.CreatedAt.Equal(listed[0].CreatedAt) {
		t.Fatalf("created time = %v, listed = %v", created.Key.CreatedAt, listed[0].CreatedAt)
	}
	if strings.Contains(strings.Join([]string{listed[0].ID, listed[0].Prefix, listed[0].Label}, " "), created.Plaintext) {
		t.Fatal("list exposed plaintext")
	}
	authenticated, err := service.Authenticate(ctx, created.Plaintext)
	if err != nil || authenticated.ID != created.Key.ID {
		t.Fatalf("auth = %+v, %v", authenticated, err)
	}
	var firstUsed int64
	if err := database.DB.QueryRow(`SELECT last_used_at FROM api_keys WHERE id=?`, created.Key.ID).Scan(&firstUsed); err != nil {
		t.Fatal(err)
	}
	if authenticated.LastUsedAt == nil || !authenticated.LastUsedAt.Equal(time.Unix(firstUsed, 0).UTC()) {
		t.Fatalf("returned last use = %v, persisted = %v", authenticated.LastUsedAt, time.Unix(firstUsed, 0).UTC())
	}
	var changesBefore int64
	if err := database.DB.QueryRow(`SELECT total_changes()`).Scan(&changesBefore); err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now.Add(time.Minute) }
	secondAuth, err := service.Authenticate(ctx, created.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if secondAuth.LastUsedAt == nil || secondAuth.LastUsedAt.Unix() != firstUsed {
		t.Fatalf("returned last use = %v, want %d", secondAuth.LastUsedAt, firstUsed)
	}
	var secondUsed int64
	if err := database.DB.QueryRow(`SELECT last_used_at FROM api_keys WHERE id=?`, created.Key.ID).Scan(&secondUsed); err != nil {
		t.Fatal(err)
	}
	if secondUsed != firstUsed {
		t.Fatal("last use was written inside rate limit")
	}
	var changesAfter int64
	if err := database.DB.QueryRow(`SELECT total_changes()`).Scan(&changesAfter); err != nil {
		t.Fatal(err)
	}
	if changesAfter != changesBefore {
		t.Fatalf("throttled authentication changed rows: before=%d after=%d", changesBefore, changesAfter)
	}
	if err := service.Revoke(ctx, created.Key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, created.Plaintext); err == nil {
		t.Fatal("revoked key authenticated")
	}
	if _, err := service.Authenticate(ctx, "sgk_unknown"); err == nil {
		t.Fatal("unknown key authenticated")
	}
	if err := database.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(database.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(created.Plaintext)) {
		t.Fatal("database contains plaintext key")
	}
	var hashCount int
	if err := database.DB.QueryRow(`SELECT count(DISTINCT hex(key_hash)) FROM api_keys`).Scan(&hashCount); err != nil || hashCount != 1 {
		t.Fatalf("hash count = %d, %v", hashCount, err)
	}
}
func APIKeyPrefixLength() int { return 47 }
