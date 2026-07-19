package store

import (
	"bytes"
	"context"
	"testing"
	"time"

	appcrypto "byos/internal/crypto"
	"byos/internal/provider"
)

func TestLocalUsageCountersPersistAcrossRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	account, err := NewAccountRepository(first.DB, keys).UpsertLogin(ctx, Account{Provider: provider.XAI, Credentials: AccountCredentials{Issuer: "issuer", Subject: "subject", AccessToken: "token", TokenEndpoint: "endpoint"}})
	if err != nil {
		t.Fatal(err)
	}
	repository := NewLocalUsageRepository(first.DB)
	if err := repository.Add(ctx, account.ID, LocalUsageCounters{Requests: 2, Failures: 1, InputTokens: 20, OutputTokens: 5}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Add(ctx, account.ID, LocalUsageCounters{Requests: 1, InputTokens: 2}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	value, err := NewLocalUsageRepository(second.DB).Get(ctx, account.ID)
	if err != nil || value.Requests != 3 || value.Failures != 1 || value.InputTokens != 22 || value.OutputTokens != 5 {
		t.Fatalf("value=%+v err=%v", value, err)
	}
}

func TestModelCapabilityStaleSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	first, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := appcrypto.DeriveKeys(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	account, err := NewAccountRepository(first.DB, keys).UpsertLogin(ctx, Account{Provider: provider.XAI, Credentials: AccountCredentials{Issuer: "issuer", Subject: "model-subject", AccessToken: "token", TokenEndpoint: "endpoint"}})
	if err != nil {
		t.Fatal(err)
	}
	repository := NewModelCapabilityRepository(first.DB)
	if err := repository.Replace(ctx, account.ID, []ModelCapability{{AccountID: account.ID, Model: "grok-4.5", Supported: true, DiscoveredAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	if err := repository.MarkStale(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	values, err := NewModelCapabilityRepository(second.DB).List(ctx, account.ID)
	if err != nil || len(values) != 1 || !values[0].Stale {
		t.Fatalf("values=%+v err=%v", values, err)
	}
}
