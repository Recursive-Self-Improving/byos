package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSecrets(t *testing.T) {
	t.Setenv("BYOS_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("BYOS_ADMIN_PASSWORD", "password-fixture")
	t.Setenv("BYOS_ADMIN_API_KEY", "admin-fixture")
	secrets, err := LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if secrets.AdminPassword() != "password-fixture" || secrets.AdminAPIKey() != "admin-fixture" {
		t.Fatal("secret accessors failed")
	}
}

func TestLoadSecretsFromFiles(t *testing.T) {
	values := map[string]string{"BYOS_MASTER_KEY": base64.StdEncoding.EncodeToString(make([]byte, 32)), "BYOS_ADMIN_PASSWORD": "pw", "BYOS_ADMIN_API_KEY": "key"}
	for name, value := range values {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", path)
	}
	if _, err := LoadSecrets(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSecretsFailsClosed(t *testing.T) {
	for _, name := range []string{"BYOS_MASTER_KEY", "BYOS_ADMIN_PASSWORD", "BYOS_ADMIN_API_KEY"} {
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", "")
	}
	if _, err := LoadSecrets(); err == nil || strings.Contains(err.Error(), "password-fixture") {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Setenv("BYOS_MASTER_KEY", "not-base64")
	if _, err := LoadSecrets(); err == nil {
		t.Fatal("malformed key accepted")
	}
}

func TestLoadSecretsRejectsLegacyEnvironmentNames(t *testing.T) {
	for _, name := range []string{"BYOS_MASTER_KEY", "BYOS_ADMIN_PASSWORD", "BYOS_ADMIN_API_KEY"} {
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", "")
	}
	t.Setenv("SUPERGROK_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("SUPERGROK_ADMIN_PASSWORD", "legacy-password")
	t.Setenv("SUPERGROK_ADMIN_API_KEY", "legacy-api-key")
	if _, err := LoadSecrets(); err == nil || !strings.Contains(err.Error(), "BYOS_MASTER_KEY") {
		t.Fatalf("legacy environment accepted or wrong error: %v", err)
	}
}

func TestLoadSecretsRejectsWhitespaceEnvironmentCredentials(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, name := range []string{"BYOS_ADMIN_PASSWORD", "BYOS_ADMIN_API_KEY"} {
		t.Setenv("BYOS_MASTER_KEY", validKey)
		t.Setenv("BYOS_ADMIN_PASSWORD", "password")
		t.Setenv("BYOS_ADMIN_API_KEY", "api-key")
		t.Setenv(name, " \t ")
		if _, err := LoadSecrets(); err == nil {
			t.Fatalf("whitespace-only %s accepted", name)
		}
	}
}
