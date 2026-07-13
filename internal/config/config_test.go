package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != DefaultListen || cfg.Models.Aliases["grok"] != DefaultModel || cfg.Limits.MaxBodyBytes != 16<<20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestYAMLOverrideRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("server:\n  listen: 127.0.0.1:9090\ndata_dir: /tmp/supergrok\nupstream:\n  request_timeout: 3m\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != "127.0.0.1:9090" || cfg.Upstream.RequestTimeout.Duration() != 3*time.Minute {
		t.Fatalf("override failed: %+v", cfg)
	}
	encoded, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := yaml.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, decoded) {
		t.Fatalf("round trip mismatch\n%+v\n%+v", cfg, decoded)
	}
}

func TestInvalidConfig(t *testing.T) {
	tests := []string{
		"upstream:\n  request_timeout: nope\n",
		"limits:\n  max_body_bytes: 0\n",
		"models:\n  aliases:\n    grok: missing\n",
		"models:\n  default: ''\n  allowlist: ['', grok-4.5]\n",
		"models:\n  aliases:\n    ' ': grok-4.5\n",
		"models:\n  aliases: null\n",
		"models:\n  allowlist: [grok-4.5, other]\n  aliases:\n    grok: other\n",
		"responses:\n  retention: 24h\n",
		"mandatory_x_search: false\n",
		"multi_instance: true\n",
	}
	for _, body := range tests {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("Load(%q) succeeded", body)
		}
	}
}

func TestSerializedConfigContainsNoSecrets(t *testing.T) {
	encoded, err := yaml.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"master_key", "admin_password", "admin_api_key"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("serialized config contains %q", forbidden)
		}
	}
}
