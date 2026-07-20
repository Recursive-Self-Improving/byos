package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	oauthxai "byos/internal/oauth/xai"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != DefaultListen || cfg.Models.Aliases["grok"] != DefaultModel || cfg.Limits.MaxBodyBytes != 16<<20 || cfg.OAuth.ClientID != oauthxai.DefaultClientID || cfg.OAuth.Scopes != oauthxai.DefaultScopes {
		t.Fatalf("existing xAI defaults changed: %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.Models.Entries, defaultModelEntries()) {
		t.Fatalf("model entries = %#v", cfg.Models.Entries)
	}
	if cfg.Devin.OAuth.CallbackPath != "/callback" {
		t.Fatalf("default Devin callback path = %q", cfg.Devin.OAuth.CallbackPath)
	}
	r := cfg.Devin.Runtime
	if !reflect.DeepEqual(r.AllowedChatHosts, []string{"server.codeium.com"}) || r.UnaryTimeout.Duration() != 15*time.Second || r.StreamIdleTimeout.Duration() != time.Minute || r.StreamDeadline.Duration() != 0 || r.MaxUnaryCompressedBytes != 2<<20 || r.MaxUnaryDecompressedBytes != 8<<20 || r.MaxFrameCompressedBytes != 4<<20 || r.MaxFrameDecompressedBytes != 16<<20 || r.MaxStreamBytes != 64<<20 || r.MaxToolArgumentBytes != 4<<20 || r.MaxNonStreamBytes != 32<<20 {
		t.Fatalf("unexpected Devin defaults: %+v", r)
	}
}

func TestRailwayConfig(t *testing.T) {
	cfg, err := Load("../../deploy/railway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Server.TrustedProxies, []string{"100.0.0.0/8"}) || cfg.Server.Listen != DefaultListen || cfg.DataDir != DefaultDataDir || cfg.Devin.OAuth.CallbackOrigin != "http://127.0.0.1:59653" || cfg.Devin.OAuth.CallbackPath != "/callback" || !reflect.DeepEqual(cfg.Models.Entries, defaultModelEntries()) {
		t.Fatalf("Railway config changed defaults: %+v", cfg)
	}
}

func TestYAMLOverrideRoundTrip(t *testing.T) {
	cfg := loadYAML(t, "server:\n  listen: 127.0.0.1:9090\n  trusted_proxies: [127.0.0.1, '10.0.0.0/8']\ndata_dir: /tmp/byos\nupstream:\n  request_timeout: 3m\noauth:\n  client_id: deployment-client\n  scopes: openid offline_access\ndevin:\n  oauth:\n    callback_origin: http://127.0.0.1:59653\n    callback_path: /callback\n  runtime:\n    allowed_chat_hosts: [chat.example.com]\n    unary_timeout: 30s\n    stream_idle_timeout: 2m\n    stream_deadline: 10m\n    max_unary_compressed_bytes: 2097152\n    max_unary_decompressed_bytes: 8388608\n    max_frame_compressed_bytes: 4194304\n    max_frame_decompressed_bytes: 16777216\n    max_stream_bytes: 67108864\n    max_tool_argument_bytes: 4194304\n    max_non_stream_bytes: 33554432\n")
	if cfg.Upstream.RequestTimeout.Duration() != 3*time.Minute || cfg.Devin.Runtime.StreamDeadline.Duration() != 10*time.Minute {
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
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, decoded) {
		t.Fatalf("round trip mismatch\n%+v\n%+v", cfg, decoded)
	}
}

func TestDevinBoundaryValidation(t *testing.T) {
	tests := []func(*DevinRuntimeConfig){
		func(c *DevinRuntimeConfig) { c.UnaryTimeout = Duration(time.Second) },
		func(c *DevinRuntimeConfig) { c.UnaryTimeout = Duration(time.Minute) },
		func(c *DevinRuntimeConfig) { c.StreamIdleTimeout = Duration(5 * time.Second) },
		func(c *DevinRuntimeConfig) { c.StreamIdleTimeout = Duration(5 * time.Minute) },
		func(c *DevinRuntimeConfig) { c.StreamDeadline = Duration(0) },
		func(c *DevinRuntimeConfig) { c.StreamDeadline = Duration(30 * time.Second) },
		func(c *DevinRuntimeConfig) { c.StreamDeadline = Duration(30 * time.Minute) },
	}
	for i, mutate := range tests {
		cfg := Default()
		mutate(&cfg.Devin.Runtime)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("boundary %d: %v", i, err)
		}
	}
	limits := []struct {
		min, max int64
		set      func(*DevinRuntimeConfig, int64)
	}{
		{1 << 10, 8 << 20, func(c *DevinRuntimeConfig, v int64) { c.MaxUnaryCompressedBytes = v }},
		{1 << 10, 32 << 20, func(c *DevinRuntimeConfig, v int64) { c.MaxUnaryDecompressedBytes = v }},
		{1 << 10, 16 << 20, func(c *DevinRuntimeConfig, v int64) { c.MaxFrameCompressedBytes = v }},
		{1 << 10, 64 << 20, func(c *DevinRuntimeConfig, v int64) { c.MaxFrameDecompressedBytes = v }},
		{1 << 20, 256 << 20, func(c *DevinRuntimeConfig, v int64) { c.MaxStreamBytes = v }},
		{1 << 10, 16 << 20, func(c *DevinRuntimeConfig, v int64) { c.MaxToolArgumentBytes = v }},
		{1 << 20, 128 << 20, func(c *DevinRuntimeConfig, v int64) { c.MaxNonStreamBytes = v }},
	}
	for i, limit := range limits {
		for _, value := range []int64{limit.min, limit.max} {
			cfg := Default()
			limit.set(&cfg.Devin.Runtime, value)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("limit %d value %d: %v", i, value, err)
			}
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	invalid := []string{
		"upstream:\n  request_timeout: nope\n", "server:\n  trusted_proxies: [not-a-network]\n", "oauth:\n  client_id: ''\n", "limits:\n  max_body_bytes: 0\n", "models:\n  aliases:\n    grok: missing\n", "responses:\n  retention: 24h\n", "mandatory_x_search: false\n", "devin:\n  unknown: true\n", "devin:\n  oauth:\n    callback_origin: http://example.com\n", "devin:\n  oauth:\n    callback_origin: https://user@example.com\n", "devin:\n  oauth:\n    callback_origin: https://example.com/path\n", "devin:\n  oauth:\n    callback_path: relative\n", "devin:\n  oauth:\n    callback_path: //evil.example/callback\n", "devin:\n  runtime:\n    allowed_chat_hosts: []\n", "devin:\n  runtime:\n    allowed_chat_hosts: ['server.codeium.com.evil.example', 'SERVER.codeium.com']\n", "devin:\n  runtime:\n    allowed_chat_hosts: ['127.0.0.1']\n", "devin:\n  runtime:\n    unary_timeout: 999ms\n", "devin:\n  runtime:\n    unary_timeout: 61s\n", "devin:\n  runtime:\n    stream_idle_timeout: 0s\n", "devin:\n  runtime:\n    stream_deadline: 1s\n", "devin:\n  runtime:\n    max_stream_bytes: 0\n", "devin:\n  runtime:\n    max_tool_argument_bytes: 16777217\n", "---\nserver: {}\n---\nserver: {}\n",
	}
	for _, body := range invalid {
		if _, err := loadYAMLError(t, body); err == nil {
			t.Fatalf("Load(%q) succeeded", body)
		}
	}
}

func TestFixedModelEntriesRejectMutation(t *testing.T) {
	mutations := []func(*Config){
		func(c *Config) { c.Models.Entries = nil },
		func(c *Config) { c.Models.Entries = append(c.Models.Entries, c.Models.Entries[0]) },
		func(c *Config) { c.Models.Entries[0].Provider = ProviderDevin },
		func(c *Config) { c.Models.Entries[1].OwnedBy = "byos" },
		func(c *Config) { c.Models.Entries[2].PublicName = "other" },
		func(c *Config) { c.Models.Entries[3].PolicyKey = "xai" },
		func(c *Config) { c.Models.Entries[4].UpstreamName = "other" },
		func(c *Config) { c.Models.Entries[2].Provider = ProviderKind("XAI") },
	}
	for i, mutate := range mutations {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

func TestLegacyModelsRespectStaticCatalogOwnership(t *testing.T) {
	tests := []struct {
		name   string
		valid  bool
		mutate func(*ModelsConfig)
	}{
		{name: "canonical grok mapping", valid: true, mutate: func(*ModelsConfig) {}},
		{name: "unique xai alias", valid: true, mutate: func(m *ModelsConfig) {
			m.Aliases["fast"] = DefaultModel
		}},
		{name: "default resolves through unique alias", valid: true, mutate: func(m *ModelsConfig) {
			m.Aliases["fast"] = DefaultModel
			m.Default = "fast"
			m.Allowlist = []string{"fast", DefaultModel}
		}},
		{name: "alias default without canonical allowlist", valid: true, mutate: func(m *ModelsConfig) {
			m.Aliases["fast"] = DefaultModel
			m.Default = "fast"
			m.Allowlist = []string{"fast"}
		}},
		{name: "canonical public name collision", mutate: func(m *ModelsConfig) {
			m.Aliases[DefaultModel] = DefaultModel
		}},
		{name: "kimi public name collision", mutate: func(m *ModelsConfig) {
			m.Aliases["kimi-k2-7"] = DefaultModel
		}},
		{name: "glm public name collision", mutate: func(m *ModelsConfig) {
			m.Aliases["glm-5-2"] = DefaultModel
		}},
		{name: "swe public name collision", mutate: func(m *ModelsConfig) {
			m.Aliases["swe-1-6-slow"] = DefaultModel
		}},
		{name: "grok redirect", mutate: func(m *ModelsConfig) {
			m.Aliases["grok"] = "other"
		}},
		{name: "alias targets Devin model", mutate: func(m *ModelsConfig) {
			m.Aliases["fast"] = "kimi-k2-7"
		}},
		{name: "alias targets unknown model", mutate: func(m *ModelsConfig) {
			m.Aliases["fast"] = "other"
		}},
		{name: "alias chain", mutate: func(m *ModelsConfig) {
			m.Aliases["turbo"] = DefaultModel
			m.Aliases["fast"] = "turbo"
		}},
		{name: "Devin default", valid: true, mutate: func(m *ModelsConfig) {
			m.Default = "kimi-k2-7"
			m.Allowlist = []string{"kimi-k2-7"}
		}},
		{name: "unknown default", mutate: func(m *ModelsConfig) {
			m.Default = "other"
			m.Allowlist = []string{"other"}
		}},
		{name: "Devin allowlist entry", valid: true, mutate: func(m *ModelsConfig) {
			m.Allowlist = append(m.Allowlist, "glm-5-2")
		}},
		{name: "unknown allowlist entry", mutate: func(m *ModelsConfig) {
			m.Allowlist = append(m.Allowlist, "other")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.mutate(&cfg.Models)
			err := cfg.Validate()
			if test.valid && err != nil {
				t.Fatalf("valid config rejected: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestStreamDeadlineOnlyShortensCallerContext(t *testing.T) {
	cfg := Default().Devin.Runtime
	parent := context.Background()
	child, childCancel := cfg.StreamContext(parent)
	defer childCancel()
	if _, ok := child.Deadline(); ok {
		t.Fatal("disabled stream deadline added a deadline")
	}
	cfg.StreamDeadline = Duration(30 * time.Second)
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	child, childCancel = cfg.StreamContext(parent)
	defer childCancel()
	pd, _ := parent.Deadline()
	cd, _ := child.Deadline()
	if !cd.Equal(pd) {
		t.Fatalf("configured deadline extended caller: parent=%v child=%v", pd, cd)
	}
}

func TestDevinActivationAcceptsOnlyLoopbackHTTP(t *testing.T) {
	cfg := Default()
	if err := cfg.Devin.ValidateEnabled(); err == nil {
		t.Fatal("unset callback origin activated Devin")
	}
	for _, origin := range []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		cfg.Devin.OAuth.CallbackOrigin = origin
		if err := cfg.Devin.ValidateEnabled(); err != nil {
			t.Fatalf("origin %q: %v", origin, err)
		}
	}
	for _, origin := range []string{
		"https://byos.example.com",
		"http://byos.example.com:8080",
		"http://127.0.0.1",
		"http://127.0.0.1:0",
		"ftp://127.0.0.1:8080",
	} {
		cfg.Devin.OAuth.CallbackOrigin = origin
		if err := cfg.Devin.ValidateEnabled(); err == nil {
			t.Fatalf("unsupported origin %q accepted", origin)
		}
	}
}

func TestSerializedConfigContainsNoSecrets(t *testing.T) {
	cfg := Default()
	yml, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.ToLower(string(yml) + string(js))
	for _, forbidden := range []string{"master_key", "admin_password", "admin_api_key", "client_secret", "session_token", "user_jwt", "access_token", "refresh_token", "code_verifier", "oauth_code", "oauth_state"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("serialized config contains %q", forbidden)
		}
	}
}

func loadYAML(t *testing.T, body string) Config {
	t.Helper()
	cfg, err := loadYAMLError(t, body)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func loadYAMLError(t *testing.T, body string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// TestConfigAcceptsAnyFixedStaticPublicModelAsDefault asserts C9.2: config
// accepts any of the five fixed static public model names as the default while
// preserving Grok alias ownership (models.aliases.grok stays fixed at the
// canonical xAI model). This guards against the prior xAI-only default/allowlist
// boundary that prevented Devin defaults.
func TestConfigAcceptsAnyFixedStaticPublicModelAsDefault(t *testing.T) {
	for _, name := range []string{DefaultModel, "grok", "kimi-k2-7", "glm-5-2", "swe-1-6-slow"} {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			cfg.Models.Default = name
			cfg.Models.Allowlist = []string{name}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("default %q rejected: %v", name, err)
			}
			if cfg.Models.Aliases["grok"] != DefaultModel {
				t.Fatalf("grok alias ownership changed for default %q: %q", name, cfg.Models.Aliases["grok"])
			}
		})
	}
}

// TestConfigRejectsNonFixedDefaultWhilePreservingGrokAlias asserts C9.2: a
// default that is not one of the five fixed static public names (and not a
// permitted xAI alias) is rejected, while the Grok alias ownership constraint
// stays intact.
func TestConfigRejectsNonFixedDefaultWhilePreservingGrokAlias(t *testing.T) {
	cfg := Default()
	cfg.Models.Default = "not-a-fixed-model"
	cfg.Models.Allowlist = []string{"not-a-fixed-model"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("non-fixed default accepted")
	}
	if cfg.Models.Aliases["grok"] != DefaultModel {
		t.Fatalf("grok alias ownership changed: %q", cfg.Models.Aliases["grok"])
	}
}

// TestConfigGrokAliasStaysFixedAtCanonicalXAIModel asserts C9.2: the Grok alias
// must always target the canonical xAI model and cannot be redirected, even
// when the default is a Devin model.
func TestConfigGrokAliasStaysFixedAtCanonicalXAIModel(t *testing.T) {
	cfg := Default()
	cfg.Models.Default = "kimi-k2-7"
	cfg.Models.Allowlist = []string{"kimi-k2-7"}
	cfg.Models.Aliases["grok"] = "kimi-k2-7"
	if err := cfg.Validate(); err == nil {
		t.Fatal("grok alias redirect to Devin accepted")
	}
}
