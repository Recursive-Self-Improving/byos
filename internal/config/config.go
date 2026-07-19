package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	oauthxai "byos/internal/oauth/xai"
)

const (
	DefaultListen              = "127.0.0.1:8080"
	DefaultDataDir             = "./data"
	DefaultCLIProxyBaseURL     = "https://cli-chat-proxy.grok.com/v1"
	DefaultGrokClientVersion   = "0.2.99"
	DefaultModel               = "grok-4.5"
	DefaultMaxBodyBytes        = 16 << 20
	DefaultResponsesRetention  = 30 * 24 * time.Hour
	DefaultDevinCallbackOrigin = ""
	DefaultDevinCallbackPath   = "/admin/api/v1/oauth/devin/callback"
	DefaultDevinChatHost       = "server.codeium.com"
)

type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return errors.New("duration must be a string")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(parsed)
	return nil
}

type Config struct {
	Server    ServerConfig    `yaml:"server" json:"server"`
	DataDir   string          `yaml:"data_dir" json:"data_dir"`
	Upstream  UpstreamConfig  `yaml:"upstream" json:"upstream"`
	OAuth     OAuthConfig     `yaml:"oauth" json:"oauth"`
	Devin     DevinConfig     `yaml:"devin" json:"devin"`
	Models    ModelsConfig    `yaml:"models" json:"models"`
	Limits    LimitsConfig    `yaml:"limits" json:"limits"`
	Usage     UsageConfig     `yaml:"usage" json:"usage"`
	Responses ResponsesConfig `yaml:"responses" json:"responses"`
}

type ServerConfig struct {
	Listen         string   `yaml:"listen" json:"listen"`
	TrustedProxies []string `yaml:"trusted_proxies" json:"trusted_proxies"`
}

// UpstreamConfig and OAuthConfig retain the original xAI YAML surface.
type UpstreamConfig struct {
	CLIProxyBaseURL   string   `yaml:"cli_proxy_base_url" json:"cli_proxy_base_url"`
	GrokClientVersion string   `yaml:"grok_client_version" json:"grok_client_version"`
	RequestTimeout    Duration `yaml:"request_timeout" json:"request_timeout"`
	SSEIdleTimeout    Duration `yaml:"sse_idle_timeout" json:"sse_idle_timeout"`
}
type OAuthConfig struct {
	ClientID string `yaml:"client_id" json:"client_id"`
	Scopes   string `yaml:"scopes" json:"scopes"`
}

type DevinConfig struct {
	OAuth   DevinOAuthConfig   `yaml:"oauth" json:"oauth"`
	Runtime DevinRuntimeConfig `yaml:"runtime" json:"runtime"`
}
type DevinOAuthConfig struct {
	CallbackOrigin string `yaml:"callback_origin" json:"callback_origin"`
	CallbackPath   string `yaml:"callback_path" json:"callback_path"`
}
type DevinRuntimeConfig struct {
	AllowedChatHosts          []string `yaml:"allowed_chat_hosts" json:"allowed_chat_hosts"`
	UnaryTimeout              Duration `yaml:"unary_timeout" json:"unary_timeout"`
	StreamIdleTimeout         Duration `yaml:"stream_idle_timeout" json:"stream_idle_timeout"`
	StreamDeadline            Duration `yaml:"stream_deadline" json:"stream_deadline"`
	MaxUnaryCompressedBytes   int64    `yaml:"max_unary_compressed_bytes" json:"max_unary_compressed_bytes"`
	MaxUnaryDecompressedBytes int64    `yaml:"max_unary_decompressed_bytes" json:"max_unary_decompressed_bytes"`
	MaxFrameCompressedBytes   int64    `yaml:"max_frame_compressed_bytes" json:"max_frame_compressed_bytes"`
	MaxFrameDecompressedBytes int64    `yaml:"max_frame_decompressed_bytes" json:"max_frame_decompressed_bytes"`
	MaxStreamBytes            int64    `yaml:"max_stream_bytes" json:"max_stream_bytes"`
	MaxToolArgumentBytes      int64    `yaml:"max_tool_argument_bytes" json:"max_tool_argument_bytes"`
	MaxNonStreamBytes         int64    `yaml:"max_non_stream_bytes" json:"max_non_stream_bytes"`
}

// StreamContext applies the optional adapter deadline without ever extending
// or replacing an earlier caller deadline.
func (c DevinRuntimeConfig) StreamContext(parent context.Context) (context.Context, context.CancelFunc) {
	if c.StreamDeadline.Duration() == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, c.StreamDeadline.Duration())
}

type ProviderKind string

const (
	ProviderXAI   ProviderKind = "xai"
	ProviderDevin ProviderKind = "devin"
)

type ModelEntry struct {
	PublicName   string       `yaml:"public_name" json:"public_name"`
	UpstreamName string       `yaml:"upstream_name" json:"upstream_name"`
	Provider     ProviderKind `yaml:"provider" json:"provider"`
	OwnedBy      string       `yaml:"owned_by" json:"owned_by"`
	PolicyKey    string       `yaml:"policy_key" json:"policy_key"`
}
type ModelsConfig struct {
	Default   string            `yaml:"default" json:"default"`
	Aliases   map[string]string `yaml:"aliases" json:"aliases"`
	Allowlist []string          `yaml:"allowlist" json:"allowlist"`
	Entries   []ModelEntry      `yaml:"entries" json:"entries"`
}
type LimitsConfig struct {
	MaxBodyBytes int64 `yaml:"max_body_bytes" json:"max_body_bytes"`
}
type UsageConfig struct {
	RefreshInterval Duration `yaml:"refresh_interval" json:"refresh_interval"`
}
type ResponsesConfig struct {
	Retention Duration `yaml:"retention" json:"retention"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{Listen: DefaultListen}, DataDir: DefaultDataDir,
		Upstream: UpstreamConfig{CLIProxyBaseURL: DefaultCLIProxyBaseURL, GrokClientVersion: DefaultGrokClientVersion, RequestTimeout: Duration(2 * time.Minute), SSEIdleTimeout: Duration(45 * time.Second)},
		OAuth:    OAuthConfig{ClientID: oauthxai.DefaultClientID, Scopes: oauthxai.DefaultScopes},
		Devin: DevinConfig{
			OAuth:   DevinOAuthConfig{CallbackOrigin: DefaultDevinCallbackOrigin, CallbackPath: DefaultDevinCallbackPath},
			Runtime: DevinRuntimeConfig{AllowedChatHosts: []string{DefaultDevinChatHost}, UnaryTimeout: Duration(15 * time.Second), StreamIdleTimeout: Duration(time.Minute), MaxUnaryCompressedBytes: 2 << 20, MaxUnaryDecompressedBytes: 8 << 20, MaxFrameCompressedBytes: 4 << 20, MaxFrameDecompressedBytes: 16 << 20, MaxStreamBytes: 64 << 20, MaxToolArgumentBytes: 4 << 20, MaxNonStreamBytes: 32 << 20},
		},
		Models: ModelsConfig{Default: DefaultModel, Aliases: map[string]string{"grok": DefaultModel}, Allowlist: []string{DefaultModel}, Entries: defaultModelEntries()},
		Limits: LimitsConfig{MaxBodyBytes: DefaultMaxBodyBytes}, Usage: UsageConfig{RefreshInterval: Duration(5 * time.Minute)},
		Responses: ResponsesConfig{Retention: Duration(DefaultResponsesRetention)},
	}
}

func defaultModelEntries() []ModelEntry {
	return []ModelEntry{
		{PublicName: "grok", UpstreamName: DefaultModel, Provider: ProviderXAI, OwnedBy: "byos", PolicyKey: "xai"},
		{PublicName: DefaultModel, UpstreamName: DefaultModel, Provider: ProviderXAI, OwnedBy: "xai", PolicyKey: "xai"},
		{PublicName: "kimi-k2-7", UpstreamName: "kimi-k2-7", Provider: ProviderDevin, OwnedBy: "devin", PolicyKey: "devin"},
		{PublicName: "glm-5-2", UpstreamName: "glm-5-2", Provider: ProviderDevin, OwnedBy: "devin", PolicyKey: "devin"},
		{PublicName: "swe-1-6-slow", UpstreamName: "swe-1-6-slow", Provider: ProviderDevin, OwnedBy: "devin", PolicyKey: "devin"},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return Config{}, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return Config{}, fmt.Errorf("decode config: %w", err)
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			if err == nil {
				return Config{}, errors.New("decode config: multiple YAML documents are not allowed")
			}
			return Config{}, fmt.Errorf("decode config: %w", err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.Listen) == "" {
		return errors.New("server.listen is required")
	}
	for _, value := range c.Server.TrustedProxies {
		value = strings.TrimSpace(value)
		if value == "" {
			return errors.New("server.trusted_proxies cannot contain blank entries")
		}
		if _, err := netip.ParseAddr(value); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(value); err != nil {
			return fmt.Errorf("invalid server.trusted_proxies entry %q", value)
		}
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return errors.New("data_dir is required")
	}
	u, err := url.Parse(c.Upstream.CLIProxyBaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("upstream.cli_proxy_base_url must be an absolute HTTPS URL")
	}
	if strings.TrimSpace(c.Upstream.GrokClientVersion) == "" {
		return errors.New("upstream.grok_client_version is required")
	}
	if strings.TrimSpace(c.OAuth.ClientID) == "" || strings.TrimSpace(c.OAuth.Scopes) == "" {
		return errors.New("oauth.client_id and oauth.scopes are required")
	}
	if c.Upstream.RequestTimeout.Duration() <= 0 || c.Upstream.SSEIdleTimeout.Duration() <= 0 || c.Usage.RefreshInterval.Duration() <= 0 {
		return errors.New("timeouts and refresh intervals must be positive")
	}
	if err := validateDevin(c.Devin); err != nil {
		return err
	}
	if c.Responses.Retention.Duration() != DefaultResponsesRetention {
		return errors.New("responses.retention is fixed at 30 days")
	}
	if c.Limits.MaxBodyBytes <= 0 {
		return errors.New("limits.max_body_bytes must be positive")
	}
	if err := validateModelEntries(c.Models.Entries); err != nil {
		return err
	}
	if err := validateLegacyModels(c.Models); err != nil {
		return err
	}
	return nil
}

func validateLegacyModels(models ModelsConfig) error {
	if strings.TrimSpace(models.Default) == "" {
		return errors.New("models.default is required")
	}
	staticNames := make(map[string]ProviderKind, len(models.Entries))
	for _, entry := range models.Entries {
		staticNames[entry.PublicName] = entry.Provider
	}
	for _, alias := range slices.Sorted(maps.Keys(models.Aliases)) {
		target := models.Aliases[alias]
		if strings.TrimSpace(alias) == "" || strings.TrimSpace(target) == "" || alias != strings.TrimSpace(alias) || target != strings.TrimSpace(target) {
			return fmt.Errorf("model alias %q must be non-blank and unpadded", alias)
		}
		if provider, reserved := staticNames[alias]; reserved && (alias != "grok" || provider != ProviderXAI || target != DefaultModel) {
			return fmt.Errorf("model alias %q collides with a fixed public model name", alias)
		}
		if target != DefaultModel {
			return fmt.Errorf("model alias %q must target the canonical xAI model %q", alias, DefaultModel)
		}
	}
	if models.Aliases["grok"] != DefaultModel {
		return errors.New("models.aliases.grok is fixed at grok-4.5")
	}
	executable := func(model string) bool {
		if model == DefaultModel {
			return true
		}
		target, aliased := models.Aliases[model]
		return aliased && target == DefaultModel
	}
	if len(models.Allowlist) == 0 || !slices.Contains(models.Allowlist, models.Default) {
		return errors.New("models.allowlist must include models.default")
	}
	if !slices.Contains(models.Allowlist, DefaultModel) {
		return fmt.Errorf("models.allowlist must include canonical xAI model %q", DefaultModel)
	}
	for _, model := range models.Allowlist {
		if strings.TrimSpace(model) == "" || model != strings.TrimSpace(model) || !executable(model) {
			return fmt.Errorf("models.allowlist model %q is not executable by the xAI boundary", model)
		}
	}
	if !executable(models.Default) {
		return fmt.Errorf("models.default %q is not executable by the xAI boundary", models.Default)
	}
	return nil
}

func validateDevin(c DevinConfig) error {
	if c.OAuth.CallbackOrigin != "" {
		if err := c.ValidateEnabled(); err != nil {
			return err
		}
	}
	callback, err := url.Parse(c.OAuth.CallbackPath)
	if err != nil || !strings.HasPrefix(c.OAuth.CallbackPath, "/") || strings.HasPrefix(c.OAuth.CallbackPath, "//") || callback.IsAbs() || callback.Host != "" || callback.RawQuery != "" || callback.Fragment != "" || callback.Path != c.OAuth.CallbackPath {
		return errors.New("devin.oauth.callback_path must be an absolute path without URL components")
	}
	if len(c.Runtime.AllowedChatHosts) == 0 {
		return errors.New("devin.runtime.allowed_chat_hosts must not be empty")
	}
	seen := make(map[string]struct{}, len(c.Runtime.AllowedChatHosts))
	for _, host := range c.Runtime.AllowedChatHosts {
		normalized := strings.ToLower(strings.TrimSpace(host))
		if normalized == "" || normalized != host || strings.HasSuffix(host, ".") || strings.ContainsAny(host, ":/@?#*\\") || net.ParseIP(host) != nil || !validDNSName(host) {
			return errors.New("devin.runtime.allowed_chat_hosts contains an invalid DNS host")
		}
		if _, ok := seen[normalized]; ok {
			return errors.New("devin.runtime.allowed_chat_hosts contains a duplicate host")
		}
		seen[normalized] = struct{}{}
	}
	if err := validateDurationRange("devin.runtime.unary_timeout", c.Runtime.UnaryTimeout.Duration(), time.Second, time.Minute, false); err != nil {
		return err
	}
	if err := validateDurationRange("devin.runtime.stream_idle_timeout", c.Runtime.StreamIdleTimeout.Duration(), 5*time.Second, 5*time.Minute, false); err != nil {
		return err
	}
	if err := validateDurationRange("devin.runtime.stream_deadline", c.Runtime.StreamDeadline.Duration(), 30*time.Second, 30*time.Minute, true); err != nil {
		return err
	}
	limits := []struct {
		name       string
		value, min int64
		max        int64
	}{
		{"max_unary_compressed_bytes", c.Runtime.MaxUnaryCompressedBytes, 1 << 10, 8 << 20},
		{"max_unary_decompressed_bytes", c.Runtime.MaxUnaryDecompressedBytes, 1 << 10, 32 << 20},
		{"max_frame_compressed_bytes", c.Runtime.MaxFrameCompressedBytes, 1 << 10, 16 << 20},
		{"max_frame_decompressed_bytes", c.Runtime.MaxFrameDecompressedBytes, 1 << 10, 64 << 20},
		{"max_stream_bytes", c.Runtime.MaxStreamBytes, 1 << 20, 256 << 20},
		{"max_tool_argument_bytes", c.Runtime.MaxToolArgumentBytes, 1 << 10, 16 << 20},
		{"max_non_stream_bytes", c.Runtime.MaxNonStreamBytes, 1 << 20, 128 << 20},
	}
	for _, limit := range limits {
		if limit.value < limit.min || limit.value > limit.max {
			return fmt.Errorf("devin.runtime.%s must be between %d and %d bytes", limit.name, limit.min, limit.max)
		}
	}
	return nil
}

func validateDurationRange(name string, value, min, max time.Duration, allowZero bool) error {
	if allowZero && value == 0 {
		return nil
	}
	if value < min || value > max {
		return fmt.Errorf("%s must be between %s and %s", name, min, max)
	}
	return nil
}

func validDNSName(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func validateModelEntries(entries []ModelEntry) error {
	want := defaultModelEntries()
	if len(entries) != len(want) {
		return errors.New("models.entries must contain exactly the five fixed model entries")
	}
	seen := make(map[string]ModelEntry, len(entries))
	for _, entry := range entries {
		if entry.Provider != ProviderXAI && entry.Provider != ProviderDevin {
			return fmt.Errorf("model %q has invalid provider kind", entry.PublicName)
		}
		if entry.PublicName == "" || entry.PublicName != strings.TrimSpace(entry.PublicName) || entry.UpstreamName == "" || entry.UpstreamName != strings.TrimSpace(entry.UpstreamName) || entry.OwnedBy == "" || entry.OwnedBy != strings.TrimSpace(entry.OwnedBy) || entry.PolicyKey == "" || entry.PolicyKey != strings.TrimSpace(entry.PolicyKey) {
			return errors.New("models.entries identities must be non-blank and unpadded")
		}
		if _, ok := seen[entry.PublicName]; ok {
			return fmt.Errorf("models.entries contains duplicate public name %q", entry.PublicName)
		}
		seen[entry.PublicName] = entry
	}
	for _, expected := range want {
		actual, ok := seen[expected.PublicName]
		if !ok || actual != expected {
			return fmt.Errorf("model %q has fixed provider ownership and identity", expected.PublicName)
		}
	}
	return nil
}

// ValidateEnabled is the activation-time seam used by Devin OAuth composition.
// The default remains unset so existing xAI-only deployments do not invent a
// public origin or derive one from request headers.
func (c DevinConfig) ValidateEnabled() error {
	origin, err := url.Parse(c.OAuth.CallbackOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" || (origin.Path != "" && origin.Path != "/") {
		return errors.New("devin.oauth.callback_origin must be an explicit HTTPS origin when Devin is enabled")
	}
	if net.ParseIP(origin.Hostname()) != nil || strings.EqualFold(origin.Hostname(), "localhost") || !validDNSName(strings.ToLower(origin.Hostname())) {
		return errors.New("devin.oauth.callback_origin must use a public DNS hostname")
	}
	return nil
}
