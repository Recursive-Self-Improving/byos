package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultListen             = "127.0.0.1:8080"
	DefaultDataDir            = "./data"
	DefaultCLIProxyBaseURL    = "https://cli-chat-proxy.grok.com/v1"
	DefaultGrokClientVersion  = "0.2.99"
	DefaultModel              = "grok-4.5"
	DefaultMaxBodyBytes       = 16 << 20
	DefaultResponsesRetention = 30 * 24 * time.Hour
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
	Models    ModelsConfig    `yaml:"models" json:"models"`
	Limits    LimitsConfig    `yaml:"limits" json:"limits"`
	Usage     UsageConfig     `yaml:"usage" json:"usage"`
	Responses ResponsesConfig `yaml:"responses" json:"responses"`
}

type ServerConfig struct {
	Listen string `yaml:"listen" json:"listen"`
}
type UpstreamConfig struct {
	CLIProxyBaseURL   string   `yaml:"cli_proxy_base_url" json:"cli_proxy_base_url"`
	GrokClientVersion string   `yaml:"grok_client_version" json:"grok_client_version"`
	RequestTimeout    Duration `yaml:"request_timeout" json:"request_timeout"`
	SSEIdleTimeout    Duration `yaml:"sse_idle_timeout" json:"sse_idle_timeout"`
}
type ModelsConfig struct {
	Default   string            `yaml:"default" json:"default"`
	Aliases   map[string]string `yaml:"aliases" json:"aliases"`
	Allowlist []string          `yaml:"allowlist" json:"allowlist"`
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
		Models:   ModelsConfig{Default: DefaultModel, Aliases: map[string]string{"grok": DefaultModel}, Allowlist: []string{DefaultModel}},
		Limits:   LimitsConfig{MaxBodyBytes: DefaultMaxBodyBytes}, Usage: UsageConfig{RefreshInterval: Duration(5 * time.Minute)},
		Responses: ResponsesConfig{Retention: Duration(DefaultResponsesRetention)},
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
	if c.Upstream.RequestTimeout.Duration() <= 0 || c.Upstream.SSEIdleTimeout.Duration() <= 0 || c.Usage.RefreshInterval.Duration() <= 0 {
		return errors.New("timeouts and refresh intervals must be positive")
	}
	if c.Responses.Retention.Duration() != DefaultResponsesRetention {
		return errors.New("responses.retention is fixed at 30 days")
	}
	if c.Limits.MaxBodyBytes <= 0 {
		return errors.New("limits.max_body_bytes must be positive")
	}
	if strings.TrimSpace(c.Models.Default) == "" {
		return errors.New("models.default is required")
	}
	for _, model := range c.Models.Allowlist {
		if strings.TrimSpace(model) == "" {
			return errors.New("models.allowlist cannot contain blank models")
		}
	}
	if len(c.Models.Allowlist) == 0 || !slices.Contains(c.Models.Allowlist, c.Models.Default) {
		return errors.New("models.allowlist must include models.default")
	}
	if c.Models.Aliases["grok"] != DefaultModel {
		return errors.New("models.aliases.grok is fixed at grok-4.5")
	}
	for alias, target := range c.Models.Aliases {
		if strings.TrimSpace(alias) == "" || strings.TrimSpace(target) == "" || alias != strings.TrimSpace(alias) || target != strings.TrimSpace(target) || !slices.Contains(c.Models.Allowlist, target) {
			return fmt.Errorf("model alias %q targets a model outside the allowlist", alias)
		}
		if alias == target {
			return fmt.Errorf("model alias %q cannot target itself", alias)
		}
	}
	return nil
}
