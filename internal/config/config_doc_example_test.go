package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readmeDevinExampleYAML extracts the fenced YAML block marked in README.md
// between the stable "BEGIN/END devin example yaml" comment markers. The test
// loads and validates that exact text so the documented example can never
// drift from the config schema.
func readmeDevinExampleYAML(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Clean(abs))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	const (
		begin = "<!-- BEGIN devin example yaml -->"
		end   = "<!-- END devin example yaml -->"
		fence = "```yaml"
	)
	beginIdx := strings.Index(string(body), begin)
	if beginIdx < 0 {
		t.Fatal("README.md missing BEGIN devin example yaml marker")
	}
	region := string(body)[beginIdx+len(begin):]
	endIdx := strings.Index(region, end)
	if endIdx < 0 {
		t.Fatal("README.md missing END devin example yaml marker")
	}
	region = region[:endIdx]
	fStart := strings.Index(region, fence)
	if fStart < 0 {
		t.Fatal("README.md devin example missing ```yaml opening fence")
	}
	afterFence := region[fStart+len(fence):]
	fClose := strings.Index(afterFence, "```")
	if fClose < 0 {
		t.Fatal("README.md devin example missing closing fence")
	}
	return strings.TrimSuffix(afterFence[:fClose], "\n")
}

func TestReadmeDevinExampleLoadsAndValidates(t *testing.T) {
	body := readmeDevinExampleYAML(t)
	if body == "" {
		t.Fatal("extracted empty YAML from README.md")
	}
	cfg := loadYAML(t, body)
	if cfg.Server.Listen != "127.0.0.1:8080" || cfg.Devin.OAuth.CallbackOrigin != "http://127.0.0.1:59653" || cfg.Devin.OAuth.CallbackPath != "/callback" {
		t.Fatalf("unexpected: %+v", cfg)
	}
	if cfg.Devin.Runtime.UnaryTimeout.Duration() != 15*time.Second || cfg.Devin.Runtime.StreamDeadline.Duration() != 0 {
		t.Fatalf("unexpected runtime: %+v", cfg.Devin.Runtime)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("readme example invalid: %v", err)
	}
}
