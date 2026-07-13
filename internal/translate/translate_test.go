package translate

import (
	"testing"

	"supergrok-api/internal/translate/registry"
)

func TestNewRegistryContainsAllProtocols(t *testing.T) {
	registered := NewRegistry()
	for _, format := range []registry.Format{registry.OpenAIChat, registry.OpenAIResponses, registry.Anthropic} {
		if _, ok := registered.Get(format); !ok {
			t.Fatalf("missing translator %s", format)
		}
	}
}
