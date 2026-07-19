package translate

import (
	"byos/internal/translate/anthropic"
	"byos/internal/translate/openai/chatcompletions"
	"byos/internal/translate/openai/responses"
	"byos/internal/translate/registry"
)

func NewRegistry() *registry.Registry {
	result := registry.New()
	if err := result.Register(registry.OpenAIChat, chatcompletions.Transformer{}); err != nil {
		panic(err)
	}
	if err := result.Register(registry.OpenAIResponses, responses.Transformer{}); err != nil {
		panic(err)
	}
	if err := result.Register(registry.Anthropic, anthropic.Transformer{}); err != nil {
		panic(err)
	}
	return result
}
