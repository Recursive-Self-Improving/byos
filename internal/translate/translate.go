package translate

import (
	"supergrok-api/internal/translate/anthropic"
	"supergrok-api/internal/translate/openai/chatcompletions"
	"supergrok-api/internal/translate/openai/responses"
	"supergrok-api/internal/translate/registry"
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
