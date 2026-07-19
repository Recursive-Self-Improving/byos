package devin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"byos/internal/devin/proto"
	"byos/internal/provider"
)

var defaultStopPatterns = []string{"<|user|>", "<|bot|>", "<|context_request|>", "<|endoftext|>", "<|end_of_turn|>"}

// BuildChatRequest maps the provider-neutral Responses request to Devin's chat wire request.
// sessionToken must already be normalized for Devin transport use.
func BuildChatRequest(canonical provider.CanonicalRequest, sessionToken, userJWT string) (*proto.GetChatMessageRequest, error) {
	model, ok := canonical["model"].(string)
	if !ok || model == "" {
		return nil, errors.New("devin: model is required")
	}
	input, ok := canonical["input"].([]any)
	if !ok {
		return nil, errors.New("devin: input must be an array")
	}
	structure, err := json.Marshal(canonical)
	if err != nil {
		return nil, errors.New("devin: canonical request is not serializable")
	}
	cascadeID := structuralID("cascade\x00" + string(structure))

	prompts, systemPrompt, err := buildChatPrompts(input, cascadeID)
	if err != nil {
		return nil, err
	}
	tools, err := buildTools(canonical["tools"])
	if err != nil {
		return nil, err
	}
	choice, err := buildToolChoice(canonical["tool_choice"], tools)
	if err != nil {
		return nil, err
	}
	stops, err := buildStops(canonical["stop"])
	if err != nil {
		return nil, err
	}

	return &proto.GetChatMessageRequest{
		Metadata:                 &proto.Metadata{APIKey: sessionToken, UserJWT: userJWT, IDEName: "windsurf", IDEVersion: "3.2.23", ExtensionName: "windsurf", ExtensionVersion: "1.48.2", Locale: "en"},
		Prompt:                   systemPrompt,
		ChatMessagePrompts:       prompts,
		ChatModelUID:             model,
		RequestType:              proto.ChatMessageRequestTypeCascade,
		Configuration:            &proto.CompletionConfiguration{NumCompletions: 1, MaxTokens: 64000, MaxNewlines: 200, Temperature: 0.4, FirstTemperature: 0.4, TopK: 50, TopP: 1, StopPatterns: stops, FIMEOTProbabilityThreshold: 1},
		Tools:                    tools,
		DisableParallelToolCalls: true,
		ToolChoice:               choice,
		SystemPromptCacheOptions: &proto.PromptCacheOptions{Type: proto.CacheControlTypeEphemeral},
		CascadeID:                cascadeID,
		ProviderSource:           proto.ProviderSourceCascade,
		PlannerMode:              proto.ConversationalPlannerModeDefault,
		ExecutionID:              structuralID("execution\x00" + string(structure)),
	}, nil
}

func buildChatPrompts(input []any, cascadeID string) ([]proto.ChatMessagePrompt, string, error) {
	prompts := make([]proto.ChatMessagePrompt, 0, len(input))
	var system []string
	for index, raw := range input {
		item, ok := raw.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("devin: input item %d must be an object", index)
		}
		typ, _ := item["type"].(string)
		switch typ {
		case "message":
			role, _ := item["role"].(string)
			text, images, err := content(item["content"])
			if err != nil {
				return nil, "", fmt.Errorf("devin: input item %d: %w", index, err)
			}
			if role == "developer" || role == "system" {
				system = append(system, text)
			}
			source := proto.ChatMessageSourceUser
			var cacheOptions *proto.PromptCacheOptions
			switch role {
			case "assistant":
				source = proto.ChatMessageSourceSystem
			case "system":
				source = proto.ChatMessageSourceSystemPrompt
				cacheOptions = &proto.PromptCacheOptions{Type: proto.CacheControlTypeEphemeral}
			case "developer", "user":
			default:
				return nil, "", fmt.Errorf("devin: input item %d has unsupported role %q", index, role)
			}
			prompts = append(prompts, proto.ChatMessagePrompt{MessageID: itemID(item, structuralID(fmt.Sprintf("%s\x00%d\x00%s", cascadeID, index, role))), Source: source, Prompt: text, Images: images, PromptCacheOptions: cacheOptions})
		case "reasoning":
			thinking, err := summaryText(item["summary"])
			if err != nil {
				return nil, "", fmt.Errorf("devin: input item %d: %w", index, err)
			}
			signature, _ := item["encrypted_content"].(string)
			prompts = append(prompts, proto.ChatMessagePrompt{MessageID: itemID(item, structuralID(fmt.Sprintf("%s\x00%d\x00reasoning", cascadeID, index))), Source: proto.ChatMessageSourceSystem, Thinking: thinking, Signature: signature, OutputID: stringValue(item["id"])})
		case "function_call":
			id, name, arguments := stringValue(item["call_id"]), stringValue(item["name"]), stringValue(item["arguments"])
			if id == "" || name == "" || !json.Valid([]byte(arguments)) {
				return nil, "", fmt.Errorf("devin: input item %d has malformed function call", index)
			}
			prompts = append(prompts, proto.ChatMessagePrompt{MessageID: itemID(item, structuralID(fmt.Sprintf("%s\x00%d\x00assistant", cascadeID, index))), Source: proto.ChatMessageSourceSystem, ToolCalls: []proto.ChatToolCall{{ID: id, Name: name, ArgumentsJSON: arguments}}, OutputID: stringValue(item["id"])})
		case "function_call_output":
			id := stringValue(item["call_id"])
			if id == "" {
				return nil, "", fmt.Errorf("devin: input item %d has no call_id", index)
			}
			text, images, err := outputContent(item["output"])
			if err != nil {
				return nil, "", fmt.Errorf("devin: input item %d: %w", index, err)
			}
			isError, _ := item["is_error"].(bool)
			prompts = append(prompts, proto.ChatMessagePrompt{MessageID: itemID(item, structuralID(fmt.Sprintf("%s\x00%d\x00tool\x00%s", cascadeID, index, id))), Source: proto.ChatMessageSourceTool, ToolCallID: id, ToolResultIsError: isError, Prompt: text, Images: images, OutputID: stringValue(item["id"])})
		default:
			return nil, "", fmt.Errorf("devin: input item %d has unsupported type %q", index, typ)
		}
	}
	return prompts, strings.Join(system, "\n\n"), nil
}

func content(raw any) (string, []proto.ImageData, error) {
	parts, ok := raw.([]any)
	if !ok {
		return "", nil, errors.New("message content must be an array")
	}
	var text strings.Builder
	var images []proto.ImageData
	for _, rawPart := range parts {
		part, ok := rawPart.(map[string]any)
		if !ok {
			return "", nil, errors.New("content part must be an object")
		}
		switch stringValue(part["type"]) {
		case "input_text", "output_text":
			text.WriteString(stringValue(part["text"]))
		case "input_image":
			image, err := inlineImage(stringValue(part["image_url"]))
			if err != nil {
				return "", nil, err
			}
			images = append(images, image)
		default:
			return "", nil, fmt.Errorf("unsupported content type %q", stringValue(part["type"]))
		}
	}
	return text.String(), images, nil
}

func outputContent(raw any) (string, []proto.ImageData, error) {
	if text, ok := raw.(string); ok {
		return text, nil, nil
	}
	return content(raw)
}

func inlineImage(value string) (proto.ImageData, error) {
	if !strings.HasPrefix(value, "data:") {
		return proto.ImageData{}, errors.New("remote images are not supported")
	}
	header, encoded, ok := strings.Cut(strings.TrimPrefix(value, "data:"), ",")
	if !ok || !strings.HasSuffix(header, ";base64") {
		return proto.ImageData{}, errors.New("image must be a base64 data URL")
	}
	mime := strings.TrimSuffix(header, ";base64")
	if mime == "" {
		return proto.ImageData{}, errors.New("image MIME type is required")
	}
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		return proto.ImageData{}, errors.New("image has invalid base64 data")
	}
	return proto.ImageData{Base64Data: encoded, MIMEType: mime}, nil
}

func summaryText(raw any) (string, error) {
	parts, ok := raw.([]any)
	if !ok {
		return "", errors.New("reasoning summary must be an array")
	}
	var out strings.Builder
	for _, rawPart := range parts {
		part, ok := rawPart.(map[string]any)
		if !ok || stringValue(part["type"]) != "summary_text" {
			return "", errors.New("reasoning summary is malformed")
		}
		out.WriteString(stringValue(part["text"]))
	}
	return out.String(), nil
}

func buildTools(raw any) ([]proto.ChatToolDefinition, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, errors.New("devin: tools must be an array")
	}
	tools := make([]proto.ChatToolDefinition, 0, len(items))
	for index, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok || stringValue(item["type"]) != "function" {
			return nil, fmt.Errorf("devin: tool %d is malformed", index)
		}
		name := stringValue(item["name"])
		if name == "" {
			return nil, fmt.Errorf("devin: tool %d has no name", index)
		}
		parameters, exists := item["parameters"]
		if !exists {
			return nil, fmt.Errorf("devin: tool %d has no parameters", index)
		}
		schema, err := json.Marshal(parameters)
		if err != nil {
			return nil, fmt.Errorf("devin: tool %d parameters are malformed", index)
		}
		strict, _ := item["strict"].(bool)
		tools = append(tools, proto.ChatToolDefinition{Name: name, Description: stringValue(item["description"]), JSONSchemaString: string(schema), Strict: strict})
	}
	return tools, nil
}

func buildToolChoice(raw any, tools []proto.ChatToolDefinition) (*proto.ChatToolChoice, error) {
	if raw == nil {
		return &proto.ChatToolChoice{OptionName: "auto"}, nil
	}
	if option, ok := raw.(string); ok {
		switch option {
		case "", "auto":
			return &proto.ChatToolChoice{OptionName: "auto"}, nil
		case "none":
			return &proto.ChatToolChoice{OptionName: "none"}, nil
		case "required":
			return nil, errors.New("devin: tool choice required is not supported")
		default:
			return nil, fmt.Errorf("devin: unsupported tool choice %q", option)
		}
	}
	choice, ok := raw.(map[string]any)
	if !ok || stringValue(choice["type"]) != "function" || stringValue(choice["name"]) == "" {
		return nil, errors.New("devin: malformed selected tool choice")
	}
	name := stringValue(choice["name"])
	for i := range tools {
		if tools[i].Name == name {
			return &proto.ChatToolChoice{ToolName: name}, nil
		}
	}
	return nil, fmt.Errorf("devin: selected tool %q is not defined", name)
}

func buildStops(raw any) ([]string, error) {
	stops := append([]string(nil), defaultStopPatterns...)
	if raw == nil {
		return stops, nil
	}
	if stop, ok := raw.(string); ok {
		return append(stops, stop), nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, errors.New("devin: stop must be a string or array")
	}
	for _, item := range items {
		stop, ok := item.(string)
		if !ok {
			return nil, errors.New("devin: stop array must contain strings")
		}
		stops = append(stops, stop)
	}
	return stops, nil
}

func structuralID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	hexed := hex.EncodeToString(sum[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexed[:8], hexed[8:12], hexed[12:16], hexed[16:20], hexed[20:32])
}
func itemID(item map[string]any, fallback string) string {
	if id := stringValue(item["id"]); id != "" {
		return id
	}
	return fallback
}
func stringValue(value any) string { text, _ := value.(string); return text }
