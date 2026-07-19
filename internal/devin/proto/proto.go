// Package proto implements the minimal protobuf wire surface needed by the Devin client.
//
// The field numbers and RPC paths are adapted from the following MIT-licensed files in
// https://github.com/can1357/oh-my-pi at revision
// fc01e3b6cba6e1add44a1613baa891a9b873f8a9:
//
//	packages/ai/src/providers/devin/proto/exa/auth_pb/auth.proto
//	packages/ai/src/providers/devin/proto/exa/api_server_pb/api_server.proto
//	packages/ai/src/providers/devin/proto/exa/chat_pb/chat.proto
//	packages/ai/src/providers/devin/proto/exa/codeium_common_pb/codeium_common.proto
//
// This is intentionally hand-written protowire code, not generated protobuf code. It
// excludes the upstream plugin, media, WebSocket, capacity, analytics, and discovery
// surfaces. See THIRD_PARTY_NOTICES for license provenance.
package proto

import (
	"errors"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	AuthServiceGetUserJWTPath    = "/exa.auth_pb.AuthService/GetUserJwt"
	APIServiceGetChatMessagePath = "/exa.api_server_pb.ApiServerService/GetChatMessage"
)

type ProviderSource int32

const (
	ProviderSourceUnspecified ProviderSource = 0
	ProviderSourceCascade     ProviderSource = 12
)

type ChatMessageSource int32

const (
	ChatMessageSourceUnspecified  ChatMessageSource = 0
	ChatMessageSourceUser         ChatMessageSource = 1
	ChatMessageSourceSystem       ChatMessageSource = 2
	ChatMessageSourceUnknown      ChatMessageSource = 3
	ChatMessageSourceTool         ChatMessageSource = 4
	ChatMessageSourceSystemPrompt ChatMessageSource = 5
)

type ConversationalPlannerMode int32

const (
	ConversationalPlannerModeUnspecified ConversationalPlannerMode = 0
	ConversationalPlannerModeDefault     ConversationalPlannerMode = 1
)

type StopReason int32

const (
	StopReasonUnspecified StopReason = iota
	StopReasonIncomplete
	StopReasonStopPattern
	StopReasonMaxTokens
	StopReasonMinLogProb
	StopReasonMaxNewlines
	StopReasonExitScope
	StopReasonNonfiniteLogitOrProb
	StopReasonFirstNonWhitespaceLine
	StopReasonPartial
	StopReasonFunctionCall
	StopReasonContentFilter
	StopReasonNonInsertion
	StopReasonError
)

type CacheControlType int32

const (
	CacheControlTypeUnspecified CacheControlType = 0
	CacheControlTypeEphemeral   CacheControlType = 1
)

type ChatMessageRequestType int32

const (
	ChatMessageRequestTypeUnspecified ChatMessageRequestType = 0
	ChatMessageRequestTypeCascade     ChatMessageRequestType = 5
)

type Metadata struct {
	IDEName, ExtensionVersion, APIKey, Locale, IDEVersion, ExtensionName, UserJWT string
}

type GetUserJWTRequest struct{ Metadata *Metadata }
type GetUserJWTResponse struct{ UserJWT, CustomAPIServerURL string }

type CompletionConfiguration struct {
	NumCompletions, MaxTokens, MaxNewlines                                                        uint64
	Temperature, FirstTemperature                                                                 float64
	TopK                                                                                          uint64
	TopP                                                                                          float64
	StopPatterns                                                                                  []string
	Seed                                                                                          uint64
	FIMEOTProbabilityThreshold                                                                    float64
	UseFIMEOTThreshold, DoNotScoreStopTokens, SqrtLenNormalizedLogProbScore, LastMessageIsPartial bool
}

type ChatToolCall struct{ ID, Name, ArgumentsJSON string }
type ImageData struct{ Base64Data, MIMEType, Caption string }
type PromptCacheOptions struct{ Type CacheControlType }
type ChatMessagePrompt struct {
	MessageID                                           string
	Source                                              ChatMessageSource
	Prompt                                              string
	ToolCalls                                           []ChatToolCall
	ToolCallID                                          string
	PromptCacheOptions                                  *PromptCacheOptions
	ToolResultIsError                                   bool
	Images                                              []ImageData
	Thinking, Signature, OutputID, SignatureType, Phase string
}
type ChatToolDefinition struct {
	Name, Description, JSONSchemaString string
	Strict                              bool
}
type ChatToolChoice struct{ OptionName, ToolName string }

type GetChatMessageRequest struct {
	Metadata                 *Metadata
	Prompt                   string
	ChatMessagePrompts       []ChatMessagePrompt
	ChatModelUID             string
	RequestType              ChatMessageRequestType
	Configuration            *CompletionConfiguration
	Tools                    []ChatToolDefinition
	DisableParallelToolCalls bool
	ToolChoice               *ChatToolChoice
	SystemPromptCacheOptions *PromptCacheOptions
	CascadeID                string
	ProviderSource           ProviderSource
	PlannerMode              ConversationalPlannerMode
	ExecutionID              string
}

type ModelUsageStats struct {
	ModelUID, BillingModelUID, RequestedModelUID                 string
	InputTokens, OutputTokens, CacheWriteTokens, CacheReadTokens uint64
	MessageID                                                    string
}

type GetChatMessageResponse struct {
	MessageID, DeltaText                                                   string
	DeltaTokens                                                            uint32
	StopReason                                                             StopReason
	DeltaToolCalls                                                         []ChatToolCall
	Usage                                                                  *ModelUsageStats
	DeltaThinking, DeltaSignature, OutputID, RequestID, DeltaSignatureType string
	ActualModelUID                                                         *string
	Phase                                                                  string
}

type marshaler interface{ Marshal() ([]byte, error) }

var (
	_ marshaler = (*GetUserJWTRequest)(nil)
	_ marshaler = (*GetChatMessageRequest)(nil)
	_ marshaler = (*ChatMessagePrompt)(nil)
	_ marshaler = (*ChatToolDefinition)(nil)
)

func stringField(b []byte, n protowire.Number, s string) []byte {
	if s == "" {
		return b
	}
	b = protowire.AppendTag(b, n, protowire.BytesType)
	return protowire.AppendString(b, s)
}
func varintField(b []byte, n protowire.Number, v uint64) []byte {
	if v == 0 {
		return b
	}
	b = protowire.AppendTag(b, n, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}
func fixed64Field(b []byte, n protowire.Number, v float64) []byte {
	if v == 0 {
		return b
	}
	b = protowire.AppendTag(b, n, protowire.Fixed64Type)
	return protowire.AppendFixed64(b, math.Float64bits(v))
}
func messageField(b []byte, n protowire.Number, m marshaler) ([]byte, error) {
	if m == nil {
		return b, nil
	}
	p, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	b = protowire.AppendTag(b, n, protowire.BytesType)
	return protowire.AppendBytes(b, p), nil
}

func (m *Metadata) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	b = stringField(b, 1, m.IDEName)
	b = stringField(b, 2, m.ExtensionVersion)
	b = stringField(b, 3, m.APIKey)
	b = stringField(b, 4, m.Locale)
	b = stringField(b, 7, m.IDEVersion)
	b = stringField(b, 12, m.ExtensionName)
	b = stringField(b, 21, m.UserJWT)
	return b, nil
}
func (m *GetUserJWTRequest) Marshal() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return messageField(nil, 1, m.Metadata)
}
func (m *GetUserJWTResponse) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	b = stringField(b, 1, m.UserJWT)
	b = stringField(b, 2, m.CustomAPIServerURL)
	return b, nil
}
func (m *CompletionConfiguration) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	b = varintField(b, 1, m.NumCompletions)
	b = varintField(b, 2, m.MaxTokens)
	b = varintField(b, 3, m.MaxNewlines)
	b = fixed64Field(b, 5, m.Temperature)
	b = fixed64Field(b, 6, m.FirstTemperature)
	b = varintField(b, 7, m.TopK)
	b = fixed64Field(b, 8, m.TopP)
	for _, s := range m.StopPatterns {
		b = stringField(b, 9, s)
	}
	b = varintField(b, 10, m.Seed)
	b = fixed64Field(b, 11, m.FIMEOTProbabilityThreshold)
	b = varintField(b, 12, boolVarint(m.UseFIMEOTThreshold))
	b = varintField(b, 13, boolVarint(m.DoNotScoreStopTokens))
	b = varintField(b, 14, boolVarint(m.SqrtLenNormalizedLogProbScore))
	b = varintField(b, 15, boolVarint(m.LastMessageIsPartial))
	return b, nil
}
func (m *ChatToolCall) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	b = stringField(b, 1, m.ID)
	b = stringField(b, 2, m.Name)
	b = stringField(b, 3, m.ArgumentsJSON)
	return b, nil
}
func (m *ImageData) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	b = stringField(b, 1, m.Base64Data)
	b = stringField(b, 2, m.MIMEType)
	b = stringField(b, 3, m.Caption)
	return b, nil
}
func (m *PromptCacheOptions) Marshal() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return varintField(nil, 1, uint64(m.Type)), nil
}
func (m *ChatMessagePrompt) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	b = stringField(b, 1, m.MessageID)
	b = varintField(b, 2, uint64(m.Source))
	b = stringField(b, 3, m.Prompt)
	var err error
	for i := range m.ToolCalls {
		b, err = messageField(b, 6, &m.ToolCalls[i])
		if err != nil {
			return nil, err
		}
	}
	b = stringField(b, 7, m.ToolCallID)
	b, err = messageField(b, 8, m.PromptCacheOptions)
	if err != nil {
		return nil, err
	}
	b = varintField(b, 9, boolVarint(m.ToolResultIsError))
	for i := range m.Images {
		b, err = messageField(b, 10, &m.Images[i])
		if err != nil {
			return nil, err
		}
	}
	b = stringField(b, 11, m.Thinking)
	b = stringField(b, 12, m.Signature)
	b = stringField(b, 15, m.OutputID)
	b = stringField(b, 18, m.SignatureType)
	b = stringField(b, 19, m.Phase)
	return b, nil
}
func (m *ChatToolDefinition) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	b = stringField(b, 1, m.Name)
	b = stringField(b, 2, m.Description)
	b = stringField(b, 3, m.JSONSchemaString)
	b = varintField(b, 12, boolVarint(m.Strict))
	return b, nil
}
func (m *ChatToolChoice) Marshal() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	if m.OptionName != "" && m.ToolName != "" {
		return nil, errors.New("devin proto: chat tool choice has both option and tool")
	}
	if m.ToolName != "" {
		return stringField(nil, 2, m.ToolName), nil
	}
	return stringField(nil, 1, m.OptionName), nil
}
func (m *ModelUsageStats) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	b = varintField(b, 2, m.InputTokens)
	b = varintField(b, 3, m.OutputTokens)
	b = varintField(b, 4, m.CacheWriteTokens)
	b = varintField(b, 5, m.CacheReadTokens)
	b = stringField(b, 7, m.MessageID)
	b = stringField(b, 9, m.ModelUID)
	b = stringField(b, 10, m.BillingModelUID)
	b = stringField(b, 11, m.RequestedModelUID)
	return b, nil
}
func (m *GetChatMessageRequest) Marshal() ([]byte, error) {
	var b []byte
	if m == nil {
		return b, nil
	}
	var err error
	b, err = messageField(b, 1, m.Metadata)
	if err != nil {
		return nil, err
	}
	b = stringField(b, 2, m.Prompt)
	for i := range m.ChatMessagePrompts {
		b, err = messageField(b, 3, &m.ChatMessagePrompts[i])
		if err != nil {
			return nil, err
		}
	}
	b = varintField(b, 7, uint64(m.RequestType))
	b, err = messageField(b, 8, m.Configuration)
	if err != nil {
		return nil, err
	}
	for i := range m.Tools {
		b, err = messageField(b, 10, &m.Tools[i])
		if err != nil {
			return nil, err
		}
	}
	b = varintField(b, 11, boolVarint(m.DisableParallelToolCalls))
	b, err = messageField(b, 12, m.ToolChoice)
	if err != nil {
		return nil, err
	}
	b, err = messageField(b, 13, m.SystemPromptCacheOptions)
	if err != nil {
		return nil, err
	}
	b = stringField(b, 16, m.CascadeID)
	b = varintField(b, 18, uint64(m.ProviderSource))
	b = varintField(b, 20, uint64(m.PlannerMode))
	b = stringField(b, 21, m.ChatModelUID)
	b = stringField(b, 22, m.ExecutionID)
	return b, nil
}
func boolVarint(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

func (m *GetUserJWTResponse) Unmarshal(b []byte) error {
	if m == nil {
		return errors.New("devin proto: nil GetUserJWTResponse")
	}
	*m = GetUserJWTResponse{}
	for len(b) > 0 {
		n, t, k := protowire.ConsumeTag(b)
		if k < 0 {
			return protowire.ParseError(k)
		}
		b = b[k:]
		if (n == 1 || n == 2) && t == protowire.BytesType {
			s, k := protowire.ConsumeString(b)
			if k < 0 {
				return protowire.ParseError(k)
			}
			if n == 1 {
				m.UserJWT = s
			} else {
				m.CustomAPIServerURL = s
			}
			b = b[k:]
			continue
		}
		k = protowire.ConsumeFieldValue(n, t, b)
		if k < 0 {
			return protowire.ParseError(k)
		}
		b = b[k:]
	}
	return nil
}

const (
	maxUnmarshalBytes = 32 << 20
	maxDeltaToolCalls = 4096
)

func copiedString(b []byte) string { return string(append([]byte(nil), b...)) }

func consumeBytesField(b []byte) ([]byte, []byte, error) {
	v, n := protowire.ConsumeBytes(b)
	if n < 0 {
		return nil, nil, protowire.ParseError(n)
	}
	return v, b[n:], nil
}

func skipField(n protowire.Number, typ protowire.Type, b []byte) ([]byte, error) {
	k := protowire.ConsumeFieldValue(n, typ, b)
	if k < 0 {
		return nil, protowire.ParseError(k)
	}
	return b[k:], nil
}

func checkWire(field protowire.Number, got, want protowire.Type) error {
	if got != want {
		return errors.New("devin proto: invalid wire type for field " + string(rune(field+'0')))
	}
	return nil
}

func (m *ChatToolCall) Unmarshal(b []byte) error {
	if m == nil {
		return errors.New("devin proto: nil ChatToolCall")
	}
	if len(b) > maxUnmarshalBytes {
		return errors.New("devin proto: message too large")
	}
	*m = ChatToolCall{}
	for len(b) > 0 {
		field, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if field >= 1 && field <= 3 {
			if err := checkWire(field, typ, protowire.BytesType); err != nil {
				return err
			}
			v, rest, err := consumeBytesField(b)
			if err != nil {
				return err
			}
			b = rest
			s := copiedString(v)
			if field == 1 {
				m.ID = s
			} else if field == 2 {
				m.Name = s
			} else {
				m.ArgumentsJSON = s
			}
			continue
		}
		var err error
		b, err = skipField(field, typ, b)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *ModelUsageStats) Unmarshal(b []byte) error {
	if m == nil {
		return errors.New("devin proto: nil ModelUsageStats")
	}
	if len(b) > maxUnmarshalBytes {
		return errors.New("devin proto: message too large")
	}
	*m = ModelUsageStats{}
	for len(b) > 0 {
		field, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		switch field {
		case 2, 3, 4, 5:
			if err := checkWire(field, typ, protowire.VarintType); err != nil {
				return err
			}
			v, k := protowire.ConsumeVarint(b)
			if k < 0 {
				return protowire.ParseError(k)
			}
			b = b[k:]
			switch field {
			case 2:
				m.InputTokens = v
			case 3:
				m.OutputTokens = v
			case 4:
				m.CacheWriteTokens = v
			case 5:
				m.CacheReadTokens = v
			}
		case 7, 9, 10, 11:
			if err := checkWire(field, typ, protowire.BytesType); err != nil {
				return err
			}
			v, rest, err := consumeBytesField(b)
			if err != nil {
				return err
			}
			b = rest
			s := copiedString(v)
			switch field {
			case 7:
				m.MessageID = s
			case 9:
				m.ModelUID = s
			case 10:
				m.BillingModelUID = s
			case 11:
				m.RequestedModelUID = s
			}
		default:
			var err error
			b, err = skipField(field, typ, b)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *GetChatMessageResponse) Unmarshal(b []byte) error {
	if m == nil {
		return errors.New("devin proto: nil GetChatMessageResponse")
	}
	if len(b) > maxUnmarshalBytes {
		return errors.New("devin proto: message too large")
	}
	*m = GetChatMessageResponse{}
	for len(b) > 0 {
		field, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		switch field {
		case 1, 3, 9, 10, 15, 17, 21, 23, 25:
			if err := checkWire(field, typ, protowire.BytesType); err != nil {
				return err
			}
			v, rest, err := consumeBytesField(b)
			if err != nil {
				return err
			}
			b = rest
			s := copiedString(v)
			switch field {
			case 1:
				m.MessageID = s
			case 3:
				m.DeltaText = s
			case 9:
				m.DeltaThinking = s
			case 10:
				m.DeltaSignature = s
			case 15:
				m.OutputID = s
			case 17:
				m.RequestID = s
			case 21:
				m.DeltaSignatureType = s
			case 23:
				m.ActualModelUID = &s
			case 25:
				m.Phase = s
			}
		case 4, 5:
			if err := checkWire(field, typ, protowire.VarintType); err != nil {
				return err
			}
			v, k := protowire.ConsumeVarint(b)
			if k < 0 {
				return protowire.ParseError(k)
			}
			b = b[k:]
			if field == 4 && v > math.MaxUint32 {
				return errors.New("devin proto: uint32 overflow")
			}
			if field == 5 && v > math.MaxInt32 {
				return errors.New("devin proto: int32 overflow")
			}
			if field == 4 {
				m.DeltaTokens = uint32(v)
			} else {
				m.StopReason = StopReason(v)
			}
		case 6:
			if err := checkWire(field, typ, protowire.BytesType); err != nil {
				return err
			}
			if len(m.DeltaToolCalls) >= maxDeltaToolCalls {
				return errors.New("devin proto: too many tool calls")
			}
			v, rest, err := consumeBytesField(b)
			if err != nil {
				return err
			}
			b = rest
			var call ChatToolCall
			if err := call.Unmarshal(v); err != nil {
				return err
			}
			m.DeltaToolCalls = append(m.DeltaToolCalls, call)
		case 7:
			if err := checkWire(field, typ, protowire.BytesType); err != nil {
				return err
			}
			v, rest, err := consumeBytesField(b)
			if err != nil {
				return err
			}
			b = rest
			usage := new(ModelUsageStats)
			if err := usage.Unmarshal(v); err != nil {
				return err
			}
			m.Usage = usage
		default:
			var err error
			b, err = skipField(field, typ, b)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
