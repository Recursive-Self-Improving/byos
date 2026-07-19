package provider

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestKindValidationAndParsing(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"xai", "devin"} {
		kind, err := ParseKind(value)
		if err != nil {
			t.Fatalf("ParseKind(%q): %v", value, err)
		}
		if !kind.Valid() || kind.String() != value {
			t.Fatalf("ParseKind(%q) = %q, valid=%v", value, kind, kind.Valid())
		}
	}
	for _, value := range []string{"", "XAI", "Devin", " xai", "xai ", "other"} {
		kind, err := ParseKind(value)
		if !errors.Is(err, ErrInvalidKind) {
			t.Errorf("ParseKind(%q) error = %v, want ErrInvalidKind", value, err)
		}
		if kind != "" {
			t.Errorf("ParseKind(%q) kind = %q, want empty", value, kind)
		}
	}
}

func TestKindTextAndDatabaseRoundTrips(t *testing.T) {
	t.Parallel()
	for _, want := range []Kind{XAI, Devin} {
		text, err := want.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%q): %v", want, err)
		}
		var fromText Kind
		if err := fromText.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if fromText != want {
			t.Errorf("text round trip = %q, want %q", fromText, want)
		}

		value, err := want.Value()
		if err != nil {
			t.Fatalf("Value(%q): %v", want, err)
		}
		if value != driver.Value(string(want)) {
			t.Errorf("Value(%q) = %#v", want, value)
		}
		for _, source := range []any{value, []byte(want)} {
			var fromDB Kind
			if err := fromDB.Scan(source); err != nil {
				t.Fatalf("Scan(%T(%q)): %v", source, source, err)
			}
			if fromDB != want {
				t.Errorf("database round trip = %q, want %q", fromDB, want)
			}
		}
	}
}

func TestKindRejectsInvalidTextAndDatabaseValues(t *testing.T) {
	t.Parallel()
	if _, err := (Kind("unknown")).MarshalText(); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("MarshalText error = %v, want ErrInvalidKind", err)
	}
	if _, err := (Kind("unknown")).Value(); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("Value error = %v, want ErrInvalidKind", err)
	}
	original := XAI
	if err := original.UnmarshalText([]byte("unknown")); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("UnmarshalText error = %v, want ErrInvalidKind", err)
	}
	if original != XAI {
		t.Fatalf("failed UnmarshalText changed receiver to %q", original)
	}
	for _, source := range []any{nil, 42, "", "DEVIN"} {
		kind := Devin
		if err := kind.Scan(source); err == nil {
			t.Errorf("Scan(%T(%v)) succeeded", source, source)
		}
		if kind != Devin {
			t.Errorf("failed Scan changed receiver to %q", kind)
		}
	}
}

func TestResolvedModelContainsStaticIdentityOnly(t *testing.T) {
	t.Parallel()
	want := []string{"PublicName", "UpstreamName", "Provider", "OwnedBy", "PolicyKey"}
	typeOf := reflect.TypeOf(ResolvedModel{})
	if typeOf.NumField() != len(want) {
		t.Fatalf("ResolvedModel has %d fields, want %d", typeOf.NumField(), len(want))
	}
	for index, name := range want {
		if typeOf.Field(index).Name != name {
			t.Errorf("ResolvedModel field %d = %s, want %s", index, typeOf.Field(index).Name, name)
		}
	}
}

type fakePolicy struct{ calls int }

func (f *fakePolicy) Prepare(_ context.Context, _ ResolvedModel, body []byte) ([]byte, error) {
	f.calls++
	return append(body, '\n'), nil
}

type fakeClient struct{ marshals int }

func (f *fakeClient) Execute(_ context.Context, request GenerationRequest) ([]Event, error) {
	f.marshals++
	return []Event{{Event: "response.completed", Data: append([]byte(nil), request.CanonicalBody...)}}, nil
}

func (f *fakeClient) Stream(_ context.Context, _ GenerationRequest) (Stream, error) {
	f.marshals++
	return &fakeStream{}, nil
}

type fakeStream struct{ done bool }

func (f *fakeStream) Next(context.Context) (Event, error) {
	if f.done {
		return Event{}, io.EOF
	}
	f.done = true
	return Event{Event: "response.completed"}, nil
}
func (*fakeStream) Close() error { return nil }

type fakeCredentials struct{}

func (fakeCredentials) Credential(context.Context, string) (Credential, error) {
	return Credential{Value: "opaque"}, nil
}
func (fakeCredentials) AuthenticationFailed(context.Context, string, *UpstreamError) error {
	return nil
}

type fakeDiscoverer struct{}

func (fakeDiscoverer) Discover(context.Context, Credential) ([]DiscoveredModel, error) {
	return []DiscoveredModel{{UpstreamName: "model"}}, nil
}

type fakeUsageFetcher struct{}

func (fakeUsageFetcher) FetchUsage(context.Context, Credential) (UsageSnapshot, error) {
	return UsageSnapshot{}, nil
}

type fakeCatalog struct{ model ResolvedModel }

func (f fakeCatalog) Resolve(string) (ResolvedModel, error) { return f.model, nil }

type fakeRegistry struct{ capabilities Capabilities }

func (f fakeRegistry) Capabilities(Kind, string) (Capabilities, bool) {
	return f.capabilities, true
}

var (
	_ RequestPolicy      = (*fakePolicy)(nil)
	_ GenerationClient   = (*fakeClient)(nil)
	_ Stream             = (*fakeStream)(nil)
	_ CredentialManager  = fakeCredentials{}
	_ ModelDiscoverer    = fakeDiscoverer{}
	_ UsageFetcher       = fakeUsageFetcher{}
	_ ModelCatalog       = fakeCatalog{}
	_ CapabilityRegistry = fakeRegistry{}
)

func TestOptionalCapabilitiesAreAbsentRatherThanNoOps(t *testing.T) {
	t.Parallel()
	capabilities := Capabilities{
		Policy:      &fakePolicy{},
		Generation:  &fakeClient{},
		Credentials: fakeCredentials{},
	}
	if capabilities.ModelDiscoverer != nil || capabilities.UsageFetcher != nil {
		t.Fatal("optional capabilities must be representable by nil")
	}
}

func TestCatalogPolicyAndRegistryDoNotMarshalProviderWireBody(t *testing.T) {
	t.Parallel()
	model := ResolvedModel{PublicName: "public", UpstreamName: "upstream", Provider: Devin, OwnedBy: "devin", PolicyKey: "devin"}
	policy := &fakePolicy{}
	client := &fakeClient{}
	catalog := fakeCatalog{model: model}
	registry := fakeRegistry{capabilities: Capabilities{Policy: policy, Generation: client, Credentials: fakeCredentials{}}}

	resolved, err := catalog.Resolve("public")
	if err != nil {
		t.Fatal(err)
	}
	capabilities, ok := registry.Capabilities(resolved.Provider, resolved.PolicyKey)
	if !ok {
		t.Fatal("runtime capabilities missing")
	}
	body, err := capabilities.Policy.Prepare(context.Background(), resolved, []byte(`{"model":"public"}`))
	if err != nil {
		t.Fatal(err)
	}
	if client.marshals != 0 {
		t.Fatalf("wire marshal count before client = %d, want 0", client.marshals)
	}
	resolvedBody := []byte(`{"model":"upstream"}`)
	resolvedBody = append(resolvedBody, body[len(body)-1])
	events, err := capabilities.Generation.Execute(context.Background(), GenerationRequest{
		Model: resolved, CanonicalBody: resolvedBody, Credential: Credential{Value: "opaque"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.calls != 1 || client.marshals != 1 {
		t.Fatalf("policy calls=%d, client marshals=%d; want 1, 1", policy.calls, client.marshals)
	}
	if len(events) != 1 || string(events[0].Data) != string(resolvedBody) {
		t.Fatalf("client received body %q, want %q", events[0].Data, resolvedBody)
	}
}

func TestNeutralErrorAndUsageMetadata(t *testing.T) {
	t.Parallel()
	err := &UpstreamError{
		Provider: Devin,
		Status:   429,
		Classification: ErrorClassification{
			Class: ErrorClass("rate_limit"), RetryNext: true,
			CooldownScope: CooldownAccount, PublicStatus: 429,
			PublicCode: "rate_limit_exceeded", PublicMessage: "provider rate limited",
		},
	}
	if got := err.Error(); got != "devin upstream returned HTTP 429" {
		t.Fatalf("Error() = %q", got)
	}
	event := Event{Usage: Usage{InputTokens: 3, OutputTokens: 5, TotalTokens: 8, CacheReadTokens: 2}}
	if event.Usage.TotalTokens != event.Usage.InputTokens+event.Usage.OutputTokens {
		t.Fatal("usage fixture total is inconsistent")
	}
}
