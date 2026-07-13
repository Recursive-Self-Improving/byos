package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type catalogStub struct {
	models []Model
	err    error
}

func (c catalogStub) PublicModels(context.Context) ([]Model, error) { return c.models, c.err }
func TestModelsHandler(t *testing.T) {
	response := httptest.NewRecorder()
	ModelsHandler(catalogStub{models: []Model{{ID: "grok"}, {ID: "grok-4.5"}}}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if response.Code != 200 {
		t.Fatalf("status=%d", response.Code)
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Data) != 2 {
		t.Fatalf("body=%s err=%v", response.Body.String(), err)
	}
	for _, item := range body.Data {
		if item["id"] != "grok" && item["id"] != "grok-4.5" {
			t.Fatalf("unexpected model=%v", item)
		}
	}
}
