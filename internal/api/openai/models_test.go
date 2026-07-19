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
	models := []Model{
		{ID: "grok", Created: 1, OwnedBy: "byos"},
		{ID: "grok-4.5", Created: 2, OwnedBy: "xai"},
		{ID: "kimi-k2-7", Created: 3, OwnedBy: "devin"},
		{ID: "glm-5-2", Created: 4, OwnedBy: "devin"},
		{ID: "swe-1-6-slow", Created: 5, OwnedBy: "devin"},
	}
	response := httptest.NewRecorder()
	ModelsHandler(catalogStub{models: models}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Object != "list" || len(body.Data) != len(models) {
		t.Fatalf("body=%s", response.Body.String())
	}
	for i, want := range models {
		got := body.Data[i]
		if got.ID != want.ID || got.Object != "model" || got.Created != want.Created || got.OwnedBy != want.OwnedBy {
			t.Fatalf("model[%d]=%+v want=%+v", i, got, want)
		}
	}
}

func TestModelsHandlerRejectsMissingOwnership(t *testing.T) {
	response := httptest.NewRecorder()
	ModelsHandler(catalogStub{models: []Model{{ID: "grok"}}}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if string(response.Body.Bytes()) == "" {
		t.Fatal("missing sanitized error response")
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("body=%s err=%v", response.Body.String(), err)
	}
	if string(response.Body.Bytes()) == `{"object":"list","data":[{"id":"grok","object":"model","created":0,"owned_by":"xai"}]}` {
		t.Fatal("missing owner silently defaulted to xai")
	}
}
