package openai

import (
	"context"
	"encoding/json"
	"net/http"

	apierrors "byos/internal/api/errors"
)

type Model struct {
	ID      string
	Created int64
	OwnedBy string
}
type ModelCatalog interface {
	PublicModels(context.Context) ([]Model, error)
}

func ModelsHandler(catalog ModelCatalog) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		models, err := catalog.PublicModels(r.Context())
		if err != nil {
			apierrors.WriteOpenAI(w, apierrors.OpenAI(apierrors.InternalFailure, 0))
			return
		}
		data := make([]map[string]any, 0, len(models))
		for _, model := range models {
			if model.OwnedBy == "" {
				apierrors.WriteOpenAI(w, apierrors.OpenAI(apierrors.InternalFailure, 0))
				return
			}
			data = append(data, map[string]any{"id": model.ID, "object": "model", "created": model.Created, "owned_by": model.OwnedBy})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
	})
}
