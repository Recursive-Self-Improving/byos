package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

type oauthPage struct {
	layoutData
	Flow *OAuthFlow
}

func (h *Handler) handleOAuthPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	data := oauthPage{layoutData: h.layout(r, "Connect xAI account", "accounts")}
	state := r.URL.Query().Get("state")
	if state == "" {
		h.render(w, "oauth", http.StatusOK, data)
		return
	}
	if _, ok := resourceID(state); !ok {
		h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		return
	}
	flow, err := h.services.OAuth.Get(r.Context(), state)
	if err != nil {
		if isNotFound(err) {
			h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		} else {
			h.renderError(w, r, http.StatusServiceUnavailable, "The connection flow could not be loaded.")
		}
		return
	}
	flow.State = state
	flow = h.prepareOAuthFlow(flow)
	if flow.Status == "completed" {
		if accountID, ok := resourceID(flow.AccountID); ok {
			h.redirect(w, r, accountURL(accountID))
			return
		}
		flow.Status = "failed"
		flow.SanitizedMessage = "The completed account could not be located."
	}
	data.Flow = &flow
	h.render(w, "oauth", http.StatusOK, data)
}

func (h *Handler) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	flow, err := h.services.OAuth.Start(r.Context())
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "A new connection flow could not be started.")
		return
	}
	state, ok := resourceID(flow.State)
	if !ok {
		h.renderError(w, r, http.StatusServiceUnavailable, "A new connection flow could not be started.")
		return
	}
	h.redirect(w, r, "/admin/oauth/new?state="+url.QueryEscape(state))
}

type oauthStatusResponse struct {
	Status      string `json:"status"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	PollAfterMS int64  `json:"poll_after_ms,omitempty"`
	AccountURL  string `json:"account_url,omitempty"`
	SafeMessage string `json:"message,omitempty"`
}

func (h *Handler) handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	state, ok := resourceID(r.PathValue("state"))
	if !ok {
		h.writeOAuthError(w, http.StatusNotFound, "Connection flow not found.")
		return
	}
	flow, err := h.services.OAuth.Get(r.Context(), state)
	if err != nil {
		if isNotFound(err) {
			h.writeOAuthError(w, http.StatusNotFound, "Connection flow not found.")
		} else {
			h.writeOAuthError(w, http.StatusServiceUnavailable, "Connection status is temporarily unavailable.")
		}
		return
	}
	flow.State = state
	flow = h.prepareOAuthFlow(flow)
	response := oauthStatusResponse{
		Status:      flow.Status,
		PollAfterMS: flow.PollAfter.Milliseconds(),
		SafeMessage: flow.SanitizedMessage,
	}
	if !flow.ExpiresAt.IsZero() {
		response.ExpiresAt = flow.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if flow.Status == "completed" {
		if accountID, valid := resourceID(flow.AccountID); valid {
			response.AccountURL = accountURL(accountID)
		} else {
			response.Status = "failed"
			response.SafeMessage = "The completed account could not be located."
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleOAuthCancel(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	state, ok := resourceID(r.PathValue("state"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		return
	}
	if err := h.services.OAuth.Cancel(r.Context(), state); err != nil {
		h.renderMutationError(w, r, err, "The connection flow could not be cancelled.")
		return
	}
	h.redirect(w, r, "/admin/oauth/new?notice=oauth-cancelled")
}

func (h *Handler) prepareOAuthFlow(flow OAuthFlow) OAuthFlow {
	flow.Status = normalizedOAuthStatus(flow.Status)
	flow.SanitizedMessage = truncateText(strings.TrimSpace(flow.SanitizedMessage), 300)
	if flow.Status == "pending" && !flow.ExpiresAt.IsZero() && !h.now().Before(flow.ExpiresAt) {
		flow.Status = "expired"
		if flow.SanitizedMessage == "" {
			flow.SanitizedMessage = "The device code expired. Start a new connection."
		}
	}
	if flow.PollAfter < time.Second {
		flow.PollAfter = time.Second
	}
	if flow.PollAfter > 30*time.Second {
		flow.PollAfter = 30 * time.Second
	}
	flow.VerificationURL = safeVerificationURL(flow.VerificationURL)
	return flow
}

func normalizedOAuthStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "starting", "pending", "authorization_pending":
		return "pending"
	case "completed", "cancelled", "denied", "expired", "failed":
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return "failed"
	}
}

func safeVerificationURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	return parsed.String()
}

func truncateText(value string, maximum int) string {
	if utf8.RuneCountInString(value) <= maximum {
		return value
	}
	runes := []rune(value)
	return string(runes[:maximum])
}

func (h *Handler) writeOAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
