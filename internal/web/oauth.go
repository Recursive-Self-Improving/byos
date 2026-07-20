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
	Provider Provider
	Flow     *OAuthFlow
}

func (h *Handler) handleOAuthPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	selected, ok := parseOAuthProvider(r.URL.Query().Get("provider"), ProviderXAI)
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, "Choose xAI or Devin as the account provider.")
		return
	}
	data := oauthPage{layoutData: h.layout(r, "Connect "+providerLabel(selected)+" account", "accounts"), Provider: selected}
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		h.render(w, "oauth", http.StatusOK, data)
		return
	}
	if _, ok := resourceID(sessionID); !ok {
		h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		return
	}
	flow, err := h.services.OAuth.Get(r.Context(), selected, sessionID)
	if err != nil {
		h.renderOAuthLoadError(w, r, err)
		return
	}
	if flow.Provider != selected || flow.SessionID != sessionID {
		h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		return
	}
	flow = h.prepareOAuthFlow(flow)
	if flow.Status == "completed" {
		if accountID, valid := resourceID(flow.AccountID); valid {
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
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "The connection form could not be read.")
		return
	}
	selected, ok := parseOAuthProvider(r.PostForm.Get("provider"), ProviderXAI)
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, "Choose xAI or Devin as the account provider.")
		return
	}
	flow, err := h.services.OAuth.Start(r.Context(), selected)
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "A new connection flow could not be started.")
		return
	}
	sessionID, valid := resourceID(flow.SessionID)
	if !valid || flow.Provider != selected {
		h.renderError(w, r, http.StatusServiceUnavailable, "A new connection flow could not be started.")
		return
	}
	h.redirect(w, r, oauthPageURL(selected, sessionID))
}

func (h *Handler) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	selected, sessionID, ok := oauthPath(r)
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		return
	}
	flow, err := h.services.OAuth.Get(r.Context(), selected, sessionID)
	if err != nil {
		h.renderOAuthLoadError(w, r, err)
		return
	}
	if flow.Provider != selected || flow.SessionID != sessionID {
		h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		return
	}
	flow = h.prepareOAuthFlow(flow)
	if flow.Status == "completed" {
		if accountID, valid := resourceID(flow.AccountID); valid {
			h.redirect(w, r, accountURL(accountID))
			return
		}
	}
	if flow.Status != "pending" || flow.AuthorizationURL == "" {
		h.renderError(w, r, http.StatusGone, "The authorization link is no longer available. Start a new connection.")
		return
	}
	// Write only a Location header. net/http.Redirect would also render the
	// provider URL, whose OAuth state must never appear in Web HTML.
	w.Header().Set("Location", flow.AuthorizationURL)
	w.WriteHeader(http.StatusSeeOther)
}

type oauthStatusResponse struct {
	Provider    Provider `json:"provider"`
	Status      string   `json:"status"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	PollAfterMS int64    `json:"poll_after_ms,omitempty"`
	AccountURL  string   `json:"account_url,omitempty"`
	SafeMessage string   `json:"message,omitempty"`
}

func (h *Handler) handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	selected, sessionID, ok := oauthPath(r)
	if !ok {
		h.writeOAuthError(w, http.StatusNotFound, "Connection flow not found.")
		return
	}
	flow, err := h.services.OAuth.Get(r.Context(), selected, sessionID)
	if err != nil {
		if isNotFound(err) {
			h.writeOAuthError(w, http.StatusNotFound, "Connection flow not found.")
		} else {
			h.writeOAuthError(w, http.StatusServiceUnavailable, "Connection status is temporarily unavailable.")
		}
		return
	}
	if flow.Provider != selected || flow.SessionID != sessionID {
		h.writeOAuthError(w, http.StatusNotFound, "Connection flow not found.")
		return
	}
	flow = h.prepareOAuthFlow(flow)
	response := oauthStatusResponse{
		Provider:    selected,
		Status:      flow.Status,
		PollAfterMS: flow.PollAfter.Milliseconds(),
		SafeMessage: flow.SanitizedMessage,
	}
	if selected == ProviderDevin && response.Status == "expired" {
		response.Status = "failed"
		if response.SafeMessage == "" {
			response.SafeMessage = "Devin authorization expired. Start a new connection."
		}
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
	selected, sessionID, ok := oauthPath(r)
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		return
	}
	if err := h.services.OAuth.Cancel(r.Context(), selected, sessionID); err != nil {
		h.renderMutationError(w, r, err, "The connection flow could not be cancelled.")
		return
	}
	h.redirect(w, r, "/admin/oauth/new?provider="+url.QueryEscape(string(selected))+"&notice=oauth-cancelled")
}

func (h *Handler) prepareOAuthFlow(flow OAuthFlow) OAuthFlow {
	flow.State = oauthManagementRef(flow.Provider, flow.SessionID)
	rawStatus := strings.ToLower(strings.TrimSpace(flow.Status))
	flow.Status = normalizedOAuthStatus(rawStatus)
	flow.SanitizedMessage = truncateText(strings.TrimSpace(flow.SanitizedMessage), 300)
	flow.UserCode = truncateText(strings.TrimSpace(flow.UserCode), 100)
	if (rawStatus == "" || rawStatus == "starting" || rawStatus == "pending" || rawStatus == "authorization_pending") && !flow.ExpiresAt.IsZero() && !h.now().Before(flow.ExpiresAt) {
		flow.Status = "expired"
		if flow.SanitizedMessage == "" {
			if flow.Provider == ProviderXAI {
				flow.SanitizedMessage = "The xAI device code expired. Start a new connection."
			} else {
				flow.SanitizedMessage = "Devin authorization expired. Start a new connection."
			}
		}
	}
	if flow.PollAfter < time.Second {
		flow.PollAfter = time.Second
	}
	if flow.PollAfter > 30*time.Second {
		flow.PollAfter = 30 * time.Second
	}
	flow.AuthorizationURL = safeAuthorizationURL(flow.AuthorizationURL)
	return flow
}

func normalizedOAuthStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "starting", "pending", "authorization_pending", "authorized", "consumed":
		return "pending"
	case "completed", "cancelled", "denied", "expired", "failed":
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return "failed"
	}
}

func parseOAuthProvider(value string, fallback Provider) (Provider, bool) {
	if value == "" {
		return fallback, fallback.Valid()
	}
	selected := Provider(value)
	return selected, selected.Valid()
}

func oauthPath(r *http.Request) (Provider, string, bool) {
	selected, ok := parseOAuthProvider(r.PathValue("provider"), "")
	if !ok {
		return "", "", false
	}
	sessionID, ok := resourceID(r.PathValue("session"))
	return selected, sessionID, ok
}

func oauthPageURL(provider Provider, sessionID string) string {
	return "/admin/oauth/new?provider=" + url.QueryEscape(string(provider)) + "&session_id=" + url.QueryEscape(sessionID)
}

func safeAuthorizationURL(value string) string {
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

func (h *Handler) renderOAuthLoadError(w http.ResponseWriter, r *http.Request, err error) {
	if isNotFound(err) {
		h.renderError(w, r, http.StatusNotFound, "Connection flow not found.")
		return
	}
	h.renderError(w, r, http.StatusServiceUnavailable, "The connection flow could not be loaded.")
}

func (h *Handler) writeOAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
