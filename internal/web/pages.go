package web

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"byoo/internal/auththrottle"
)

func (h *Handler) handleAdminRedirect(w http.ResponseWriter, r *http.Request) {
	h.redirect(w, r, "/admin/")
}

type loginPage struct {
	layoutData
	Error         string
	ExpiredNotice string
}

func (h *Handler) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	state := authFromRequest(r)
	if state.err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "Administration is temporarily unavailable.")
		return
	}
	if state.authenticated() {
		h.redirect(w, r, "/admin/")
		return
	}
	data := loginPage{layoutData: h.layout(r, "Sign in", "")}
	if r.URL.Query().Get("expired") == "1" {
		data.ExpiredNotice = "Your session ended. Sign in again to continue."
	}
	h.render(w, "login", http.StatusOK, data)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := authFromRequest(r)
	if state.err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "Administration is temporarily unavailable.")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "The sign-in form could not be read.")
		return
	}
	password := r.PostForm.Get("password")
	if state.authenticated() {
		if passwordMatches(h.passwordHash, password) {
			h.completeLogin(w, r, state)
			return
		}
		source, err := h.trustedProxies.ClientIP(r)
		if err != nil {
			h.renderError(w, r, http.StatusServiceUnavailable, "Administration is temporarily unavailable.")
			return
		}
		outcome, err := h.loginAttempts.RecordFailure(r.Context(), source, auththrottle.SurfaceWebPassword)
		if err != nil {
			h.renderError(w, r, http.StatusServiceUnavailable, "Administration is temporarily unavailable.")
			return
		}
		if outcome.Disposition == auththrottle.Blocked {
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds(outcome.RetryAfter), 10))
			h.renderError(w, r, http.StatusTooManyRequests, "Too many authentication attempts. Try again later.")
			return
		}
		h.renderLoginRejected(w, r)
		return
	}
	source, err := h.trustedProxies.ClientIP(r)
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "Administration is temporarily unavailable.")
		return
	}
	outcome, err := h.loginAttempts.Evaluate(r.Context(), source, auththrottle.SurfaceWebPassword, func() bool {
		return passwordMatches(h.passwordHash, password)
	})
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "Administration is temporarily unavailable.")
		return
	}
	switch outcome.Disposition {
	case auththrottle.Blocked:
		w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds(outcome.RetryAfter), 10))
		h.renderError(w, r, http.StatusTooManyRequests, "Too many authentication attempts. Try again later.")
	case auththrottle.Rejected:
		h.renderLoginRejected(w, r)
	case auththrottle.Authenticated:
		h.completeLogin(w, r, state)
	default:
		h.renderError(w, r, http.StatusServiceUnavailable, "Administration is temporarily unavailable.")
	}
}

func (h *Handler) renderLoginRejected(w http.ResponseWriter, r *http.Request) {
	data := loginPage{layoutData: h.layout(r, "Sign in", ""), Error: "The administrator password was not accepted."}
	h.render(w, "login", http.StatusUnauthorized, data)
}

func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, state authState) {
	now := h.now()
	created, err := h.sessions.Create(r.Context(), now, now.Add(h.sessionTTL))
	if err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "A secure session could not be created. Try again.")
		return
	}
	if state.authenticated() {
		if err := h.sessions.Revoke(r.Context(), state.token, now); err != nil && !errors.Is(err, sql.ErrNoRows) {
			_ = h.sessions.Revoke(r.Context(), created.Token, now)
			h.renderError(w, r, http.StatusServiceUnavailable, "A secure session could not be created. Try again.")
			return
		}
	}
	h.clearAuthCookies(w, r)
	h.setSessionCookie(w, r, created)
	h.redirect(w, r, "/admin/")
}

func retryAfterSeconds(value time.Duration) int64 {
	seconds := int64((value + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	state, ok := h.requireAuthentication(w, r)
	if !ok {
		return
	}
	if err := h.sessions.Revoke(r.Context(), state.token, h.now()); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.renderError(w, r, http.StatusServiceUnavailable, "The session could not be closed. Try again.")
		return
	}
	h.clearAuthCookies(w, r)
	h.redirect(w, r, "/admin/login")
}

type dashboardPage struct {
	layoutData
	Ready         bool
	AccountCount  int
	ReadyAccounts int
	ActiveKeys    int
	CheckedAt     time.Time
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	accounts, accountErr := h.services.Accounts.List(r.Context())
	keys, keyErr := h.services.APIKeys.List(r.Context())
	ready, readyErr := h.services.Readiness.Ready(r.Context())
	data := dashboardPage{layoutData: h.layout(r, "Dashboard", "dashboard"), AccountCount: len(accounts), CheckedAt: h.now()}
	for _, account := range accounts {
		if account.Enabled && strings.EqualFold(account.Status, "ready") {
			data.ReadyAccounts++
		}
	}
	for _, key := range keys {
		if key.RevokedAt == nil {
			data.ActiveKeys++
		}
	}
	data.Ready = ready
	status := http.StatusOK
	if accountErr != nil || keyErr != nil || readyErr != nil {
		data.LoadError = "Some dashboard status could not be loaded."
		status = http.StatusServiceUnavailable
	}
	h.render(w, "dashboard", status, data)
}

type accountsPage struct {
	layoutData
	Accounts []AccountSummary
}

func (h *Handler) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	accounts, err := h.services.Accounts.List(r.Context())
	data := accountsPage{layoutData: h.layout(r, "Accounts", "accounts"), Accounts: accounts}
	status := http.StatusOK
	if err != nil {
		data.LoadError = "Accounts could not be loaded."
		status = http.StatusServiceUnavailable
	}
	h.render(w, "accounts", status, data)
}

type accountPage struct {
	layoutData
	Account     AccountDetail
	ActionError string
}

func (h *Handler) handleAccount(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	h.renderAccount(w, r, id, http.StatusOK, "")
}

func (h *Handler) renderAccount(w http.ResponseWriter, r *http.Request, id string, status int, actionError string) {
	account, err := h.services.Accounts.Get(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			h.renderError(w, r, http.StatusNotFound, "Account not found.")
		} else {
			h.renderError(w, r, http.StatusServiceUnavailable, "The account could not be loaded.")
		}
		return
	}
	data := accountPage{layoutData: h.layout(r, displayLabel(account.Label), "accounts"), Account: account, ActionError: actionError}
	h.render(w, "account", status, data)
}

func (h *Handler) handleAccountLabel(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderAccount(w, r, id, http.StatusBadRequest, "The label form could not be read.")
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if label == "" || utf8.RuneCountInString(label) > 100 {
		h.renderAccount(w, r, id, http.StatusBadRequest, "Enter a label between 1 and 100 characters.")
		return
	}
	if err := h.services.Accounts.Update(r.Context(), id, AccountUpdate{Label: &label}); err != nil {
		h.renderMutationError(w, r, err, "Account settings could not be updated.")
		return
	}
	h.redirect(w, r, accountURL(id)+"?notice=account-updated")
}

func (h *Handler) handleAccountEnabled(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderAccount(w, r, id, http.StatusBadRequest, "The account form could not be read.")
		return
	}
	var enabled bool
	switch r.PostForm.Get("enabled") {
	case "true":
		enabled = true
	case "false":
		enabled = false
	default:
		h.renderAccount(w, r, id, http.StatusBadRequest, "Choose whether the account is enabled.")
		return
	}
	if err := h.services.Accounts.Update(r.Context(), id, AccountUpdate{Enabled: &enabled}); err != nil {
		h.renderMutationError(w, r, err, "Account settings could not be updated.")
		return
	}
	h.redirect(w, r, accountURL(id)+"?notice=account-updated")
}

func (h *Handler) handleAccountRefresh(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := h.services.Accounts.Refresh(r.Context(), id); err != nil {
		h.renderMutationError(w, r, err, "The account refresh could not be started.")
		return
	}
	h.redirect(w, r, accountURL(id)+"?notice=account-refreshed")
}

func (h *Handler) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("confirm") != "delete" {
		h.renderAccount(w, r, id, http.StatusBadRequest, "Confirm account deletion before continuing.")
		return
	}
	if err := h.services.Accounts.Delete(r.Context(), id); err != nil {
		h.renderMutationError(w, r, err, "The account could not be deleted.")
		return
	}
	h.redirect(w, r, "/admin/accounts?notice=account-deleted")
}

type usagePage struct {
	layoutData
	Usage []AccountUsage
}

func (h *Handler) handleUsage(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	usage, err := h.services.Usage.List(r.Context())
	data := usagePage{layoutData: h.layout(r, "Usage", "usage"), Usage: usage}
	status := http.StatusOK
	if err != nil {
		data.LoadError = "Usage could not be loaded."
		status = http.StatusServiceUnavailable
	}
	h.render(w, "usage", status, data)
}

func (h *Handler) handleUsageRefresh(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := h.services.Usage.Refresh(r.Context(), id); err != nil {
		h.renderMutationError(w, r, err, "Usage refresh could not be started.")
		return
	}
	h.redirect(w, r, "/admin/usage?notice=usage-refreshed")
}

type modelsPage struct {
	layoutData
	Models []ModelSupport
}

func (h *Handler) handleModels(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	models, err := h.services.Models.List(r.Context())
	data := modelsPage{layoutData: h.layout(r, "Models", "models"), Models: models}
	status := http.StatusOK
	if err != nil {
		data.LoadError = "Model support could not be loaded."
		status = http.StatusServiceUnavailable
	}
	h.render(w, "models", status, data)
}

func (h *Handler) handleModelsRefresh(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := h.services.Models.Refresh(r.Context(), id); err != nil {
		h.renderMutationError(w, r, err, "Model discovery refresh could not be started.")
		return
	}
	h.redirect(w, r, "/admin/models?notice=models-refreshed")
}

type apiKeysPage struct {
	layoutData
	Keys             []APIKey
	CreatedPlaintext string
	FormError        string
}

func (h *Handler) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	h.renderAPIKeys(w, r, http.StatusOK, "", "")
}

func (h *Handler) handleAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderAPIKeys(w, r, http.StatusBadRequest, "", "The key form could not be read.")
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if label == "" || utf8.RuneCountInString(label) > 100 {
		h.renderAPIKeys(w, r, http.StatusBadRequest, "", "Enter a label between 1 and 100 characters.")
		return
	}
	created, err := h.services.APIKeys.Create(r.Context(), label)
	if err != nil || created.Plaintext == "" {
		h.renderAPIKeys(w, r, http.StatusServiceUnavailable, "", "The API key could not be created.")
		return
	}
	h.renderAPIKeys(w, r, http.StatusCreated, created.Plaintext, "")
}

func (h *Handler) renderAPIKeys(w http.ResponseWriter, r *http.Request, status int, plaintext, formError string) {
	keys, err := h.services.APIKeys.List(r.Context())
	data := apiKeysPage{layoutData: h.layout(r, "API keys", "api-keys"), Keys: keys, CreatedPlaintext: plaintext, FormError: formError}
	if err != nil {
		data.LoadError = "Existing API keys could not be loaded."
		if plaintext == "" {
			status = http.StatusServiceUnavailable
		}
	}
	h.render(w, "api_keys", status, data)
}

func (h *Handler) handleAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "API key not found.")
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("confirm") != "revoke" {
		h.renderError(w, r, http.StatusBadRequest, "Confirm API key revocation before continuing.")
		return
	}
	if err := h.services.APIKeys.Revoke(r.Context(), id); err != nil {
		h.renderMutationError(w, r, err, "The API key could not be revoked.")
		return
	}
	h.redirect(w, r, "/admin/api-keys?notice=key-revoked")
}

func (h *Handler) renderMutationError(w http.ResponseWriter, r *http.Request, err error, message string) {
	if isNotFound(err) {
		h.renderError(w, r, http.StatusNotFound, "The requested item was not found.")
		return
	}
	h.renderError(w, r, http.StatusServiceUnavailable, message)
}

func isNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows)
}

func resourceID(value string) (string, bool) {
	if value == "" || len(value) > 256 {
		return "", false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return "", false
	}
	return value, true
}
