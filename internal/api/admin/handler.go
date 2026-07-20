package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"byos/internal/accounts"
	"byos/internal/models"
	"byos/internal/provider"
	"byos/internal/store"
	"byos/internal/usage"
)

const basePath = "/admin/api/v1"

type AccountManager interface {
	StartLogin(context.Context, provider.Kind) (provider.Authorization, error)
	LoginStatus(context.Context, provider.Kind, provider.SessionID) (provider.AuthorizationSession, error)
	CancelLogin(context.Context, provider.Kind, provider.SessionID) error
	List(context.Context) ([]store.Account, error)
	Update(context.Context, string, string, bool) error
	Delete(context.Context, string) error
	Refresh(context.Context, string) (store.Account, error)
}

type CompletionCoordinator interface {
	Resume(string)
	EnsureCompletion(string)
}

type UsageReader interface {
	Latest(context.Context, string) (usage.Snapshot, error)
}

type UsageRefresher interface {
	RefreshAccount(context.Context, usage.Account) error
	Status(string) usage.RefreshStatus
}

type ModelReader interface {
	Capabilities(context.Context, string) ([]models.Capability, error)
}

type ModelRefresher interface {
	RefreshAccount(context.Context, models.Account) error
	Status(string) models.RefreshStatus
}

type CooldownReader interface {
	Get(context.Context, string, string, time.Time) (store.Cooldown, error)
}

type APIKeyManager interface {
	List(context.Context) ([]store.APIKey, error)
	Create(context.Context, string) (accounts.CreatedAPIKey, error)
	Revoke(context.Context, string) error
}

// CallbackCompleter completes a callback-PKCE authorization using the raw
// OAuth state and authorization code supplied by the provider redirect. It is
// the sole unauthenticated completion seam and must never accept a SessionID.
type CallbackCompleter interface {
	CompleteLogin(context.Context, provider.Kind, provider.AuthorizationRef, provider.AuthorizationCompletion) (store.Account, error)
}

// ErrAuthorizationNotFound is the stable not-found sentinel returned by admin
// handlers when an authorization SessionID is unknown, belongs to the wrong
// provider, or is otherwise unresolvable. It wraps sql.ErrNoRows so existing
// errors.Is(err, sql.ErrNoRows) callers continue to map to 404, while letting
// the admin layer distinguish a safe not-found from a genuine internal error
// without sanitizing away the not-found classification.
var ErrAuthorizationNotFound = fmt.Errorf("authorization not found: %w", sql.ErrNoRows)

type Services struct {
	Accounts      AccountManager
	Completion    CompletionCoordinator
	Usage         UsageReader
	UsageRefresh  UsageRefresher
	Models        ModelReader
	ModelsRefresh ModelRefresher
	Cooldowns     CooldownReader
	APIKeys       APIKeyManager
	Capabilities  provider.CapabilityRegistry
}

type handler struct{ services Services }

func NewHandler(services Services) http.Handler {
	h := &handler{services: services}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+basePath+"/oauth/xai/device", h.startDevice)
	mux.HandleFunc("GET "+basePath+"/oauth/xai/device/{state}", h.pollDevice)
	mux.HandleFunc("DELETE "+basePath+"/oauth/xai/device/{state}", h.cancelDevice)
	mux.HandleFunc("POST "+basePath+"/oauth/devin/start", h.startDevin)
	mux.HandleFunc("GET "+basePath+"/oauth/devin/status/{session}", h.pollDevin)
	mux.HandleFunc("POST "+basePath+"/oauth/devin/cancel/{session}", h.cancelDevin)
	mux.HandleFunc("GET "+basePath+"/accounts", h.listAccounts)
	mux.HandleFunc("PATCH "+basePath+"/accounts/{id}", h.patchAccount)
	mux.HandleFunc("DELETE "+basePath+"/accounts/{id}", h.deleteAccount)
	mux.HandleFunc("POST "+basePath+"/accounts/{id}/refresh", h.refreshAccount)
	mux.HandleFunc("GET "+basePath+"/accounts/{id}/usage", h.accountUsage)
	mux.HandleFunc("POST "+basePath+"/accounts/{id}/usage/refresh", h.refreshUsage)
	mux.HandleFunc("GET "+basePath+"/usage", h.allUsage)
	mux.HandleFunc("GET "+basePath+"/models", h.allModels)
	mux.HandleFunc("POST "+basePath+"/models/refresh", h.refreshModels)
	mux.HandleFunc("GET "+basePath+"/api-keys", h.listAPIKeys)
	mux.HandleFunc("POST "+basePath+"/api-keys", h.createAPIKey)
	mux.HandleFunc("DELETE "+basePath+"/api-keys/{id}", h.revokeAPIKey)
	return mux
}

// CallbackHandler returns the exact GET callback handler for Devin's
// callback-PKCE flow. It is unauthenticated and must be registered outside
// AdminAuth at the configured callback path. The same handler is exported for
// CLI reuse.
func CallbackHandler(completer CallbackCompleter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDevinCallback(w, r, completer)
	})
}

func handleDevinCallback(w http.ResponseWriter, r *http.Request, completer CallbackCompleter) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is accepted")
		return
	}
	query := r.URL.Query()
	// Reject any provider-reported error by key presence, not by first-value
	// non-emptiness. An explicit empty `error=` or a repeated
	// `error=&error=denied` (query.Get returns "") must still be treated as an
	// error signal and never reach the exchange path.
	if errorValues, present := query["error"]; present {
		_ = errorValues
		writeError(w, http.StatusBadRequest, "callback_error", "authorization provider reported an error")
		return
	}
	if errorDescriptionValues, present := query["error_description"]; present {
		_ = errorDescriptionValues
		writeError(w, http.StatusBadRequest, "callback_error", "authorization provider reported an error")
		return
	}
	state := query["state"]
	code := query["code"]
	if len(state) != 1 || len(code) != 1 || state[0] == "" || code[0] == "" {
		writeError(w, http.StatusBadRequest, "invalid_callback", "exactly one state and code are required")
		return
	}
	if _, err := completer.CompleteLogin(r.Context(), provider.Devin, provider.AuthorizationRef{Provider: provider.Devin, State: state[0]}, provider.AuthorizationCompletion{Code: code[0]}); err != nil {
		writeError(w, http.StatusBadGateway, "callback_failed", "Devin authorization could not be completed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var body errorBody
	body.Error.Code = code
	body.Error.Message = message
	writeJSON(w, status, body)
}

func internalError(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "internal_error", "request failed")
}

func notFoundOrInternal(w http.ResponseWriter, err error, noun string) {
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", noun+" not found")
		return
	}
	internalError(w)
}

// writeOAuthCancelError classifies a cancel-login error into the exact HTTP
// semantics required by the OAuth lifecycle: a known-but-terminal session
// (consumed, completed, failed, already cancelled) maps to 409 Conflict with
// a sanitized authorizationView; a genuinely unknown or wrong-provider
// session maps to 404 Not Found; anything else maps to 500 Internal Server
// Error. useSessionID selects whether the view carries State (xAI device) or
// SessionID (Devin callback-PKCE). No unsanitized error text is ever echoed.
func writeOAuthCancelError(w http.ResponseWriter, err error, kind provider.Kind, handle, noun string, useSessionID bool) {
	view := authorizationView{Provider: string(kind), Status: "failed"}
	if useSessionID {
		view.SessionID = handle
	} else {
		view.State = handle
	}
	switch {
	case errors.Is(err, provider.ErrOAuthConflict):
		view.Error = noun + " is no longer cancellable"
		writeJSON(w, http.StatusConflict, view)
	case errors.Is(err, sql.ErrNoRows):
		view.Error = noun + " not found"
		writeJSON(w, http.StatusNotFound, view)
	default:
		view.Error = noun + " cancellation failed"
		writeJSON(w, http.StatusInternalServerError, view)
	}
}

func decodeJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

type authorizationView struct {
	Provider        string     `json:"provider"`
	State           string     `json:"state,omitempty"`
	SessionID       string     `json:"session_id,omitempty"`
	UserCode        string     `json:"user_code,omitempty"`
	VerificationURL string     `json:"verification_url,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Status          string     `json:"status"`
	AccountID       string     `json:"account_id,omitempty"`
	Error           string     `json:"error,omitempty"`
}

func (h *handler) startDevice(w http.ResponseWriter, r *http.Request) {
	if h.services.Accounts == nil {
		writeJSON(w, http.StatusInternalServerError, authorizationView{Provider: string(provider.XAI), Status: "failed", Error: "device authorization failed"})
		return
	}
	flow, err := h.services.Accounts.StartLogin(r.Context(), provider.XAI)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, authorizationView{Provider: string(provider.XAI), Status: "failed", Error: "device authorization failed"})
		return
	}
	verificationURL := flow.VerificationURLComplete
	if verificationURL == "" {
		verificationURL = flow.VerificationURL
	}
	if h.services.Completion != nil {
		h.services.Completion.Resume(flow.SessionID.String())
	}
	writeJSON(w, http.StatusCreated, authorizationView{Provider: string(provider.XAI), State: flow.SessionID.String(), Status: "pending", UserCode: flow.UserCode, VerificationURL: verificationURL, ExpiresAt: &flow.ExpiresAt})
}

func (h *handler) pollDevice(w http.ResponseWriter, r *http.Request) {
	if h.services.Accounts == nil {
		internalError(w)
		return
	}
	sessionID := r.PathValue("state")
	session, err := h.services.Accounts.LoginStatus(r.Context(), provider.XAI, provider.SessionID(sessionID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, authorizationView{State: sessionID, Status: "failed", Error: "device authorization not found"})
		} else {
			internalError(w)
		}
		return
	}
	if h.services.Completion != nil && (session.Status == provider.AuthorizationPending || session.Status == provider.AuthorizationAuthorized) {
		h.services.Completion.EnsureCompletion(sessionID)
	}
	view := authorizationView{Provider: string(provider.XAI), State: sessionID, Status: string(session.Status), AccountID: session.AccountID}
	switch session.Status {
	case provider.AuthorizationPending, provider.AuthorizationAuthorized:
		view.Status = "pending"
		view.UserCode = session.UserCode
		view.ExpiresAt = &session.ExpiresAt
		view.VerificationURL = session.VerificationURLComplete
		if view.VerificationURL == "" {
			view.VerificationURL = session.VerificationURL
		}
		writeJSON(w, http.StatusAccepted, view)
	case provider.AuthorizationCompleted:
		writeJSON(w, http.StatusOK, view)
	case provider.AuthorizationExpired:
		view.Error = "device authorization expired"
		writeJSON(w, http.StatusGone, view)
	case provider.AuthorizationCancelled:
		view.Error = "device authorization was cancelled"
		writeJSON(w, http.StatusConflict, view)
	case provider.AuthorizationFailed:
		view.Error = "device authorization failed"
		writeJSON(w, http.StatusConflict, view)
	default:
		internalError(w)
	}
}

func (h *handler) cancelDevice(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("state")
	if h.services.Accounts == nil {
		writeJSON(w, http.StatusInternalServerError, authorizationView{Provider: string(provider.XAI), State: sessionID, Status: "failed", Error: "device authorization cancellation failed"})
		return
	}
	if err := h.services.Accounts.CancelLogin(r.Context(), provider.XAI, provider.SessionID(sessionID)); err != nil {
		writeOAuthCancelError(w, err, provider.XAI, sessionID, "device authorization", false)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) startDevin(w http.ResponseWriter, r *http.Request) {
	if h.services.Accounts == nil {
		writeJSON(w, http.StatusInternalServerError, authorizationView{Provider: string(provider.Devin), Status: "failed", Error: "Devin authorization could not be started"})
		return
	}
	flow, err := h.services.Accounts.StartLogin(r.Context(), provider.Devin)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, authorizationView{Provider: string(provider.Devin), Status: "failed", Error: "Devin authorization could not be started"})
		return
	}
	writeJSON(w, http.StatusCreated, authorizationView{Provider: string(provider.Devin), SessionID: flow.SessionID.String(), Status: "pending", VerificationURL: flow.VerificationURL, ExpiresAt: &flow.ExpiresAt})
}

func (h *handler) pollDevin(w http.ResponseWriter, r *http.Request) {
	if h.services.Accounts == nil {
		internalError(w)
		return
	}
	sessionID := r.PathValue("session")
	session, err := h.services.Accounts.LoginStatus(r.Context(), provider.Devin, provider.SessionID(sessionID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, authorizationView{SessionID: sessionID, Status: "failed", Error: "Devin authorization not found"})
		} else {
			internalError(w)
		}
		return
	}
	view := authorizationView{Provider: string(provider.Devin), SessionID: sessionID, Status: string(session.Status), AccountID: session.AccountID}
	switch session.Status {
	case provider.AuthorizationPending, provider.AuthorizationConsumed:
		view.Status = "pending"
		view.ExpiresAt = &session.ExpiresAt
		writeJSON(w, http.StatusAccepted, view)
	case provider.AuthorizationCompleted:
		writeJSON(w, http.StatusOK, view)
	case provider.AuthorizationExpired:
		view.Error = "Devin authorization expired"
		writeJSON(w, http.StatusGone, view)
	case provider.AuthorizationCancelled:
		view.Error = "Devin authorization was cancelled"
		writeJSON(w, http.StatusConflict, view)
	case provider.AuthorizationFailed:
		view.Error = "Devin authorization failed"
		writeJSON(w, http.StatusConflict, view)
	default:
		internalError(w)
	}
}

func (h *handler) cancelDevin(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("session")
	if h.services.Accounts == nil {
		writeJSON(w, http.StatusInternalServerError, authorizationView{Provider: string(provider.Devin), SessionID: sessionID, Status: "failed", Error: "Devin authorization cancellation failed"})
		return
	}
	if err := h.services.Accounts.CancelLogin(r.Context(), provider.Devin, provider.SessionID(sessionID)); err != nil {
		writeOAuthCancelError(w, err, provider.Devin, sessionID, "Devin authorization", true)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

type refreshStatusView struct {
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	Refreshing  bool       `json:"refreshing"`
	Stale       bool       `json:"stale"`
}

type accountView struct {
	Provider              string            `json:"provider"`
	ID                    string            `json:"id"`
	Label                 string            `json:"label"`
	Enabled               bool              `json:"enabled"`
	Status                string            `json:"status"`
	ExpiresAt             *time.Time        `json:"expires_at,omitempty"`
	LastRefreshAt         *time.Time        `json:"last_refresh_at,omitempty"`
	CooldownUntil         *time.Time        `json:"cooldown_until,omitempty"`
	CapabilityFreshness   refreshStatusView `json:"capability_freshness"`
	UsageFreshness        refreshStatusView `json:"usage_freshness"`
	CanRefreshCredentials bool              `json:"can_refresh_credentials"`
	CanRelogin            bool              `json:"can_relogin"`
	CanRefreshUsage       bool              `json:"can_refresh_usage"`
	CanRefreshModels      bool              `json:"can_refresh_models"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

func timeIfSet(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func modelRefreshView(value models.RefreshStatus) refreshStatusView {
	return refreshStatusView{LastSuccess: timeIfSet(value.LastSuccess), LastAttempt: timeIfSet(value.LastAttempt), Refreshing: value.Refreshing, Stale: value.Stale}
}

func usageRefreshView(value usage.RefreshStatus) refreshStatusView {
	return refreshStatusView{LastSuccess: timeIfSet(value.LastSuccess), LastAttempt: timeIfSet(value.LastAttempt), Refreshing: value.Refreshing, Stale: value.Stale}
}

func (h *handler) cooldownUntil(ctx context.Context, accountID string) (*time.Time, error) {
	if h.services.Cooldowns == nil {
		return nil, nil
	}
	modelsToCheck := []string{"*"}
	if h.services.Models != nil {
		capabilities, err := h.services.Models.Capabilities(ctx, accountID)
		if err != nil {
			return nil, err
		}
		for _, capability := range capabilities {
			modelsToCheck = append(modelsToCheck, capability.ID)
		}
	}
	now := time.Now().UTC()
	var latest *time.Time
	for _, model := range modelsToCheck {
		state, err := h.services.Cooldowns.Get(ctx, accountID, model, now)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if state.Until != nil && (latest == nil || state.Until.After(*latest)) {
			value := *state.Until
			latest = &value
		}
	}
	return latest, nil
}

func (h *handler) projectAccount(ctx context.Context, account store.Account) (accountView, error) {
	cooldown, err := h.cooldownUntil(ctx, account.ID)
	if err != nil {
		return accountView{}, err
	}
	view := accountView{Provider: string(account.Provider), ID: account.ID, Label: account.Label, Enabled: account.Enabled, Status: account.Status, ExpiresAt: account.ExpiresAt, LastRefreshAt: account.LastRefreshAt, CooldownUntil: cooldown, CreatedAt: account.CreatedAt, UpdatedAt: account.UpdatedAt}
	capabilities := h.accountCapabilities(account)
	needsRelogin := account.Status == "relogin_required"
	view.CanRefreshCredentials = capabilities.CredentialRefresher != nil && !needsRelogin
	view.CanRelogin = capabilities.Lifecycle != nil
	view.CanRefreshUsage = capabilities.UsageFetcher != nil && capabilities.Credentials != nil
	view.CanRefreshModels = capabilities.ModelDiscoverer != nil && capabilities.Credentials != nil
	if h.services.ModelsRefresh != nil {
		view.CapabilityFreshness = modelRefreshView(h.services.ModelsRefresh.Status(account.ID))
	}
	if h.services.UsageRefresh != nil {
		view.UsageFreshness = usageRefreshView(h.services.UsageRefresh.Status(account.ID))
	}
	return view, nil
}

// accountCapabilities resolves the runtime capabilities registered for the
// account's provider. The policy key mirrors the runtime composition root,
// which keys provider capabilities by the provider kind string. A nil
// registry yields zero capabilities so capability booleans project as false
// without panicking.
func (h *handler) accountCapabilities(account store.Account) provider.Capabilities {
	if h.services.Capabilities == nil {
		return provider.Capabilities{}
	}
	capabilities, _ := h.services.Capabilities.Capabilities(account.Provider, string(account.Provider))
	return capabilities
}

func (h *handler) listAccounts(w http.ResponseWriter, r *http.Request) {
	accountsList, err := h.list(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	views := make([]accountView, 0, len(accountsList))
	for _, account := range accountsList {
		view, err := h.projectAccount(r.Context(), account)
		if err != nil {
			internalError(w)
			return
		}
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": views})
}

func (h *handler) list(ctx context.Context) ([]store.Account, error) {
	if h.services.Accounts == nil {
		return nil, errors.New("accounts service unavailable")
	}
	return h.services.Accounts.List(ctx)
}

func (h *handler) findAccount(ctx context.Context, id string) (store.Account, error) {
	values, err := h.list(ctx)
	if err != nil {
		return store.Account{}, err
	}
	for _, account := range values {
		if account.ID == id {
			return account, nil
		}
	}
	return store.Account{}, sql.ErrNoRows
}

type accountPatch struct {
	Label   *string `json:"label"`
	Enabled *bool   `json:"enabled"`
}

func (h *handler) patchAccount(w http.ResponseWriter, r *http.Request) {
	var patch accountPatch
	if err := decodeJSON(r, &patch); err != nil || (patch.Label == nil && patch.Enabled == nil) {
		writeError(w, http.StatusBadRequest, "invalid_request", "only label and enabled may be changed")
		return
	}
	account, err := h.findAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		notFoundOrInternal(w, err, "account")
		return
	}
	if patch.Label != nil {
		account.Label = strings.TrimSpace(*patch.Label)
	}
	if patch.Enabled != nil {
		account.Enabled = *patch.Enabled
	}
	if err := h.services.Accounts.Update(r.Context(), account.ID, account.Label, account.Enabled); err != nil {
		notFoundOrInternal(w, err, "account")
		return
	}
	account.UpdatedAt = time.Now().UTC()
	view, err := h.projectAccount(r.Context(), account)
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *handler) deleteAccount(w http.ResponseWriter, r *http.Request) {
	if h.services.Accounts == nil {
		internalError(w)
		return
	}
	if err := h.services.Accounts.Delete(r.Context(), r.PathValue("id")); err != nil {
		notFoundOrInternal(w, err, "account")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) refreshAccount(w http.ResponseWriter, r *http.Request) {
	if h.services.Accounts == nil {
		internalError(w)
		return
	}
	id := r.PathValue("id")
	account, err := h.findAccount(r.Context(), id)
	if err != nil {
		notFoundOrInternal(w, err, "account")
		return
	}
	capabilities := h.accountCapabilities(account)
	if capabilities.CredentialRefresher == nil {
		// Devin does not register a CredentialRefresher; credential refresh
		// is unavailable without a no-op. Reconnection is via OAuth start.
		writeError(w, http.StatusConflict, "action_unavailable", "credential refresh is not supported for this provider; reconnect via the authorization flow")
		return
	}
	if account.Status == "relogin_required" {
		writeError(w, http.StatusConflict, "relogin_required", "account requires reconnection via the authorization flow")
		return
	}
	account, err = h.services.Accounts.Refresh(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			notFoundOrInternal(w, err, "account")
		} else {
			writeError(w, http.StatusBadGateway, "refresh_failed", "account refresh failed")
		}
		return
	}
	view, err := h.projectAccount(r.Context(), account)
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type usageView struct {
	AccountID              string         `json:"account_id"`
	Provider               string         `json:"provider"`
	Monthly                *usage.Monthly `json:"monthly"`
	Weekly                 *usage.Weekly  `json:"weekly"`
	QuotaAvailable         bool           `json:"quota_available"`
	UpstreamUsageAvailable bool           `json:"upstream_usage_available"`
	Local                  usage.Counters `json:"local"`
	FetchedAt              time.Time      `json:"fetched_at"`
	Stale                  bool           `json:"stale"`
	Unknown                bool           `json:"unknown"`
	Error                  string         `json:"error,omitempty"`
}

// projectUsage projects a usage snapshot for an account owned by kind. xAI
// retains its upstream Monthly/Weekly quota when present; Devin never exposes
// upstream quota — Monthly/Weekly are forced nil even if a corrupt or legacy
// xAI-shaped snapshot was persisted, and quota availability is false. Local
// counters remain available for every provider. UpstreamUsageAvailable is true
// only when a real upstream quota window was reported; QuotaAvailable mirrors
// it for callers that reason in terms of remaining quota.
func projectUsage(kind provider.Kind, value usage.Snapshot) usageView {
	view := usageView{AccountID: value.AccountID, Provider: string(kind), Local: value.Local, FetchedAt: value.FetchedAt, Stale: value.Stale, Unknown: value.Unknown}
	if kind == provider.XAI {
		// xAI is the only provider with an upstream quota API. Even when a
		// snapshot has not yet been fetched (Monthly/Weekly nil), the provider
		// supports upstream quota, so QuotaAvailable is true. Devin never
		// exposes upstream quota — Monthly/Weekly are forced nil even if a
		// corrupt or legacy xAI-shaped snapshot was persisted.
		view.Monthly = value.Monthly
		view.Weekly = value.Weekly
		view.QuotaAvailable = true
		view.UpstreamUsageAvailable = value.Monthly != nil || value.Weekly != nil
	}
	if value.Error != "" {
		view.Error = "usage data may be stale"
	}
	return view
}

func (h *handler) accountUsage(w http.ResponseWriter, r *http.Request) {
	if h.services.Usage == nil {
		internalError(w)
		return
	}
	id := r.PathValue("id")
	account, err := h.findAccount(r.Context(), id)
	if err != nil {
		notFoundOrInternal(w, err, "account")
		return
	}
	value, err := h.services.Usage.Latest(r.Context(), id)
	if err != nil {
		notFoundOrInternal(w, err, "usage")
		return
	}
	writeJSON(w, http.StatusOK, projectUsage(account.Provider, value))
}

func (h *handler) refreshUsage(w http.ResponseWriter, r *http.Request) {
	if h.services.UsageRefresh == nil || h.services.Usage == nil {
		internalError(w)
		return
	}
	id := r.PathValue("id")
	account, err := h.findAccount(r.Context(), id)
	if err != nil {
		notFoundOrInternal(w, err, "account")
		return
	}
	capabilities := h.accountCapabilities(account)
	if capabilities.UsageFetcher == nil || capabilities.Credentials == nil {
		// Devin does not expose an upstream usage API; return a stable
		// action-unavailable response rather than a fake success/no-op.
		writeError(w, http.StatusConflict, "action_unavailable", "usage refresh is not supported for this provider")
		return
	}
	refreshErr := h.services.UsageRefresh.RefreshAccount(r.Context(), usage.Account{ID: account.ID, Provider: account.Provider, Enabled: account.Enabled})
	value, latestErr := h.services.Usage.Latest(r.Context(), id)
	if latestErr != nil {
		notFoundOrInternal(w, latestErr, "usage")
		return
	}
	if refreshErr != nil {
		value.Stale = true
		value.Error = "refresh failed"
	}
	writeJSON(w, http.StatusOK, projectUsage(account.Provider, value))
}

func (h *handler) allUsage(w http.ResponseWriter, r *http.Request) {
	if h.services.Usage == nil {
		internalError(w)
		return
	}
	accountsList, err := h.list(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	views := make([]usageView, 0, len(accountsList))
	for _, account := range accountsList {
		value, err := h.services.Usage.Latest(r.Context(), account.ID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			internalError(w)
			return
		}
		views = append(views, projectUsage(account.Provider, value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"usage": views})
}

type modelView struct {
	AccountID             string    `json:"account_id"`
	Provider              string    `json:"provider"`
	ID                    string    `json:"id"`
	DisplayName           string    `json:"display_name,omitempty"`
	Supported             bool      `json:"supported"`
	SupportsBackendSearch *bool     `json:"supports_backend_search,omitempty"`
	ContextWindow         int64     `json:"context_window,omitempty"`
	MaxOutputTokens       int64     `json:"max_output_tokens,omitempty"`
	ReasoningEfforts      []string  `json:"reasoning_efforts"`
	DiscoveredAt          time.Time `json:"discovered_at"`
	Stale                 bool      `json:"stale"`
}

func projectModel(accountID string, kind provider.Kind, value models.Capability) modelView {
	efforts := value.ReasoningEfforts
	if efforts == nil {
		efforts = []string{}
	}
	return modelView{AccountID: accountID, Provider: string(kind), ID: value.ID, DisplayName: value.DisplayName, Supported: true, SupportsBackendSearch: value.SupportsBackendSearch, ContextWindow: value.ContextWindow, MaxOutputTokens: value.MaxOutputTokens, ReasoningEfforts: efforts, DiscoveredAt: value.DiscoveredAt, Stale: value.Stale}
}

func (h *handler) modelViews(ctx context.Context, accountsList []store.Account) ([]modelView, error) {
	views := make([]modelView, 0)
	for _, account := range accountsList {
		values, err := h.services.Models.Capabilities(ctx, account.ID)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			views = append(views, projectModel(account.ID, account.Provider, value))
		}
	}
	return views, nil
}

func (h *handler) allModels(w http.ResponseWriter, r *http.Request) {
	if h.services.Models == nil {
		internalError(w)
		return
	}
	accountsList, err := h.list(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	views, err := h.modelViews(r.Context(), accountsList)
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": views})
}

func (h *handler) refreshModels(w http.ResponseWriter, r *http.Request) {
	if h.services.ModelsRefresh == nil || h.services.Models == nil {
		internalError(w)
		return
	}
	accountsList, err := h.list(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	failed := false
	for _, account := range accountsList {
		// Global model refresh handles only providers with a registered
		// ModelDiscoverer; providers without discovery (e.g. Devin) are
		// skipped rather than treated as refresh failures.
		if !account.Enabled {
			continue
		}
		capabilities := h.accountCapabilities(account)
		if capabilities.ModelDiscoverer == nil || capabilities.Credentials == nil {
			continue
		}
		if h.services.ModelsRefresh.RefreshAccount(r.Context(), models.Account{ID: account.ID, Provider: account.Provider, Enabled: true}) != nil {
			failed = true
		}
	}
	views, listErr := h.modelViews(r.Context(), accountsList)
	if listErr != nil {
		internalError(w)
		return
	}
	response := map[string]any{"models": views}
	if failed {
		response["refresh_error"] = "one or more model refreshes failed; stale data may be shown"
	}
	writeJSON(w, http.StatusOK, response)
}

type apiKeyView struct {
	ID         string     `json:"id"`
	Prefix     string     `json:"prefix"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func projectAPIKey(value store.APIKey) apiKeyView {
	return apiKeyView{ID: value.ID, Prefix: value.Prefix, Label: value.Label, CreatedAt: value.CreatedAt, LastUsedAt: value.LastUsedAt, RevokedAt: value.RevokedAt}
}

func (h *handler) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if h.services.APIKeys == nil {
		internalError(w)
		return
	}
	values, err := h.services.APIKeys.List(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	views := make([]apiKeyView, 0, len(values))
	for _, value := range values {
		views = append(views, projectAPIKey(value))
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": views})
}

func (h *handler) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if h.services.APIKeys == nil {
		internalError(w)
		return
	}
	var request struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(r, &request); err != nil || strings.TrimSpace(request.Label) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "label is required")
		return
	}
	created, err := h.services.APIKeys.Create(r.Context(), strings.TrimSpace(request.Label))
	if err != nil {
		internalError(w)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"api_key": projectAPIKey(created.Key), "plaintext": created.Plaintext})
}

func (h *handler) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if h.services.APIKeys == nil {
		internalError(w)
		return
	}
	if err := h.services.APIKeys.Revoke(r.Context(), r.PathValue("id")); err != nil {
		notFoundOrInternal(w, err, "api key")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
