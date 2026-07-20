package web

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/csrf"

	"byos/internal/requestsource"
)

const defaultSessionTTL = 12 * time.Hour

type Options struct {
	AdminPassword string
	SessionStore  SessionStore
	LoginAttempts LoginAttemptPolicy
	CSRFKey       [32]byte
	Services      Services
	SessionTTL    time.Duration
	TrustedProxy  requestsource.TrustedProxies
	Now           func() time.Time
}

// Handler owns the server-rendered administration routes and their scoped
// authentication, CSRF, cookie, and security-header middleware.
type Handler struct {
	sessions       SessionStore
	loginAttempts  LoginAttemptPolicy
	services       Services
	sessionTTL     time.Duration
	trustedProxies requestsource.TrustedProxies
	now            func() time.Time
	passwordHash   [32]byte
	loginCSRFKey   [32]byte
	templates      map[string]*template.Template
	routes         http.Handler
}

func NewHandler(options Options) (*Handler, error) {
	if strings.TrimSpace(options.AdminPassword) == "" {
		return nil, errors.New("administrator password is required")
	}
	if options.SessionStore == nil {
		return nil, errors.New("admin session store is required")
	}
	if options.LoginAttempts == nil {
		return nil, errors.New("administrator login attempt policy is required")
	}
	if options.Services.Accounts == nil || options.Services.OAuth == nil || options.Services.Usage == nil || options.Services.Models == nil || options.Services.APIKeys == nil || options.Services.Readiness == nil {
		return nil, errors.New("all Web UI services are required")
	}
	var zeroKey [32]byte
	if options.CSRFKey == zeroKey {
		return nil, errors.New("Web UI CSRF key is required")
	}
	if options.SessionTTL == 0 {
		options.SessionTTL = defaultSessionTTL
	}
	if options.SessionTTL < time.Second {
		return nil, errors.New("admin session TTL must be at least one second")
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	templates, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	loginKeyMaterial := append([]byte("byos/login-csrf/v1\x00"), options.CSRFKey[:]...)
	handler := &Handler{
		sessions:       options.SessionStore,
		loginAttempts:  options.LoginAttempts,
		services:       options.Services,
		sessionTTL:     options.SessionTTL,
		trustedProxies: options.TrustedProxy,
		now:            options.Now,
		passwordHash:   sha256.Sum256([]byte(options.AdminPassword)),
		loginCSRFKey:   sha256.Sum256(loginKeyMaterial),
		templates:      templates,
	}
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	handler.routes = mux
	return handler, nil
}

// RegisterRoutes installs every Web UI route on a caller-owned ServeMux. The
// method is intended for the main API server's later integration.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /admin", h.page(http.HandlerFunc(h.handleAdminRedirect)))
	mux.Handle("GET /admin/login", h.page(http.HandlerFunc(h.handleLoginPage)))
	mux.Handle("POST /admin/login", h.page(http.HandlerFunc(h.handleLogin)))
	mux.Handle("POST /admin/logout", h.page(http.HandlerFunc(h.handleLogout)))
	mux.Handle("GET /admin/", h.page(http.HandlerFunc(h.handleDashboard)))
	mux.Handle("GET /admin/accounts", h.page(http.HandlerFunc(h.handleAccounts)))
	mux.Handle("GET /admin/accounts/{id}", h.page(http.HandlerFunc(h.handleAccount)))
	mux.Handle("POST /admin/accounts/{id}/label", h.page(http.HandlerFunc(h.handleAccountLabel)))
	mux.Handle("POST /admin/accounts/{id}/enabled", h.page(http.HandlerFunc(h.handleAccountEnabled)))
	mux.Handle("POST /admin/accounts/{id}/refresh", h.page(http.HandlerFunc(h.handleAccountRefresh)))
	mux.Handle("POST /admin/accounts/{id}/delete", h.page(http.HandlerFunc(h.handleAccountDelete)))
	mux.Handle("GET /admin/oauth/new", h.page(http.HandlerFunc(h.handleOAuthPage)))
	mux.Handle("POST /admin/oauth/new", h.page(http.HandlerFunc(h.handleOAuthStart)))
	mux.Handle("GET /admin/oauth/{provider}/authorize/{session}", h.page(http.HandlerFunc(h.handleOAuthAuthorize)))
	mux.Handle("GET /admin/oauth/{provider}/status/{session}", h.page(http.HandlerFunc(h.handleOAuthStatus)))
	mux.Handle("POST /admin/oauth/{provider}/cancel/{session}", h.page(http.HandlerFunc(h.handleOAuthCancel)))
	mux.Handle("GET /admin/usage", h.page(http.HandlerFunc(h.handleUsage)))
	mux.Handle("POST /admin/usage/{id}/refresh", h.page(http.HandlerFunc(h.handleUsageRefresh)))
	mux.Handle("GET /admin/models", h.page(http.HandlerFunc(h.handleModels)))
	mux.Handle("POST /admin/models/{id}/refresh", h.page(http.HandlerFunc(h.handleModelsRefresh)))
	mux.Handle("GET /admin/api-keys", h.page(http.HandlerFunc(h.handleAPIKeys)))
	mux.Handle("POST /admin/api-keys", h.page(http.HandlerFunc(h.handleAPIKeyCreate)))
	mux.Handle("POST /admin/api-keys/{id}/revoke", h.page(http.HandlerFunc(h.handleAPIKeyRevoke)))
	mux.Handle("GET /admin/static/{file}", h.securityHeaders(http.HandlerFunc(h.handleStatic)))
}

// Routes returns a standalone handler with the same explicit route inventory
// used by RegisterRoutes.
func (h *Handler) Routes() http.Handler { return h.routes }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.routes.ServeHTTP(w, r)
}

func (h *Handler) page(next http.Handler) http.Handler {
	return h.securityHeaders(h.withFormLimit(h.withSession(h.withCSRF(next))))
}

func (h *Handler) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()
		headers.Set("Cache-Control", "no-store")
		headers.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'")
		headers.Set("Cross-Origin-Opener-Policy", "same-origin")
		headers.Set("Cross-Origin-Resource-Policy", "same-origin")
		headers.Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		headers.Set("Referrer-Policy", "same-origin")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		if h.trustedProxies.RequestIsHTTPS(r) {
			headers.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

type layoutData struct {
	Title         string
	Active        string
	Authenticated bool
	CSRFField     template.HTML
	Notice        string
	LoadError     string
}

func (h *Handler) layout(r *http.Request, title, active string) layoutData {
	return layoutData{
		Title:         title,
		Active:        active,
		Authenticated: authFromRequest(r).authenticated(),
		CSRFField:     csrf.TemplateField(r),
		Notice:        noticeMessage(r.URL.Query().Get("notice")),
	}
}

func noticeMessage(code string) string {
	switch code {
	case "account-updated":
		return "Account settings updated."
	case "account-refreshed":
		return "Account refresh started."
	case "account-deleted":
		return "Account deleted."
	case "oauth-cancelled":
		return "Connection flow cancelled."
	case "usage-refreshed":
		return "Usage refresh started."
	case "models-refreshed":
		return "Model discovery refresh started."
	case "key-revoked":
		return "API key revoked."
	default:
		return ""
	}
}

func (h *Handler) render(w http.ResponseWriter, name string, status int, data any) {
	tmpl, ok := h.templates[name]
	if !ok {
		http.Error(w, "Administration page unavailable", http.StatusInternalServerError)
		return
	}
	var output bytes.Buffer
	if err := tmpl.ExecuteTemplate(&output, "layout", data); err != nil {
		http.Error(w, "Administration page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(output.Bytes())
}

func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, status int, message string) {
	data := errorPage{layoutData: h.layout(r, http.StatusText(status), ""), Status: status, Message: message}
	h.render(w, "error", status, data)
}

func (h *Handler) redirect(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func parseTemplates() (map[string]*template.Template, error) {
	functions := template.FuncMap{
		"accountURL":        accountURL,
		"accountLabelURL":   func(id string) string { return resourceURL("/admin/accounts/", id, "/label") },
		"accountEnabledURL": func(id string) string { return resourceURL("/admin/accounts/", id, "/enabled") },
		"accountRefreshURL": func(id string) string { return resourceURL("/admin/accounts/", id, "/refresh") },
		"accountDeleteURL":  func(id string) string { return resourceURL("/admin/accounts/", id, "/delete") },
		"oauthNewURL":       oauthNewURL,
		"oauthAuthorizeURL": oauthAuthorizeURL,
		"oauthStatusURL":    oauthStatusURL,
		"oauthCancelURL":    oauthCancelURL,
		"usageRefreshURL":   func(id string) string { return resourceURL("/admin/usage/", id, "/refresh") },
		"modelRefreshURL":   func(id string) string { return resourceURL("/admin/models/", id, "/refresh") },
		"keyRevokeURL":      func(id string) string { return resourceURL("/admin/api-keys/", id, "/revoke") },
		"formatTime":        formatTime,
		"timeAttr":          func(value time.Time) string { return value.UTC().Format(time.RFC3339) },
		"formatCount":       func(value uint64) string { return strconv.FormatUint(value, 10) },
		"formatInt":         func(value int64) string { return strconv.FormatInt(value, 10) },
		"formatFloat":       formatFloat,
		"percentValue":      percentValue,
		"durationMS":        func(value time.Duration) int64 { return value.Milliseconds() },
		"searchSupport":     searchSupport,
		"join":              func(values []string) string { return strings.Join(values, ", ") },
		"displayLabel":      displayLabel,
		"providerLabel":     providerLabel,
		"providerSelected":  func(value Provider, expected string) bool { return string(value) == expected },
		"isXAI":             func(value Provider) bool { return value == ProviderXAI },
	}
	pages := []string{"login", "dashboard", "accounts", "account", "oauth", "usage", "models", "api_keys", "error"}
	parsed := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		tmpl, err := template.New("layout.html").Funcs(functions).ParseFS(assets, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, fmt.Errorf("parse Web UI template %s: %w", page, err)
		}
		parsed[page] = tmpl
	}
	return parsed, nil
}

func resourceURL(prefix, id, suffix string) string {
	return prefix + url.PathEscape(id) + suffix
}

func accountURL(id string) string { return resourceURL("/admin/accounts/", id, "") }

func oauthNewURL(provider Provider) string {
	if !provider.Valid() {
		return "/admin/oauth/new"
	}
	return "/admin/oauth/new?provider=" + url.QueryEscape(string(provider))
}

func oauthAuthorizeURL(provider Provider, sessionID string) string {
	return resourceURL("/admin/oauth/"+url.PathEscape(string(provider))+"/authorize/", sessionID, "")
}

func oauthStatusURL(ref string) string {
	provider, sessionID, ok := oauthManagementParts(ref)
	if !ok {
		return ""
	}
	return resourceURL("/admin/oauth/"+url.PathEscape(string(provider))+"/status/", sessionID, "")
}

func oauthCancelURL(ref string) string {
	provider, sessionID, ok := oauthManagementParts(ref)
	if !ok {
		return ""
	}
	return resourceURL("/admin/oauth/"+url.PathEscape(string(provider))+"/cancel/", sessionID, "")
}

func oauthManagementRef(provider Provider, sessionID string) string {
	return string(provider) + "/" + sessionID
}

func oauthManagementParts(ref string) (Provider, string, bool) {
	providerValue, sessionID, found := strings.Cut(ref, "/")
	provider := Provider(providerValue)
	if !found || !provider.Valid() {
		return "", "", false
	}
	validated, ok := resourceID(sessionID)
	return provider, validated, ok
}

func formatTime(value any) string {
	var instant time.Time
	switch typed := value.(type) {
	case time.Time:
		instant = typed
	case *time.Time:
		if typed == nil {
			return "Not available"
		}
		instant = *typed
	default:
		return "Not available"
	}
	if instant.IsZero() {
		return "Not available"
	}
	return instant.UTC().Format("2006-01-02 15:04 UTC")
}

func formatFloat(value any) string {
	var number float64
	switch typed := value.(type) {
	case float64:
		number = typed
	case *float64:
		if typed == nil {
			return "Not available"
		}
		number = *typed
	default:
		return "Not available"
	}
	return strconv.FormatFloat(number, 'f', 1, 64)
}

func percentValue(value *float64) float64 {
	if value == nil {
		return 0
	}
	if *value < 0 {
		return 0
	}
	if *value > 100 {
		return 100
	}
	return *value
}

func searchSupport(value *bool) string {
	if value == nil {
		return "Unknown"
	}
	if *value {
		return "Supported"
	}
	return "Unavailable"
}

func displayLabel(label string) string {
	if strings.TrimSpace(label) == "" {
		return "Unlabeled account"
	}
	return label
}

func providerLabel(value Provider) string {
	switch value {
	case ProviderXAI:
		return "xAI"
	case ProviderDevin:
		return "Devin"
	default:
		return "Unknown provider"
	}
}

type errorPage struct {
	layoutData
	Status  int
	Message string
}
