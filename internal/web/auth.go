package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gorilla/csrf"

	"supergrok-api/internal/store"
)

const (
	SessionCookieName = "supergrok_admin_session"
	CSRFCookieName    = "supergrok_admin_csrf"
	adminCookiePath   = "/admin"
	maxFormBytes      = 64 << 10
)

type SessionStore interface {
	Create(context.Context, time.Time, time.Time) (store.CreatedAdminSession, error)
	Get(context.Context, string, time.Time) (store.AdminSession, error)
	Revoke(context.Context, string, time.Time) error
}

// TrustedProxies is an allowlist of network peers permitted to assert that the
// original request used HTTPS. Forwarded headers from every other peer are
// ignored.
type TrustedProxies struct {
	prefixes []netip.Prefix
}

func ParseTrustedProxies(values []string) (TrustedProxies, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return TrustedProxies{}, errors.New("trusted proxy entry cannot be blank")
		}
		if address, err := netip.ParseAddr(value); err == nil {
			address = address.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return TrustedProxies{}, fmt.Errorf("invalid trusted proxy %q", value)
		}
		address := prefix.Addr().Unmap()
		bits := prefix.Bits()
		if address.Is4() && bits > 32 {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return TrustedProxies{}, fmt.Errorf("invalid trusted proxy %q", value)
		}
		prefixes = append(prefixes, netip.PrefixFrom(address, bits).Masked())
	}
	return TrustedProxies{prefixes: prefixes}, nil
}

func (p TrustedProxies) RequestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer, ok := remoteAddress(r.RemoteAddr)
	if !ok || !p.contains(peer) {
		return false
	}
	values := r.Header.Values("X-Forwarded-Proto")
	if len(values) == 0 {
		return false
	}
	parts := strings.Split(values[len(values)-1], ",")
	return strings.EqualFold(strings.TrimSpace(parts[len(parts)-1]), "https")
}

func (p TrustedProxies) contains(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range p.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func remoteAddress(value string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = strings.Trim(value, "[]")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

type authContextKey struct{}

type authState struct {
	token         string
	session       *store.AdminSession
	cookiePresent bool
	err           error
}

func (s authState) authenticated() bool { return s.session != nil && s.err == nil }

func authFromRequest(r *http.Request) authState {
	state, _ := r.Context().Value(authContextKey{}).(authState)
	return state
}

func (h *Handler) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := authState{}
		cookie, err := r.Cookie(SessionCookieName)
		switch {
		case errors.Is(err, http.ErrNoCookie):
		case err != nil:
			state.cookiePresent = true
		case cookie.Value == "":
			state.cookiePresent = true
		default:
			state.cookiePresent = true
			state.token = cookie.Value
			decoded, decodeErr := base64.RawURLEncoding.DecodeString(cookie.Value)
			if decodeErr == nil && len(decoded) == 32 {
				session, lookupErr := h.sessions.Get(r.Context(), cookie.Value, h.now())
				switch {
				case lookupErr == nil:
					state.session = &session
				case errors.Is(lookupErr, sql.ErrNoRows):
				default:
					state.err = lookupErr
				}
			}
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, state)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handler) withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := authFromRequest(r)
		key := h.loginCSRFKey
		if state.authenticated() {
			key = state.session.CSRFSecret
		}
		secure := h.trustedProxies.RequestIsHTTPS(r)
		request := r
		if !secure {
			request = csrf.PlaintextHTTPRequest(r)
		}
		protection := csrf.Protect(
			key[:],
			csrf.CookieName(CSRFCookieName),
			csrf.Path(adminCookiePath),
			csrf.HttpOnly(true),
			csrf.SameSite(csrf.SameSiteStrictMode),
			csrf.Secure(secure),
			csrf.MaxAge(int(h.sessionTTL/time.Second)),
			csrf.ErrorHandler(http.HandlerFunc(h.csrfFailure)),
		)
		protection(next).ServeHTTP(w, request)
	})
}

func (h *Handler) withFormLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) requireAuthentication(w http.ResponseWriter, r *http.Request) (authState, bool) {
	state := authFromRequest(r)
	if state.err != nil {
		h.renderError(w, r, http.StatusServiceUnavailable, "Administration is temporarily unavailable.")
		return authState{}, false
	}
	if state.authenticated() {
		return state, true
	}
	if state.cookiePresent {
		h.clearAuthCookies(w, r)
		h.redirect(w, r, "/admin/login?expired=1")
	} else {
		h.redirect(w, r, "/admin/login")
	}
	return authState{}, false
}

func passwordMatches(expected [32]byte, candidate string) bool {
	actual := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(expected[:], actual[:]) == 1
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, r *http.Request, created store.CreatedAdminSession) {
	maxAge := int(created.Session.ExpiresAt.Sub(h.now()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    created.Token,
		Path:     adminCookiePath,
		Expires:  created.Session.ExpiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.trustedProxies.RequestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	secure := h.trustedProxies.RequestIsHTTPS(r)
	for _, name := range []string{SessionCookieName, CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     adminCookiePath,
			Expires:  time.Unix(1, 0).UTC(),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

func (h *Handler) csrfFailure(w http.ResponseWriter, r *http.Request) {
	h.renderError(w, r, http.StatusForbidden, "The form expired or could not be verified. Reload the page and try again.")
}
