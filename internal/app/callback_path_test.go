package app

import (
	"testing"
)

func TestValidateCallbackPathAllowsDefaultAdminCallback(t *testing.T) {
	// The default Devin callback path lives under /admin/api/v1/ and must be
	// allowed: the outer exact dispatcher secures it, and AdminAuth protects
	// every neighboring admin route.
	if err := validateCallbackPath("/admin/api/v1/oauth/devin/callback"); err != nil {
		t.Fatalf("default callback path rejected: %v", err)
	}
}

func TestValidateCallbackPathRejectsReservedSubtrees(t *testing.T) {
	for _, path := range []string{
		"/healthz",
		"/readyz",
		"/v1/models",
		"/v1/chat/completions",
		"/v1/responses",
		"/v1/messages",
		"/v1/messages/count_tokens",
		"/admin/",
		"/v1/custom",
		"/healthz/sub",
	} {
		if err := validateCallbackPath(path); err == nil {
			t.Fatalf("reserved path %q should be rejected", path)
		}
	}
}

func TestValidateCallbackPathRejectsMetacharacters(t *testing.T) {
	for _, path := range []string{
		"/admin/api/v1/oauth/devin/callback/{state}",
		"/admin/api/v1/oauth/devin/callback/$",
		"/oauth/callback/{id}",
	} {
		if err := validateCallbackPath(path); err == nil {
			t.Fatalf("metacharacter path %q should be rejected", path)
		}
	}
}

func TestValidateCallbackPathRejectsTrailingSlash(t *testing.T) {
	if err := validateCallbackPath("/oauth/callback/"); err == nil {
		t.Fatalf("trailing slash path should be rejected")
	}
}

func TestValidateCallbackPathRejectsMissingLeadingSlash(t *testing.T) {
	if err := validateCallbackPath("oauth/callback"); err == nil {
		t.Fatalf("path without leading slash should be rejected")
	}
}

func TestValidateCallbackPathRejectsExactAdminRouteCollision(t *testing.T) {
	for _, route := range []string{
		"/admin/api/v1/oauth/xai/device",
		"/admin/api/v1/oauth/devin/start",
		"/admin/api/v1/accounts",
		"/admin/api/v1/models",
		"/admin/api/v1/usage",
		"/admin/api/v1/api-keys",
	} {
		if err := validateCallbackPath(route); err == nil {
			t.Fatalf("admin route %q should be rejected as callback collision", route)
		}
	}
}

func TestValidateCallbackPathRejectsExactWebRouteCollision(t *testing.T) {
	// The exact GET callback must not shadow any Web/admin UI route registered
	// under /admin/ — doing so would bypass the Web handler's session/CSRF
	// wrappers for that path.
	for _, route := range []string{
		"/admin",
		"/admin/login",
		"/admin/logout",
		"/admin/accounts",
		"/admin/oauth/new",
		"/admin/usage",
		"/admin/models",
		"/admin/api-keys",
	} {
		if err := validateCallbackPath(route); err == nil {
			t.Fatalf("web route %q should be rejected as callback collision", route)
		}
	}
}

func TestValidateCallbackPathRejectsConcreteWebDynamicRouteMatch(t *testing.T) {
	// A concrete callback path that would match a dynamic Web/admin route
	// pattern under accurate Go ServeMux segment semantics must be rejected —
	// the exact dispatcher would bypass the Web handler's session/CSRF
	// wrappers for that path. Each path below has the same segment count as a
	// registered dynamic route and lines up literal-for-literal on every
	// non-wildcard segment.
	for _, path := range []string{
		"/admin/accounts/abc",
		"/admin/accounts/abc/label",
		"/admin/accounts/abc/enabled",
		"/admin/accounts/abc/refresh",
		"/admin/accounts/abc/delete",
		"/admin/oauth/devin/authorize/sess",
		"/admin/oauth/devin/status/sess",
		"/admin/oauth/devin/cancel/sess",
		"/admin/usage/abc/refresh",
		"/admin/models/abc/refresh",
		"/admin/api-keys/abc/revoke",
		"/admin/static/app.css",
	} {
		if err := validateCallbackPath(path); err == nil {
			t.Fatalf("dynamic web route match %q should be rejected", path)
		}
	}
}

func TestValidateCallbackPathAllowsPrefixSharingNonMatchingSegments(t *testing.T) {
	// These paths share a literal prefix with a registered dynamic route but
	// do NOT match it under ServeMux segment semantics (different segment
	// count or a non-matching literal segment). The old prefix check falsely
	// rejected them; the segment-aware check must allow them.
	for _, path := range []string{
		// 4 segments vs /admin/oauth/{provider}/authorize/{session} (5) and
		// /admin/oauth/{provider}/status/{session} (5): segment count differs.
		"/admin/oauth/devin/callback",
		// 4 segments vs /admin/static/{file} (3): segment count differs, so
		// the nested static asset path is not shadowed by the single-segment
		// {file} wildcard.
		"/admin/static/css/app.css",
		// 4 segments vs /admin/accounts/{id} (3) and /admin/accounts/{id}/label
		// (4): the 4-segment form's last literal "extra" matches no registered
		// 4-segment route (label/enabled/refresh/delete).
		"/admin/accounts/abc/extra",
		// 6 segments vs /admin/api/v1/oauth/devin/status/{session} (7): count
		// differs, and "callback" != "start" on the 6-segment admin route.
		"/admin/api/v1/oauth/devin/callback",
	} {
		if err := validateCallbackPath(path); err != nil {
			t.Fatalf("non-matching path %q should be allowed: %v", path, err)
		}
	}
}

func TestValidateCallbackPathRejectsConcreteDynamicRouteMatch(t *testing.T) {
	// A concrete callback path that would match a dynamic admin route pattern
	// must be rejected — the exact dispatcher would bypass admin auth for that
	// protected route.
	for _, path := range []string{
		"/admin/api/v1/oauth/devin/status/abc",
		"/admin/api/v1/oauth/devin/cancel/abc",
		"/admin/api/v1/oauth/xai/device/abc",
		"/admin/api/v1/accounts/abc",
		"/admin/api/v1/accounts/abc/refresh",
		"/admin/api/v1/accounts/abc/usage",
		"/admin/api/v1/accounts/abc/usage/refresh",
		"/admin/api/v1/api-keys/abc",
	} {
		if err := validateCallbackPath(path); err == nil {
			t.Fatalf("dynamic route match %q should be rejected", path)
		}
	}
}

func TestValidateCallbackPathDefaultCallbackDoesNotCollide(t *testing.T) {
	// The default callback must not be rejected by the dynamic route checks.
	if err := validateCallbackPath("/admin/api/v1/oauth/devin/callback"); err != nil {
		t.Fatalf("default callback path rejected: %v", err)
	}
}

func TestValidateCallbackPathAllowsNonAdminCallback(t *testing.T) {
	if err := validateCallbackPath("/oauth/devin/callback"); err != nil {
		t.Fatalf("non-admin callback path rejected: %v", err)
	}
}

func TestValidateCallbackPathAllowsCustomAdminSubtreeCallback(t *testing.T) {
	// A custom callback that lives under /admin/api/v1/ but does not equal or
	// dynamically match any registered admin or Web route must remain allowed —
	// the exact dispatcher secures it and AdminAuth protects every neighbor.
	if err := validateCallbackPath("/admin/api/v1/oauth/devin/return"); err != nil {
		t.Fatalf("custom admin-subtree callback path rejected: %v", err)
	}
}

func TestValidateCallbackPathEmptyIsNoOp(t *testing.T) {
	if err := validateCallbackPath(""); err != nil {
		t.Fatalf("empty callback path should be a no-op: %v", err)
	}
}
