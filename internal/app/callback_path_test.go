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

func TestValidateCallbackPathEmptyIsNoOp(t *testing.T) {
	if err := validateCallbackPath(""); err != nil {
		t.Fatalf("empty callback path should be a no-op: %v", err)
	}
}
