package routing

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reset := now.Add(2 * time.Hour)
	tests := []struct {
		name     string
		status   int
		headers  http.Header
		body     string
		err      error
		reset    *time.Time
		class    ErrorClass
		retry    bool
		cooldown time.Duration
	}{{"validation", 400, nil, "", nil, nil, ClassValidation, false, 0}, {"unauthorized", 401, nil, "", nil, nil, ClassUnauthorized, true, 0}, {"permission", 403, nil, "", nil, nil, ClassPermission, false, 0}, {"retry after", 429, http.Header{"Retry-After": []string{"120"}}, "", nil, nil, ClassRateLimit, true, 2 * time.Minute}, {"free reset", 429, nil, `{"error":"subscription:free-usage-exhausted"}`, nil, &reset, ClassFreeUsageExhausted, true, 2 * time.Hour}, {"free fallback", 429, nil, `{"error":{"code":"subscription:free-usage-exhausted"}}`, nil, nil, ClassFreeUsageExhausted, true, 24 * time.Hour}, {"transient", 503, nil, "", nil, nil, ClassTransient, true, time.Minute}, {"connection setup", 0, nil, "", &ConnectionSetupError{Err: errors.New("refused")}, nil, ClassConnection, true, 0}, {"post-connect error", 0, nil, "", errors.New("read timeout"), nil, ClassUpstream, false, 0}, {"cancel", 0, nil, "", context.Canceled, nil, ClassCancelled, false, 0}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Classify(test.status, test.headers, []byte(test.body), test.err, test.reset, now)
			if got.Class != test.class || got.RetryNext != test.retry || got.Cooldown != test.cooldown {
				t.Fatalf("got=%+v", got)
			}
		})
	}
	invalid := InvalidGrant("")
	if !invalid.DisableAccount || invalid.Class != ClassInvalidGrant {
		t.Fatalf("invalid=%+v", invalid)
	}
}

func TestFreeUsageClassificationIsExact(t *testing.T) {
	now := time.Now()
	for _, body := range []string{`{"message":"not subscription:free-usage-exhausted today"}`, `{"metadata":"subscription:free-usage-exhausted"}`, `{"error":"subscription:free-usage-exhausted-near"}`, `{`} {
		if got := Classify(429, nil, []byte(body), nil, nil, now); got.Class != ClassRateLimit {
			t.Fatalf("body %q classified as %s", body, got.Class)
		}
	}
}

func TestRetryAfterZeroAndPastAreExplicit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, value := range []string{"0", now.Add(-time.Hour).Format(http.TimeFormat)} {
		classified := Classify(429, http.Header{"Retry-After": []string{value}}, nil, nil, nil, now)
		if !classified.ExplicitRetryAfter || classified.Cooldown != 0 || !classified.RetryAfter.Equal(now) {
			t.Fatalf("Retry-After %q = %+v", value, classified)
		}
	}
}
