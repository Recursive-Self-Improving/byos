package auththrottle_test

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"byos/internal/auththrottle"
	appcrypto "byos/internal/crypto"
	"byos/internal/store"
)

func TestGuardBlocksWithoutEvaluatingAndResetsOnSuccess(t *testing.T) {
	database, err := store.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	keys, err := appcrypto.DeriveKeys(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	guard, err := auththrottle.NewGuard(store.NewAdminAuthThrottleRepository(database.DB), keys.AdminAuthSourceFingerprint, auththrottle.DefaultPolicy(), slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("192.0.2.10")
	checks := 0
	wrong := func() bool { checks++; return false }
	for failure := range 3 {
		outcome, err := guard.Evaluate(t.Context(), source, auththrottle.SurfaceWebPassword, wrong)
		if err != nil || outcome.Disposition != auththrottle.Rejected {
			t.Fatalf("failure %d outcome=%#v err=%v", failure+1, outcome, err)
		}
	}
	outcome, err := guard.Evaluate(t.Context(), source, auththrottle.SurfaceAdminBearer, func() bool { checks++; return true })
	if err != nil || outcome.Disposition != auththrottle.Blocked || outcome.RetryAfter != 5*time.Second || checks != 3 {
		t.Fatalf("blocked outcome=%#v checks=%d err=%v", outcome, checks, err)
	}
	clock = clock.Add(5 * time.Second)
	outcome, err = guard.Evaluate(t.Context(), source, auththrottle.SurfaceAdminBearer, func() bool { checks++; return true })
	if err != nil || outcome.Disposition != auththrottle.Authenticated || checks != 4 {
		t.Fatalf("success outcome=%#v checks=%d err=%v", outcome, checks, err)
	}
	outcome, err = guard.Evaluate(t.Context(), source, auththrottle.SurfaceWebPassword, wrong)
	if err != nil || outcome.Disposition != auththrottle.Rejected || checks != 5 {
		t.Fatalf("post-reset outcome=%#v checks=%d err=%v", outcome, checks, err)
	}
}
