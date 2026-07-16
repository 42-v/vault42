package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/model"
)

// A response body that dies mid-read (connection reset after headers) must fail
// open exactly like an unreachable API: the breach check cannot become a
// registration blocker because HIBP hung up halfway through the range list.
func TestHIBPBodyReadFailureFailsOpen(t *testing.T) {
	h := newTestHIBPClient(&mockTransport{
		handler: func(req *http.Request) (*http.Response, error) {
			body := io.MultiReader(
				strings.NewReader("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"),
				iotest.ErrReader(errors.New("connection reset mid-body")),
			)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(body),
			}, nil
		},
	})

	if h.IsBreached("password-for-truncated-body-test") {
		t.Error("a body read failure should fail open (return false)")
	}
}

// A successful refresh with a collector wired in bumps the tokens-refreshed
// counter, mirroring the login path's login-success/tokens-issued recording.
func TestRefreshMetricsRecorded(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				FingerprintHash: fp,
				ExpiresAt:       time.Now().Add(1 * time.Hour),
			}, nil
		}
		o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
			return true, nil
		}
	})
	zero := func() int64 { return 0 }
	collector := metrics.NewCollector(zero, zero, func() int { return 0 })
	svc.SetMetrics(collector)

	if _, err := svc.Refresh(context.Background(), "valid-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rec := httptest.NewRecorder()
	collector.Handler()(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "vault_tokens_refreshed_total 1") {
		t.Error("tokens refreshed counter not recorded on refresh")
	}
}

// The DB fallback (cache nil) must not lock an account whose persisted
// failed-login count is still under the threshold: the fallback is a brute
// force backstop, not a hair trigger for accounts with a few stale failures.
func TestIsAccountLockedDBFallbackBelowThreshold(t *testing.T) {
	svc, o := newMockAuthService(t)
	svc.cache = nil
	o.userRepo.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, FailedLoginCount: lockoutThreshold - 1}, nil
	}

	if svc.isAccountLocked(context.Background(), "user-1") {
		t.Fatal("failed-login count below threshold must not lock via DB fallback")
	}
}
