package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Refresh-token reuse detection, read the way the audit log is actually read.
//
// Both arms of reuse detection wrote audit.TokenRevoke with a reason key, which
// is the row Logout writes and the row a session-lifetime expiry writes. The
// reason is metadata; the score and the alert rule come off the class. So the
// one event that proves a session credential is in two pairs of hands was
// recorded with risk_score 0 -- below a mistyped password -- and no rule could
// watch it without paging on every logout.
//
// These tests assert the class and the score rather than the reason, because a
// test that asserts the reason passes on the defect.

// capturedAudit collects the rows a service path wrote.
type capturedAudit struct {
	mu      sync.Mutex
	entries []model.AuditEntry
}

func (c *capturedAudit) repo() *mocks.MockAuditRepo {
	return &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.entries = append(c.entries, *e)
			return nil
		},
	}
}

// ofType returns the rows of one event class.
func (c *capturedAudit) ofType(eventType string) []model.AuditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []model.AuditEntry
	for _, e := range c.entries {
		if e.EventType == eventType {
			out = append(out, e)
		}
	}
	return out
}

// replayArm is one of the two ways one refresh token gets caught in two hands.
type replayArm struct {
	name string
	// token is the row GetByTokenHash resolves the presented cookie to.
	token func(fp string) *model.RefreshToken
	// markUsed is the compare-and-set result. The concurrent arm loses it.
	markUsed bool
	// reason is the metadata key the arm records, kept as detail under one class
	// rather than as a class of its own.
	reason string
}

func replayArms(fp string) []replayArm {
	return []replayArm{
		{
			name: "the presented row was already spent",
			token: func(fp string) *model.RefreshToken {
				return &model.RefreshToken{
					ID: "rt-1", UserID: "user-1", ClientID: "client-1", FamilyID: "fam-1",
					Used: true, FingerprintHash: fp,
					ExpiresAt: time.Now().Add(time.Hour),
				}
			},
			markUsed: true,
			reason:   "replay_detected",
		},
		{
			name: "the mark-used compare-and-set was lost to a concurrent request",
			token: func(fp string) *model.RefreshToken {
				return &model.RefreshToken{
					ID: "rt-1", UserID: "user-1", ClientID: "client-1", FamilyID: "fam-1",
					FingerprintHash: fp,
					ExpiresAt:       time.Now().Add(time.Hour),
				}
			},
			markUsed: false,
			reason:   "concurrent_replay_detected",
		},
	}
}

// TestRefreshReuseIsAuditedAsAReplayAndNotAsALogout is the gate on the class.
func TestRefreshReuseIsAuditedAsAReplayAndNotAsALogout(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})

	for _, arm := range replayArms(fp) {
		t.Run(arm.name, func(t *testing.T) {
			captured := &capturedAudit{}
			svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
				o.auditRepo = captured.repo()
				o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
					return arm.token(fp), nil
				}
				o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
					return arm.markUsed, nil
				}
			})

			if _, err := svc.Refresh(context.Background(), "stolen-cookie", "1.2.3.4", "TestAgent",
				vaultcrypto.FingerprintInput{}); err == nil {
				t.Fatal("a reused refresh token was accepted")
			}

			if got := captured.ofType(audit.TokenRevoke); len(got) != 0 {
				t.Errorf("reuse detection wrote %d token_revoke row(s). That is the class a logout "+
					"writes, so the score comes out routine and any rule watching it pages on "+
					"every sign-out.", len(got))
			}

			rows := captured.ofType(audit.RefreshTokenReplayed)
			if len(rows) != 1 {
				t.Fatalf("reuse detection wrote %d %s rows, want 1", len(rows), audit.RefreshTokenReplayed)
			}
			row := rows[0]
			if row.RiskScore != audit.SeverityCritical {
				t.Errorf("the replay row scored %d, want critical %d. An operator filtering "+
					"risk_score >= %d has to see refresh-token theft.",
					row.RiskScore, audit.SeverityCritical, audit.SeverityElevated)
			}
			if row.Metadata["reason"] != arm.reason {
				t.Errorf("reason = %v, want %q; the two arms stay distinguishable inside the class",
					row.Metadata["reason"], arm.reason)
			}
			if row.Metadata["family_id"] != "fam-1" {
				t.Errorf("family_id = %v, want fam-1; the burned family has to be named or the "+
					"row says a session ended without saying which", row.Metadata["family_id"])
			}
			if row.UserID != "user-1" {
				t.Errorf("the replay row names user %q, want user-1", row.UserID)
			}
		})
	}
}

// The counter is the half a deployment's monitoring can page on without parsing
// the audit log, and there was none: internal/metrics counted refreshes that
// worked and nothing for a refresh refused because the credential turned up
// twice.
func TestRefreshReuseIncrementsTheReplayCounter(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "1.2.3.4", UserAgent: "TestAgent",
	})

	for _, arm := range replayArms(fp) {
		t.Run(arm.name, func(t *testing.T) {
			svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
				o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
					return arm.token(fp), nil
				}
				o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) {
					return arm.markUsed, nil
				}
			})
			zero := func() int64 { return 0 }
			collector := metrics.NewCollector(zero, zero, func() int { return 0 })
			svc.SetMetrics(collector)

			if _, err := svc.Refresh(context.Background(), "stolen-cookie", "1.2.3.4", "TestAgent",
				vaultcrypto.FingerprintInput{}); err == nil {
				t.Fatal("a reused refresh token was accepted")
			}

			rec := httptest.NewRecorder()
			collector.Handler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			body := rec.Body.String()
			if !strings.Contains(body, "vault_refresh_token_replays_total 1") {
				t.Error("a detected replay did not reach vault_refresh_token_replays_total")
			}
			if !strings.Contains(body, "vault_tokens_refreshed_total 0") {
				t.Error("a refused rotation was counted as a refresh; the two outcomes must not share a counter")
			}
		})
	}
}
