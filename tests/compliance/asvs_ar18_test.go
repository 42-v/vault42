package compliance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/ipintel"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// AR-18 — new-location login notice, and VPN/anonymiser rate-limit scrutiny.
//
// docs/security.md AR-18 (and docs/PRIVACY.md P13) commit vault42 to two
// behaviors derived from a LOCAL IP-intelligence table (no third-party lookup):
//
//  1. Notify a user when their account is accessed from a country they have not
//     signed in from before — at COUNTRY GRANULARITY ONLY. The notice and its
//     audit record carry the ISO alpha-2 country code and never the IP.
//
//  2. Raise rate-limit scrutiny on VPN / hosting / Tor addresses so credential
//     stuffing from anonymising infrastructure exhausts the login/register/reset
//     buckets faster — WITHOUT ever hard-blocking a VPN (the response is the
//     ordinary 429, never a 403).
//
// This is a behavioral suite, not a structural one: it drives the real login
// success path and the real rate-limit middleware and asserts the observable
// outcome, including the data-minimisation invariant that the IP never leaves
// the country derivation.
// =============================================================================

// ar18IPIntel builds an in-process ipintel table over documentation ranges:
//
//	203.0.113.0/24  -> DE, clean (a "known" country to seed)
//	192.0.2.0/24    -> FR, clean (the "new" country that triggers the notice)
//	198.51.100.0/24 -> US, hosting (=> IsAnonymous, for the scrutiny half)
func ar18IPIntel(t *testing.T) *ipintel.DB {
	t.Helper()
	addr := func(s string) netip.Addr {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		return a
	}
	blob := ipintel.Marshal([]ipintel.Range{
		{Lo: addr("203.0.113.0"), Hi: addr("203.0.113.255"), CC: "DE"},
		{Lo: addr("192.0.2.0"), Hi: addr("192.0.2.255"), CC: "FR"},
		{Lo: addr("198.51.100.0"), Hi: addr("198.51.100.255"), CC: "US", Hosting: true},
	})
	db, err := ipintel.Load(blob)
	if err != nil {
		t.Fatalf("load ipintel: %v", err)
	}
	return db
}

type ar18Email struct{ to, subject, html, text string }

// TestASVS_AR18_NewLocationNoticeAndVPNScrutiny is the compliance-register entry
// for AR-18. It proves both halves of the control in one test.
func TestASVS_AR18_NewLocationNoticeAndVPNScrutiny(t *testing.T) {
	t.Run("NewCountryNoticeCarriesCountryNeverIP", func(t *testing.T) {
		ctx := context.Background()

		// --- wire a real auth service over mocks ---
		key, _ := vaultcrypto.GenerateRSAKeyPair()
		kid, _ := vaultcrypto.RandomUUID()
		tokenSvc := service.NewTokenService(key, kid, "https://vault.test", "https://vault.test",
			15*time.Minute, 24*time.Hour, 30*24*time.Hour)

		// Capture audit events so we can prove the new-country event is country-only.
		var auditMu sync.Mutex
		var auditEvents []*model.AuditEntry
		auditLog := audit.NewLogger(&mocks.MockAuditRepo{
			InsertFn: func(_ context.Context, e *model.AuditEntry) error {
				auditMu.Lock()
				cp := *e
				auditEvents = append(auditEvents, &cp)
				auditMu.Unlock()
				return nil
			},
		}, 0)

		mem := cache.NewMemoryCache()
		t.Cleanup(func() { _ = mem.Close() })
		emailCh := make(chan ar18Email, 4)
		sender := &mocks.MockEmailSender{
			SendFn: func(_ context.Context, to, subject, html, text string) error {
				emailCh <- ar18Email{to, subject, html, text}
				return nil
			},
		}

		hash, err := vaultcrypto.HashPassword("correct-horse-battery-staple")
		if err != nil {
			t.Fatal(err)
		}
		user := &model.User{
			ID: "user-ar18", Email: "traveler@example.com",
			PasswordHash: hash, EmailVerified: true,
		}
		userRepo := &mocks.MockUserRepo{
			GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) { return user, nil },
			GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
				return &model.User{ID: id, Roles: []string{"user"}}, nil
			},
		}
		lc := &mocks.MockLoginCountryRepo{}

		svc := service.NewAuthService(
			userRepo, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
			tokenSvc, nil, auditLog, service.NewHIBPClient(),
			mem, sender, "https://vault.test", "TestVault", "", 15, false, nil,
		)
		svc.SetIPIntel(ar18IPIntel(t))
		svc.SetLoginCountryRepo(lc)

		// Seed a first, known country (DE) synchronously: a first-ever login seeds
		// silently, so we establish prior history before the tested login.
		if _, _, err := lc.UpsertAndWasNew(ctx, user.ID, "DE"); err != nil {
			t.Fatalf("seed: %v", err)
		}

		// Log in from FR (192.0.2.x): a genuinely new country.
		const loginIP = "192.0.2.42"
		if _, err := svc.Login(ctx, service.LoginInput{
			Email: user.Email, Password: "correct-horse-battery-staple",
		}, loginIP, "TestAgent"); err != nil {
			t.Fatalf("login: %v", err)
		}

		var e ar18Email
		select {
		case e = <-emailCh:
		case <-time.After(2 * time.Second):
			t.Fatal("no new-location notice was sent for a login from a new country")
		}

		// The notice carries the country...
		if !strings.Contains(e.text, "FR") && !strings.Contains(e.html, "FR") {
			t.Errorf("notice does not carry the country FR; body=%q", e.text)
		}
		// ...and never the IP (data minimisation to country granularity).
		if strings.Contains(e.html, loginIP) || strings.Contains(e.text, loginIP) || strings.Contains(e.subject, loginIP) {
			t.Errorf("notice leaked the login IP %q", loginIP)
		}

		// The audit record for the new country is country-only, never the IP.
		auditMu.Lock()
		defer auditMu.Unlock()
		var found bool
		for _, ev := range auditEvents {
			if ev.EventType != audit.LoginNewCountry {
				continue
			}
			found = true
			if ev.IP == loginIP {
				t.Errorf("login_new_country audit row carried the IP %q", loginIP)
			}
			if cc, _ := ev.Metadata["country"].(string); cc != "FR" {
				t.Errorf("login_new_country audit metadata country = %v, want FR", ev.Metadata["country"])
			}
		}
		if !found {
			t.Error("no login_new_country audit event was recorded")
		}
	})

	t.Run("VPNGetsHeavierScrutinyButIsNeverBlocked", func(t *testing.T) {
		db := ar18IPIntel(t)
		c := cache.NewMemoryCache()
		t.Cleanup(func() { _ = c.Close() })

		// Login limiter: 5 per window, VPN weight 3, so a flagged IP trips on its
		// 2nd request (2*3 > 5) while a clean IP keeps its full budget.
		mw := middleware.RateLimit(c, middleware.RateLimitConfig{
			Limit: 5, Window: time.Minute, KeyFunc: middleware.LoginRateLimitKey,
			Weight: middleware.IPIntelWeight(db, 3),
		}, true)

		serve := func(remote string) int {
			ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
			r.RemoteAddr = remote
			rec := httptest.NewRecorder()
			mw(ok).ServeHTTP(rec, r)
			return rec.Code
		}

		// A VPN's first login attempt is allowed — this is scrutiny, not denial.
		if code := serve("198.51.100.7:5000"); code != http.StatusOK {
			t.Fatalf("VPN first request = %d, want 200 (a VPN must not be blocked outright)", code)
		}
		// Its budget is tighter: the next request trips the ordinary 429.
		code := serve("198.51.100.7:5000")
		if code != http.StatusTooManyRequests {
			t.Errorf("VPN second request = %d, want 429 (tighter bucket)", code)
		}
		// It is never a 403 hard block — that belongs in ipaccess.go, not here.
		if code == http.StatusForbidden {
			t.Error("a VPN was answered 403; VPN scrutiny must never hard-block")
		}

		// A clean IP keeps the full budget: 5 through before the 6th trips.
		for i := 0; i < 5; i++ {
			if got := serve("203.0.113.7:6000"); got != http.StatusOK {
				t.Fatalf("clean request %d = %d, want 200", i, got)
			}
		}
		if got := serve("203.0.113.7:6000"); got != http.StatusTooManyRequests {
			t.Errorf("clean request 6 = %d, want 429", got)
		}
	})
}
