package service

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/ipintel"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// New-location (AR-18) notice: country granularity only, out of band, fail-open.
//
// notifyNewCountry fires a notice when a successful login comes from a country
// the user has not been seen from before AND they already had at least one
// recorded country. A first-ever login seeds silently. When either the ipintel
// handle or the country store is absent the whole thing no-ops. The notice and
// its audit record carry the country code only — never the IP.
// =============================================================================

// testIPIntel builds a small in-process ipintel table. Documentation-range
// blocks are used so the addresses are globally-scoped (ipintel fails open on
// private/loopback) yet never real:
//
//	203.0.113.0/24  -> DE, clean
//	192.0.2.0/24    -> FR, clean
//	198.51.100.0/24 -> US, hosting (=> IsAnonymous)
func testIPIntel(t *testing.T) *ipintel.DB {
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

type capturedEmail struct {
	to, subject, html, text string
}

// newNotifyService returns a fully-wired auth service whose cache is backed by a
// real in-memory store (so the throttle gate behaves like production) and whose
// email sender pushes every send onto emailCh.
func newNotifyService(t *testing.T, lc *mocks.MockLoginCountryRepo, ip *ipintel.DB) (*AuthService, chan capturedEmail) {
	t.Helper()
	mem := cache.NewMemoryCache()
	emailCh := make(chan capturedEmail, 8)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.cache.GetFn = mem.Get
		o.cache.SetFn = mem.Set
		o.cache.DeleteFn = mem.Delete
		o.cache.GetAndDeleteFn = mem.GetAndDelete
		o.cache.SetIfNotExistsFn = mem.SetIfNotExists
		o.cache.IncrementFn = mem.Increment
		o.cache.ExistsFn = mem.Exists
		o.emailSender.SendFn = func(_ context.Context, to, subject, html, text string) error {
			emailCh <- capturedEmail{to: to, subject: subject, html: html, text: text}
			return nil
		}
	})
	svc.SetIPIntel(ip)
	svc.SetLoginCountryRepo(lc)
	return svc, emailCh
}

// expectEmail waits for a single send and fails if none arrives.
func expectEmail(t *testing.T, ch chan capturedEmail) capturedEmail {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("expected a new-location notice, got none")
		return capturedEmail{}
	}
}

// expectNoEmail asserts nothing is sent within a short settle window. The
// decision to send is made synchronously before any send goroutine is spawned,
// so a negative path provably enqueues nothing.
func expectNoEmail(t *testing.T, ch chan capturedEmail) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("expected no notice, but one was sent to %q (subject %q)", e.to, e.subject)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestNotifyNewCountry_NewCountryNotifiesWithCountryNotIP(t *testing.T) {
	lc := &mocks.MockLoginCountryRepo{
		UpsertAndWasNewFn: func(_ context.Context, _, cc string) (bool, bool, error) {
			return true, true, nil // new country, user already had one
		},
	}
	svc, ch := newNotifyService(t, lc, testIPIntel(t))

	const ip = "192.0.2.50" // FR
	svc.notifyNewCountry("user-1", "user@example.com", ip, "")

	e := expectEmail(t, ch)
	if e.to != "user@example.com" {
		t.Errorf("notice sent to %q, want user@example.com", e.to)
	}
	if !strings.Contains(e.text, "FR") && !strings.Contains(e.html, "FR") {
		t.Errorf("notice does not carry the country code FR; text=%q", e.text)
	}
	// The invariant: the raw IP must never appear in the notice.
	if strings.Contains(e.html, ip) || strings.Contains(e.text, ip) || strings.Contains(e.subject, ip) {
		t.Errorf("notice leaked the IP %q; body=%q", ip, e.text)
	}
}

func TestNotifyNewCountry_SameCountryNoNotice(t *testing.T) {
	lc := &mocks.MockLoginCountryRepo{
		UpsertAndWasNewFn: func(_ context.Context, _, _ string) (bool, bool, error) {
			return false, true, nil // known country
		},
	}
	svc, ch := newNotifyService(t, lc, testIPIntel(t))
	svc.notifyNewCountry("user-1", "user@example.com", "203.0.113.9", "")
	expectNoEmail(t, ch)
}

func TestNotifyNewCountry_FirstEverSeedsSilently(t *testing.T) {
	lc := &mocks.MockLoginCountryRepo{
		UpsertAndWasNewFn: func(_ context.Context, _, _ string) (bool, bool, error) {
			return true, false, nil // new, but the user had no prior country
		},
	}
	svc, ch := newNotifyService(t, lc, testIPIntel(t))
	svc.notifyNewCountry("user-1", "user@example.com", "203.0.113.9", "")
	expectNoEmail(t, ch)
}

func TestNotifyNewCountry_IPIntelNilNoop(t *testing.T) {
	lc := &mocks.MockLoginCountryRepo{
		UpsertAndWasNewFn: func(_ context.Context, _, _ string) (bool, bool, error) {
			t.Fatal("country store must not be consulted when ipintel is nil")
			return false, false, nil
		},
	}
	// ip == nil: SetIPIntel(nil) leaves the feature off.
	svc, ch := newNotifyService(t, lc, nil)
	svc.notifyNewCountry("user-1", "user@example.com", "203.0.113.9", "")
	expectNoEmail(t, ch)
}

func TestNotifyNewCountry_UnknownCountryNoop(t *testing.T) {
	lc := &mocks.MockLoginCountryRepo{
		UpsertAndWasNewFn: func(_ context.Context, _, _ string) (bool, bool, error) {
			t.Fatal("country store must not be consulted when the IP yields no country")
			return false, false, nil
		},
	}
	svc, ch := newNotifyService(t, lc, testIPIntel(t))
	// 8.8.8.8 is not in the test table -> fails open to "" -> nothing to compare.
	svc.notifyNewCountry("user-1", "user@example.com", "8.8.8.8", "")
	expectNoEmail(t, ch)
}

func TestNotifyNewCountry_ThrottledPerCountry(t *testing.T) {
	lc := &mocks.MockLoginCountryRepo{
		UpsertAndWasNewFn: func(_ context.Context, _, _ string) (bool, bool, error) {
			return true, true, nil // always "new country, had prior" so only the throttle can gate
		},
	}
	svc, ch := newNotifyService(t, lc, testIPIntel(t))
	svc.notifyNewCountry("user-1", "user@example.com", "192.0.2.50", "") // FR
	_ = expectEmail(t, ch)
	// Second notice for the same user+country inside the window is throttled.
	svc.notifyNewCountry("user-1", "user@example.com", "192.0.2.51", "") // FR again
	expectNoEmail(t, ch)
}

// TestLogin_NewCountryEndToEnd drives the real password-login success path: a
// login from a genuinely new country (the user already had one recorded) fires
// the notice, carrying the country and never the IP.
func TestLogin_NewCountryEndToEnd(t *testing.T) {
	hash := validPasswordHash(t)
	lc := &mocks.MockLoginCountryRepo{}
	user := &model.User{
		ID: "user-1", Email: "traveler@example.com",
		PasswordHash: hash, EmailVerified: true,
	}
	svc, ch := loginServiceForUser(t, user, lc, testIPIntel(t))

	ctx := context.Background()

	// Seed the user's first country (DE) directly and synchronously: a first-ever
	// login would otherwise seed silently, and we want to test the notice.
	if _, _, err := lc.UpsertAndWasNew(ctx, user.ID, "DE"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Login from FR (192.0.2.x): a new country for a user who already had DE.
	if _, err := svc.Login(ctx, LoginInput{
		Email: user.Email, Password: "correct-horse-battery-staple",
	}, "192.0.2.77", "TestAgent"); err != nil {
		t.Fatalf("login: %v", err)
	}
	e := expectEmail(t, ch)
	if !strings.Contains(e.text, "FR") && !strings.Contains(e.html, "FR") {
		t.Errorf("end-to-end notice missing country FR; text=%q", e.text)
	}
	if strings.Contains(e.html, "192.0.2.77") || strings.Contains(e.text, "192.0.2.77") {
		t.Errorf("end-to-end notice leaked the IP")
	}
}

// loginServiceForUser builds a notify-wired service whose GetByEmail returns the
// given user, so Login can be driven to its success path.
func loginServiceForUser(t *testing.T, user *model.User, lc *mocks.MockLoginCountryRepo, ip *ipintel.DB) (*AuthService, chan capturedEmail) {
	t.Helper()
	mem := cache.NewMemoryCache()
	emailCh := make(chan capturedEmail, 8)
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
			return user, nil
		}
		o.cache.GetFn = mem.Get
		o.cache.SetFn = mem.Set
		o.cache.DeleteFn = mem.Delete
		o.cache.GetAndDeleteFn = mem.GetAndDelete
		o.cache.SetIfNotExistsFn = mem.SetIfNotExists
		o.cache.IncrementFn = mem.Increment
		o.cache.ExistsFn = mem.Exists
		o.emailSender.SendFn = func(_ context.Context, to, subject, html, text string) error {
			emailCh <- capturedEmail{to: to, subject: subject, html: html, text: text}
			return nil
		}
	})
	svc.SetIPIntel(ip)
	svc.SetLoginCountryRepo(lc)
	return svc, emailCh
}
