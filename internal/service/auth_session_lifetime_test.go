package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Rotation hands out a full fresh refresh TTL every time and carries the same
// family_id forward, so before migration 013 the TTL was a sliding window: a
// client that refreshed inside every window held one session for as long as it
// liked, and nothing in the system could say how old that session was. NIST SP
// 800-63B-4 §5.2.3 wants reauthentication at an absolute interval regardless of
// activity, so the bound is measured from the family's creation and every branch
// that cannot establish it refuses to rotate.

// datedTokenRepo is a refresh-token store that can date a family, which is the
// capability AuthService asserts for before it enforces the bound.
type datedTokenRepo struct {
	*mocks.MockRefreshTokenRepo
	origin    time.Time
	originErr error

	mu       sync.Mutex
	revoked  []string
	inserted []*model.RefreshToken
}

func (r *datedTokenRepo) FamilyOrigin(_ context.Context, _ string) (time.Time, error) {
	return r.origin, r.originErr
}

func (r *datedTokenRepo) RevokeFamily(_ context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, familyID)
	return nil
}

func (r *datedTokenRepo) Create(_ context.Context, token *model.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inserted = append(r.inserted, token)
	return nil
}

func (r *datedTokenRepo) revocations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.revoked...)
}

func (r *datedTokenRepo) lastInsert(t *testing.T) *model.RefreshToken {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.inserted) == 0 {
		t.Fatal("no refresh token was stored")
	}
	return r.inserted[len(r.inserted)-1]
}

// storedToken is the row a presented refresh token resolves to. It is always
// inside its own per-token expiry, so only the family's age can reject it.
func storedToken(raw string) *model.RefreshToken {
	return &model.RefreshToken{
		ID: "rt-old", UserID: "u-1", FamilyID: "fam-1",
		TokenHash: vaultcrypto.SHA256Hex(raw),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

// refreshFixture wires a service whose token store can date families.
func refreshFixture(t *testing.T, maxLifetime time.Duration, origin time.Time) (*AuthService, *datedTokenRepo) {
	t.Helper()
	svc, o := newMockAuthService(t)
	repo := &datedTokenRepo{MockRefreshTokenRepo: o.tokenRepo, origin: origin}
	repo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
		return storedToken("raw-refresh-token"), nil
	}
	repo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) { return true, nil }
	svc.tokens = repo
	svc.tokenSvc.SetMaxSessionLifetime(maxLifetime)
	return svc, repo
}

func TestRefresh_TerminatesAFamilyPastTheAbsoluteLifetime(t *testing.T) {
	svc, repo := refreshFixture(t, 7*24*time.Hour, time.Now().Add(-8*24*time.Hour))

	_, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "UA", vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("an over-age family must be rejected, got %v", err)
	}
	// The transport maps ErrTokenExpired to 401 and clears the cookie. Wrapping is
	// what keeps an over-age session from surfacing as a 500.
	if !errors.Is(err, ErrTokenExpired) {
		t.Error("ErrSessionExpired must wrap ErrTokenExpired so existing transports keep their status code")
	}
	if got := repo.revocations(); len(got) != 1 || got[0] != "fam-1" {
		t.Errorf("family revocations = %v, want [fam-1]: the whole session must end, not just this rotation", got)
	}
}

func TestRefresh_AllowsAFamilyInsideTheAbsoluteLifetime(t *testing.T) {
	svc, repo := refreshFixture(t, 7*24*time.Hour, time.Now().Add(-time.Hour))

	res, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "UA", vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatalf("a one-hour-old family is well inside a seven-day bound: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Error("rotation inside the bound must still issue a pair")
	}
	if got := repo.revocations(); len(got) != 0 {
		t.Errorf("nothing should have been revoked, got %v", got)
	}
}

// The reject alone would let the last rotation before the deadline walk out with
// a full fresh TTL and outlive the bound by a whole window. Clamping is what makes
// the stored expires_at and the cookie end at the deadline instead.
func TestRefresh_ClampsTheReissuedTokenToTheFamilyDeadline(t *testing.T) {
	const maxLifetime = 7 * 24 * time.Hour
	origin := time.Now().Add(-maxLifetime + 10*time.Minute)
	svc, repo := refreshFixture(t, maxLifetime, origin)

	res, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "UA", vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	deadline := origin.Add(maxLifetime)
	stored := repo.lastInsert(t)
	if stored.ExpiresAt.After(deadline) {
		t.Errorf("stored expires_at %v is past the family deadline %v; the session outlives its bound", stored.ExpiresAt, deadline)
	}
	if remaining := time.Duration(res.CookieMaxAge) * time.Second; remaining > 11*time.Minute {
		t.Errorf("cookie max-age %v exceeds the ~10 minutes left in the session", remaining)
	}
}

// The service must not treat "I could not find out" as "it is fine".
func TestRefresh_FailsClosedWhenTheFamilyOriginCannotBeRead(t *testing.T) {
	svc, repo := refreshFixture(t, 7*24*time.Hour, time.Time{})
	repo.originErr = errors.New("db down")

	_, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "UA", vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrSessionAgeUnknown) {
		t.Fatalf("a failed origin lookup must reject the rotation, got %v", err)
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Error("ErrSessionAgeUnknown must wrap ErrTokenInvalid so the transport answers 401, not 500")
	}
	// A transient lookup failure is not evidence of compromise, so the family
	// survives and the next refresh can succeed.
	if got := repo.revocations(); len(got) != 0 {
		t.Errorf("a lookup failure must not revoke the family, got %v", got)
	}
}

// A family that vanished between the token read and the origin read dates to the
// zero time. Zero is "unknown", never "the epoch".
func TestRefresh_FailsClosedOnAZeroFamilyOrigin(t *testing.T) {
	svc, _ := refreshFixture(t, 7*24*time.Hour, time.Time{})

	_, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "UA", vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrSessionAgeUnknown) {
		t.Fatalf("an undatable family must reject the rotation, got %v", err)
	}
}

// Configuring a bound against a store that cannot answer would otherwise be a
// silent no-op, which is the exact failure mode the bound exists to end.
func TestRefresh_FailsClosedWhenTheStoreCannotDateFamilies(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
		return storedToken("raw-refresh-token"), nil
	}
	o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) { return true, nil }
	svc.tokenSvc.SetMaxSessionLifetime(7 * 24 * time.Hour)

	if _, ok := any(o.tokenRepo).(familyOriginReader); ok {
		t.Fatal("this test needs a store that cannot date families")
	}

	_, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "UA", vaultcrypto.FingerprintInput{})
	if !errors.Is(err, ErrSessionAgeUnknown) {
		t.Fatalf("an unenforceable bound must reject rather than pass, got %v", err)
	}
}

// Zero means no bound, and no bound must mean no refusal: a deployment that has
// not configured one must not start failing refreshes because its store cannot
// date a family.
//
// The lookup itself does now happen — the origin is also the authentication
// instant a rotation states in auth_time, which is a claim a deployment gets
// whether or not it caps session age. What the absent bound removes is every
// branch that rejects, not the read.
func TestRefresh_UnboundedWhenNoLifetimeIsConfigured(t *testing.T) {
	svc, repo := refreshFixture(t, 0, time.Time{})
	repo.originErr = errors.New("family origin unavailable")

	if _, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "UA", vaultcrypto.FingerprintInput{}); err != nil {
		t.Fatalf("with no bound configured, rotation must behave exactly as before: %v", err)
	}
}

// The bound lives on the token service, so an AuthService built without one has
// no bound to enforce. NewAuthService accepts a nil token service, and the guard
// is what turns that into "unbounded" instead of a nil dereference on the first
// refresh. Rotation must also not consult the store: with nothing configured
// there is no family age to look up.
func TestEnforceSessionLifetime_UnboundedWithoutATokenService(t *testing.T) {
	svc, o := newMockAuthService(t)
	svc.tokenSvc = nil
	svc.tokens = &datedTokenRepo{
		MockRefreshTokenRepo: o.tokenRepo,
		originErr:            errors.New("the family origin must not be read when no bound is configured"),
	}

	origin, err := svc.enforceSessionLifetime(context.Background(), storedToken("raw-refresh-token"), "1.2.3.4", "UA")
	if err != nil {
		t.Fatalf("an unconfigured token service must leave rotation unbounded, got %v", err)
	}
	if !origin.IsZero() {
		t.Errorf("family origin = %v, want the zero time that means 'no deadline to clamp to'", origin)
	}
}

// --- the inactivity bound ---

// The inactivity bound lives on the same token service the absolute bound does,
// so an AuthService built without one has no bound to enforce here either.
// NewAuthService accepts a nil token service, and this guard is what turns that
// into "unbounded" rather than a nil dereference on the first refresh.
//
// storedToken carries no CreatedAt, so if the guard were removed this call would
// take the fail-closed branch and refuse — which is the right behavior when a
// bound is configured and the wrong one when none is.
func TestEnforceSessionInactivity_UnboundedWithoutATokenService(t *testing.T) {
	svc, _ := newMockAuthService(t)
	svc.tokenSvc = nil

	if err := svc.enforceSessionInactivity(context.Background(), storedToken("raw-refresh-token"), "1.2.3.4", "UA"); err != nil {
		t.Fatalf("an unconfigured token service must leave rotation unbounded, got %v", err)
	}
}

// With a token service present but no inactivity timeout set, the same row must
// still pass. This is the branch an existing deployment takes on upgrade before
// anyone sets the variable, and it is the one that would log every user out if
// a zero were read as "expire immediately".
func TestEnforceSessionInactivity_UnboundedWhenNoTimeoutIsConfigured(t *testing.T) {
	svc, _ := newMockAuthService(t)
	svc.tokenSvc.SetInactivityTimeout(0)

	if err := svc.enforceSessionInactivity(context.Background(), storedToken("raw-refresh-token"), "1.2.3.4", "UA"); err != nil {
		t.Fatalf("no configured inactivity timeout must leave rotation unbounded, got %v", err)
	}
}
