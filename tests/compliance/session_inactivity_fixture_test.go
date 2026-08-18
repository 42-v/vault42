package compliance

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// The reauthentication evidence drives the refresh path that ships.
//
// Everything CR-14 covered rested on reading source text: that a symbol was
// still spelled the same way in internal/service/token.go, that a migration
// still contained a column name. Source-text assertions are the right shape for
// "this control has no mechanism" — you cannot drive a control that does not
// exist — but they are the wrong shape for "this control works", because a
// timeout that is configured, wired and never consulted passes every one of
// them.
//
// So the inactivity rows are asserted here against a real service.AuthService
// over a real service.TokenService, driving service.AuthService.Login and
// service.AuthService.Refresh, which are the two functions every session in
// the deployment goes through. The timeout is set through the same setter
// cmd/vault calls, never poked into a struct field, and the fixture never
// asserts a duration it also supplied to the code under test.
//
// Time is moved by aging the STORE, not by sleeping and not by injecting a
// clock. Rewinding a stored row's created_at is indistinguishable, to every
// line of production code, from that row having been written that long ago,
// and it leaves expires_at alone — so a refusal in these tests is the
// inactivity check refusing, never the ordinary expiry check getting there
// first. TestNIST63B4_2_2_3_AnIdleSessionIsRefusedByTheInactivityCheckItself
// pins that distinction rather than assuming it.
// =============================================================================

// sessionPassword is the one password the fixture's account accepts.
const sessionPassword = "correct-horse-battery-staple-42"

// sessionIP and sessionAgent are held constant across login and refresh so the
// device fingerprint matches and cannot be what refuses a rotation.
const (
	sessionIP    = "203.0.113.42"
	sessionAgent = "TestAgent/1.0"
)

// memRefreshRepo is the smallest refresh-token store the rotation path needs:
// insert, look up by hash, mark used, revoke. It keeps rows in a slice in
// insertion order because "the newest generation of this family" is a real
// property of the table the rotation path depends on.
//
// It also implements FamilyOrigin, which service asserts for rather than
// requiring, so the absolute session lifetime is live in these tests too. A
// fixture that could not date a family would fail closed before reaching the
// assertion under test, and the failure would look like a bug in the control.
type memRefreshRepo struct {
	mu   sync.Mutex
	rows []*model.RefreshToken
}

func (r *memRefreshRepo) Create(_ context.Context, token *model.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.FamilyID == token.FamilyID && row.Revoked {
			return repository.ErrFamilyRevoked
		}
	}
	copied := *token
	// family_created_at semantics: the family's birth date is inherited from its
	// first row and a rotation can never move it. The production INSERT does this
	// inside the statement; here the equivalent is that FamilyOrigin reads the
	// oldest row's CreatedAt and nothing writes it separately.
	r.rows = append(r.rows, &copied)
	return nil
}

func (r *memRefreshRepo) CreateWithinCap(ctx context.Context, token *model.RefreshToken, _ int) error {
	return r.Create(ctx, token)
}

func (r *memRefreshRepo) GetByTokenHash(_ context.Context, hash string) (*model.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.TokenHash == hash {
			copied := *row
			return &copied, nil
		}
	}
	return nil, nil
}

func (r *memRefreshRepo) MarkUsed(_ context.Context, id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.ID == id && !row.Used && !row.Revoked {
			row.Used = true
			return true, nil
		}
	}
	return false, nil
}

func (r *memRefreshRepo) RevokeByID(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.ID == id {
			row.Revoked = true
		}
	}
	return nil
}

func (r *memRefreshRepo) RevokeByDeviceID(_ context.Context, deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.DeviceID == deviceID {
			row.Revoked = true
		}
	}
	return nil
}

func (r *memRefreshRepo) RevokeFamily(_ context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.FamilyID == familyID {
			row.Revoked = true
		}
	}
	return nil
}

func (r *memRefreshRepo) RevokeAllForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.UserID == userID {
			row.Revoked = true
		}
	}
	return nil
}

func (r *memRefreshRepo) DeleteAllForUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.rows[:0]
	for _, row := range r.rows {
		if row.UserID != userID {
			kept = append(kept, row)
		}
	}
	r.rows = kept
	return nil
}

func (r *memRefreshRepo) RevokeAll(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		row.Revoked = true
	}
	return nil
}

// active reports whether a row is one CountActiveFamilies would count: not
// revoked, not spent, and not past its expiry. The three conditions are the
// production definition, and the expiry one is why the inactivity clamp on
// issuance matters — see TestNIST63B4_2_2_3_AnIdleSessionStopsHoldingItsSlot.
func (r *memRefreshRepo) active(row *model.RefreshToken, now time.Time) bool {
	return !row.Revoked && !row.Used && row.ExpiresAt.After(now)
}

func (r *memRefreshRepo) CountActiveFamilies(_ context.Context, userID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	families := map[string]struct{}{}
	for _, row := range r.rows {
		if row.UserID == userID && r.active(row, now) {
			families[row.FamilyID] = struct{}{}
		}
	}
	return len(families), nil
}

func (r *memRefreshRepo) ListActiveFamilies(_ context.Context, userID string) ([]*repository.ActiveFamily, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	seen := map[string]*repository.ActiveFamily{}
	order := []string{}
	for _, row := range r.rows {
		if row.UserID != userID || !r.active(row, now) {
			continue
		}
		if _, ok := seen[row.FamilyID]; !ok {
			seen[row.FamilyID] = &repository.ActiveFamily{FamilyID: row.FamilyID, ClientID: row.ClientID}
			order = append(order, row.FamilyID)
		}
		// LastUsedAt is the newest live generation's created_at, which is the
		// same fact enforceSessionInactivity measures against.
		f := seen[row.FamilyID]
		f.DeviceID = row.DeviceID
		f.LastUsedAt = row.CreatedAt
		f.ExpiresAt = row.ExpiresAt
	}
	out := make([]*repository.ActiveFamily, 0, len(order))
	for _, id := range order {
		out = append(out, seen[id])
	}
	return out, nil
}

func (r *memRefreshRepo) DeleteExpired(_ context.Context) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	kept, removed := r.rows[:0], int64(0)
	for _, row := range r.rows {
		if (row.Used || row.Revoked) && !row.ExpiresAt.After(now) {
			removed++
			continue
		}
		kept = append(kept, row)
	}
	r.rows = kept
	return removed, nil
}

// FamilyOrigin is the optional capability the absolute session lifetime asserts
// for. The origin is the oldest row's created_at, which is what
// MIN(family_created_at) resolves to once the column has been inherited down
// the family.
func (r *memRefreshRepo) FamilyOrigin(_ context.Context, familyID string) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var origin time.Time
	for _, row := range r.rows {
		if row.FamilyID != familyID {
			continue
		}
		if origin.IsZero() || row.CreatedAt.Before(origin) {
			origin = row.CreatedAt
		}
	}
	return origin, nil
}

// age moves every stored row back by d, which is indistinguishable from d
// having elapsed since they were written. created_at moves; expires_at does
// not, so the ordinary expiry check cannot be what refuses.
func (r *memRefreshRepo) age(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		row.CreatedAt = row.CreatedAt.Add(-d)
	}
}

// ageEverything moves created_at AND expires_at back, which is what genuinely
// elapsed time does. Used only where the test needs a row that is idle and
// expired at once.
func (r *memRefreshRepo) ageEverything(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		row.CreatedAt = row.CreatedAt.Add(-d)
		row.ExpiresAt = row.ExpiresAt.Add(-d)
	}
}

// clearIssuanceInstants blanks created_at on every row, which is the state a
// store that has stopped reporting the column would hand the refresh path. The
// column is NOT NULL in the schema, so this is not a row shape Postgres can
// produce — it is the store-level failure the fail-closed branch exists for.
func (r *memRefreshRepo) clearIssuanceInstants() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		row.CreatedAt = time.Time{}
	}
}

func (r *memRefreshRepo) familyRevoked(familyID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.FamilyID == familyID && !row.Revoked {
			return false
		}
	}
	return true
}

// sessionFixture is a real AuthService and TokenService over the store above.
type sessionFixture struct {
	svc      *service.AuthService
	tokens   *memRefreshRepo
	tokenSvc *service.TokenService

	mu     sync.Mutex
	events []*model.AuditEntry
}

// newSessionFixture builds the service with the bounds a caller wants, set
// through the setters cmd/vault calls and nowhere else.
//
// accessTTL is a parameter because the relationship between it and the
// inactivity window is the whole reason the window is measured in hours: a
// fixture that quietly used a 15-minute access TTL against a 15-minute idle
// bound would be testing a misconfiguration.
func newSessionFixture(t *testing.T, accessTTL, refreshTTL, maxLifetime, idleTimeout time.Duration) *sessionFixture {
	t.Helper()

	hash, err := vaultcrypto.HashPassword(sessionPassword)
	if err != nil {
		t.Fatalf("hash the fixture password: %v", err)
	}
	user := &model.User{
		ID: "00000000-0000-0000-0000-0000000000aa", Email: "session@example.com",
		PasswordHash: hash, EmailVerified: true, Roles: []string{"user"},
	}
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			if email != user.Email {
				return nil, nil
			}
			copied := *user
			return &copied, nil
		},
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			if id != user.ID {
				return nil, nil
			}
			copied := *user
			return &copied, nil
		},
	}

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate the fixture signing key: %v", err)
	}
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("generate the fixture kid: %v", err)
	}
	tokenSvc := service.NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		accessTTL, refreshTTL, refreshTTL)
	tokenSvc.SetMaxSessionLifetime(maxLifetime)
	tokenSvc.SetInactivityTimeout(idleTimeout)

	f := &sessionFixture{tokens: &memRefreshRepo{}, tokenSvc: tokenSvc}

	c := cache.NewMemoryCache()
	f.svc = service.NewAuthService(
		users, f.tokens, &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil,
		audit.NewLogger(&mocks.MockAuditRepo{InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, e)
			return nil
		}}, 0),
		service.NewHIBPClient(), c, &mocks.MockEmailSender{},
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
	t.Cleanup(func() { _ = c.Close() })
	return f
}

// login runs the real login path and returns the refresh token it issued.
func (f *sessionFixture) login(t *testing.T) *service.LoginResult {
	t.Helper()
	res, err := f.svc.Login(context.Background(),
		service.LoginInput{Email: "session@example.com", Password: sessionPassword},
		sessionIP, sessionAgent)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.RefreshToken == "" {
		t.Fatal("login issued no refresh token; the fixture has nothing to rotate")
	}
	return res
}

// refresh runs the real rotation path.
func (f *sessionFixture) refresh(token string) (*service.RefreshResult, error) {
	return f.svc.Refresh(context.Background(), token, sessionIP, sessionAgent,
		vaultcrypto.FingerprintInput{})
}

// familyOf returns the family the given refresh token belongs to.
func (f *sessionFixture) familyOf(t *testing.T, token string) string {
	t.Helper()
	row, err := f.tokens.GetByTokenHash(context.Background(), vaultcrypto.SHA256Hex(token))
	if err != nil || row == nil {
		t.Fatalf("the fixture store does not hold the token just issued (err=%v)", err)
	}
	return row.FamilyID
}

// auditReasons returns the "reason" metadata of every audit entry recorded so
// far, so a test can assert what the operator would see rather than only what
// the caller was told.
func (f *sessionFixture) auditReasons() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, e := range f.events {
		if reason, ok := e.Metadata["reason"].(string); ok {
			out = append(out, reason)
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
