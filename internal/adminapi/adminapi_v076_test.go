package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Local stateful mocks for the two admin repos that have no shared mock in
// tests/mocks. These live here (white-box package) so the coverage attributed
// to `go test ./internal/adminapi/` includes the handler/auth/middleware paths
// they drive. Each supports per-test error injection via the err* fields.
// ---------------------------------------------------------------------------

type fakeAdminRepo struct {
	users      map[string]*model.AdminUser
	failed     map[string]int
	errGetByID error
	errGetByU  error
	errCreate  error
	errUpdate  error
	errRevoke  error
	errIncr    error
}

func newFakeAdminRepo() *fakeAdminRepo {
	return &fakeAdminRepo{users: map[string]*model.AdminUser{}, failed: map[string]int{}}
}

func (m *fakeAdminRepo) Create(_ context.Context, u *model.AdminUser) error {
	if m.errCreate != nil {
		return m.errCreate
	}
	m.users[u.ID] = u
	return nil
}

func (m *fakeAdminRepo) GetByID(_ context.Context, id string) (*model.AdminUser, error) {
	if m.errGetByID != nil {
		return nil, m.errGetByID
	}
	u := m.users[id]
	if u == nil {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (m *fakeAdminRepo) GetByUsername(_ context.Context, username string) (*model.AdminUser, error) {
	if m.errGetByU != nil {
		return nil, m.errGetByU
	}
	for _, u := range m.users {
		if u.Username == username {
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *fakeAdminRepo) List(_ context.Context) ([]*model.AdminUser, error) {
	out := make([]*model.AdminUser, 0, len(m.users))
	for _, u := range m.users {
		cp := *u
		out = append(out, &cp)
	}
	return out, nil
}

func (m *fakeAdminRepo) Count(_ context.Context) (int, error) { return len(m.users), nil }

func (m *fakeAdminRepo) Update(_ context.Context, u *model.AdminUser) error {
	if m.errUpdate != nil {
		return m.errUpdate
	}
	m.users[u.ID] = u
	return nil
}

func (m *fakeAdminRepo) IncrementFailedLogin(_ context.Context, id string) (int, error) {
	if m.errIncr != nil {
		return 0, m.errIncr
	}
	m.failed[id]++
	if u, ok := m.users[id]; ok {
		u.FailedLoginCount = m.failed[id]
	}
	return m.failed[id], nil
}

func (m *fakeAdminRepo) ResetFailedLogin(_ context.Context, id string) error {
	m.failed[id] = 0
	return nil
}

func (m *fakeAdminRepo) LockUntil(_ context.Context, id string, until time.Time) error {
	if u, ok := m.users[id]; ok {
		u.LockedUntil = &until
	}
	return nil
}

func (m *fakeAdminRepo) UpdateLastTOTPCounter(_ context.Context, id string, c int64) error {
	if u, ok := m.users[id]; ok {
		u.LastTOTPCounter = c
	}
	return nil
}

func (m *fakeAdminRepo) UpdateLastLogin(_ context.Context, id string) error {
	if u, ok := m.users[id]; ok {
		now := time.Now()
		u.LastLoginAt = &now
	}
	return nil
}

func (m *fakeAdminRepo) Revoke(_ context.Context, id string) error {
	if m.errRevoke != nil {
		return m.errRevoke
	}
	delete(m.users, id)
	return nil
}

var _ repository.AdminUserRepository = (*fakeAdminRepo)(nil)

type fakeSessionRepo struct {
	sessions  map[string]*model.AdminSession
	errCreate error
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{sessions: map[string]*model.AdminSession{}}
}

func (m *fakeSessionRepo) Create(_ context.Context, s *model.AdminSession) error {
	if m.errCreate != nil {
		return m.errCreate
	}
	m.sessions[s.ID] = s
	return nil
}

func (m *fakeSessionRepo) GetByTokenHash(_ context.Context, hash string) (*model.AdminSession, error) {
	for _, s := range m.sessions {
		if s.TokenHash == hash {
			cp := *s
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *fakeSessionRepo) ListByAdmin(_ context.Context, adminID string) ([]*model.AdminSession, error) {
	return nil, nil
}

func (m *fakeSessionRepo) ListActive(_ context.Context) ([]*model.AdminSession, error) {
	return nil, nil
}

func (m *fakeSessionRepo) Revoke(_ context.Context, id string) error {
	if s, ok := m.sessions[id]; ok {
		s.Revoked = true
	}
	return nil
}

func (m *fakeSessionRepo) RevokeAllForAdmin(_ context.Context, adminID string) error { return nil }
func (m *fakeSessionRepo) RevokeAll(_ context.Context) error                         { return nil }
func (m *fakeSessionRepo) DeleteExpired(_ context.Context) (int64, error)            { return 0, nil }

var _ repository.AdminSessionRepository = (*fakeSessionRepo)(nil)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

func testAuditLog() *audit.Logger {
	return audit.NewLogger(&mocks.MockAuditRepo{}, time.Hour)
}

// newTestHandler wires a Handler from injectable mocks. keyStore stays nil; the
// key endpoints are exercised elsewhere via their 503 branch.
func newTestHandler(admins repository.AdminUserRepository, users repository.UserRepository,
	clients repository.ClientRepository, auditRepo repository.AuditRepository) *Handler {
	if users == nil {
		users = &mocks.MockUserRepo{}
	}
	if clients == nil {
		clients = &mocks.MockClientRepo{}
	}
	if auditRepo == nil {
		auditRepo = &mocks.MockAuditRepo{}
	}
	if admins == nil {
		admins = newFakeAdminRepo()
	}
	return NewHandler(users, clients, &mocks.MockRefreshTokenRepo{}, auditRepo,
		admins, newFakeSessionRepo(), &mocks.MockAdminConfigRepo{}, nil,
		testAuditLog(), make([]byte, 32), "")
}

// withActor attaches an authenticated super_admin actor so handlers that call
// GetAdmin for the audit log don't nil-deref.
func withActor(r *http.Request) *http.Request {
	return r.WithContext(WithAdmin(r.Context(), &model.AdminUser{
		ID: "00000000-0000-0000-0000-000000000099", Username: "actor", Role: string(rbac.RoleSuperAdmin),
	}))
}

func jsonReq(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// ---------------------------------------------------------------------------
// ListUsers — error branches on repo lookup
// ---------------------------------------------------------------------------

func TestListUsers_UUIDLookupError500(t *testing.T) {
	users := &mocks.MockUserRepo{GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
		return nil, errors.New("db down")
	}}
	h := newTestHandler(nil, users, nil, nil)
	rec := httptest.NewRecorder()
	h.ListUsers(rec, httptest.NewRequest(http.MethodGet, "/admin/users?q=00000000-0000-0000-0000-000000000001", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestListUsers_EmailLookupHit(t *testing.T) {
	users := &mocks.MockUserRepo{GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
		return &model.User{ID: "u1", Email: "a@b.c", EmailVerified: true}, nil
	}}
	h := newTestHandler(nil, users, nil, nil)
	rec := httptest.NewRecorder()
	h.ListUsers(rec, httptest.NewRequest(http.MethodGet, "/admin/users?q=a@b.c", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "a@b.c") {
		t.Fatalf("body should contain matched user: %s", rec.Body.String())
	}
}

func TestListUsers_EmailLookupError500(t *testing.T) {
	users := &mocks.MockUserRepo{GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
		return nil, errors.New("db down")
	}}
	h := newTestHandler(nil, users, nil, nil)
	rec := httptest.NewRecorder()
	h.ListUsers(rec, httptest.NewRequest(http.MethodGet, "/admin/users?q=a@b.c", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// QueryAudit — filter parsing + repo error
// ---------------------------------------------------------------------------

func TestQueryAudit_ParsesFiltersAndReturnsEntries(t *testing.T) {
	var captured repository.AuditFilter
	auditRepo := &mocks.MockAuditRepo{QueryFn: func(_ context.Context, f repository.AuditFilter) ([]*model.AuditEntry, error) {
		captured = f
		return []*model.AuditEntry{{ID: "e1"}}, nil
	}}
	h := newTestHandler(nil, nil, nil, auditRepo)
	rec := httptest.NewRecorder()
	target := "/admin/audit?limit=10&offset=5&user_id=u1&event_type=login" +
		"&since=2020-01-01T00:00:00Z&until=2021-01-01T00:00:00Z"
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if captured.Limit != 10 || captured.Offset != 5 || captured.UserID != "u1" || captured.EventType != "login" {
		t.Fatalf("filter not parsed: %+v", captured)
	}
	if captured.Since == nil || captured.Until == nil {
		t.Fatalf("since/until not parsed: %+v", captured)
	}
}

func TestQueryAudit_IgnoresInvalidLimitAndTime(t *testing.T) {
	var captured repository.AuditFilter
	auditRepo := &mocks.MockAuditRepo{QueryFn: func(_ context.Context, f repository.AuditFilter) ([]*model.AuditEntry, error) {
		captured = f
		return nil, nil
	}}
	h := newTestHandler(nil, nil, nil, auditRepo)
	rec := httptest.NewRecorder()
	// limit out of range (>500), garbage offset, unparsable since → all defaults kept.
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit?limit=9999&offset=abc&since=notatime", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if captured.Limit != 50 || captured.Offset != 0 || captured.Since != nil {
		t.Fatalf("invalid params should be ignored, got %+v", captured)
	}
}

func TestQueryAudit_RepoError500(t *testing.T) {
	auditRepo := &mocks.MockAuditRepo{QueryFn: func(_ context.Context, _ repository.AuditFilter) ([]*model.AuditEntry, error) {
		return nil, errors.New("query failed")
	}}
	h := newTestHandler(nil, nil, nil, auditRepo)
	rec := httptest.NewRecorder()
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateClient — validation + success
// ---------------------------------------------------------------------------

func TestCreateClient_MissingName400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.CreateClient(rec, withActor(jsonReq(http.MethodPost, "/admin/clients", `{"role":"viewer"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCreateClient_SuccessReturnsSecret(t *testing.T) {
	var created *model.Client
	clients := &mocks.MockClientRepo{CreateFn: func(_ context.Context, c *model.Client) error {
		created = c
		return nil
	}}
	h := newTestHandler(nil, nil, clients, nil)
	rec := httptest.NewRecorder()
	h.CreateClient(rec, withActor(jsonReq(http.MethodPost, "/admin/clients",
		`{"name":"svc","role":"viewer","scopes":["read"]}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	if created == nil || created.Name != "svc" || created.SecretHash == "" {
		t.Fatalf("client not created with hashed secret: %+v", created)
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["secret"] == "" {
		t.Fatal("response should include plaintext secret once")
	}
}

func TestCreateClient_RepoError500(t *testing.T) {
	clients := &mocks.MockClientRepo{CreateFn: func(_ context.Context, _ *model.Client) error {
		return errors.New("insert failed")
	}}
	h := newTestHandler(nil, nil, clients, nil)
	rec := httptest.NewRecorder()
	h.CreateClient(rec, withActor(jsonReq(http.MethodPost, "/admin/clients", `{"name":"svc"}`)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RotateClientSecret — found path + update error
// ---------------------------------------------------------------------------

func TestRotateClientSecret_SuccessRotatesHash(t *testing.T) {
	existing := &model.Client{ID: "c1", Name: "svc", SecretHash: "old"}
	var updated *model.Client
	clients := &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.Client, error) { return existing, nil },
		UpdateFn:  func(_ context.Context, c *model.Client) error { updated = c; return nil },
	}
	h := newTestHandler(nil, nil, clients, nil)
	r := withActor(httptest.NewRequest(http.MethodPost, "/admin/clients/c1/rotate", nil))
	r.SetPathValue("id", "c1")
	rec := httptest.NewRecorder()
	h.RotateClientSecret(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if updated == nil || updated.SecretHash == "old" || updated.SecretHash == "" {
		t.Fatalf("secret hash not rotated: %+v", updated)
	}
}

func TestRotateClientSecret_UpdateError500(t *testing.T) {
	clients := &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, _ string) (*model.Client, error) {
			return &model.Client{ID: "c1"}, nil
		},
		UpdateFn: func(_ context.Context, _ *model.Client) error { return errors.New("update failed") },
	}
	h := newTestHandler(nil, nil, clients, nil)
	r := withActor(httptest.NewRequest(http.MethodPost, "/admin/clients/c1/rotate", nil))
	r.SetPathValue("id", "c1")
	rec := httptest.NewRecorder()
	h.RotateClientSecret(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestRotateClientSecret_MissingID400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.RotateClientSecret(rec, withActor(httptest.NewRequest(http.MethodPost, "/admin/clients//rotate", nil)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateAdmin — validation, conflict, success
// ---------------------------------------------------------------------------

func TestCreateAdmin_MissingFields400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins", `{"username":"x"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCreateAdmin_InvalidRole400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"username":"x","password":"aVeryLongPassword12345","role":"wizard"}`
	h.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins", body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateAdmin_ShortPassword400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"username":"x","password":"short","role":"viewer"}`
	h.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins", body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCreateAdmin_UsernameExists409(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.users["existing"] = &model.AdminUser{ID: "existing", Username: "taken"}
	h := newTestHandler(repo, nil, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"username":"taken","password":"aVeryLongPassword12345","role":"viewer"}`
	h.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins", body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateAdmin_Success201(t *testing.T) {
	repo := newFakeAdminRepo()
	h := newTestHandler(repo, nil, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"username":"newadmin","password":"aVeryLongPassword12345","role":"viewer"}`
	h.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins", body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	if len(repo.users) != 1 {
		t.Fatalf("admin not persisted, count=%d", len(repo.users))
	}
}

func TestCreateAdmin_LookupError500(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errGetByU = errors.New("db down")
	h := newTestHandler(repo, nil, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"username":"x","password":"aVeryLongPassword12345","role":"viewer"}`
	h.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins", body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// AuthHandler builders
// ---------------------------------------------------------------------------

func newTestAuth(admins repository.AdminUserRepository, sessions repository.AdminSessionRepository) *AuthHandler {
	if admins == nil {
		admins = newFakeAdminRepo()
	}
	if sessions == nil {
		sessions = newFakeSessionRepo()
	}
	return NewAuthHandler(admins, sessions, testAuditLog(), make([]byte, 32), "", time.Hour, 3, time.Hour)
}

// seedAdmin inserts an admin whose password hash matches password.
func seedAdmin(t *testing.T, repo *fakeAdminRepo, username, password string) *model.AdminUser {
	t.Helper()
	hash, err := vaultcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	a := &model.AdminUser{ID: "admin-" + username, Username: username, PasswordHash: hash, Role: "viewer"}
	repo.users[a.ID] = a
	return a
}

// ---------------------------------------------------------------------------
// Login — denial / error branches (happy path is covered elsewhere)
// ---------------------------------------------------------------------------

func TestLogin_UnknownUser401(t *testing.T) {
	h := newTestAuth(nil, nil)
	rec := httptest.NewRecorder()
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login", `{"username":"nobody","password":"whatever-long-pw"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestLogin_LookupError500(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errGetByU = errors.New("db down")
	h := newTestAuth(repo, nil)
	rec := httptest.NewRecorder()
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login", `{"username":"x","password":"long-enough-pw"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestLogin_AccountLocked401(t *testing.T) {
	repo := newFakeAdminRepo()
	a := seedAdmin(t, repo, "locked", "correct-password-123")
	until := time.Now().Add(time.Hour)
	a.LockedUntil = &until
	h := newTestAuth(repo, nil)
	rec := httptest.NewRecorder()
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login", `{"username":"locked","password":"correct-password-123"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (locked)", rec.Code)
	}
}

func TestLogin_WrongPassword401(t *testing.T) {
	repo := newFakeAdminRepo()
	seedAdmin(t, repo, "real", "correct-password-123")
	h := newTestAuth(repo, nil)
	rec := httptest.NewRecorder()
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login", `{"username":"real","password":"wrong-password-000"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if repo.failed["admin-real"] == 0 {
		t.Fatal("failed login should have been recorded")
	}
}

func TestLogin_TOTPRequiredButMissing401(t *testing.T) {
	repo := newFakeAdminRepo()
	a := seedAdmin(t, repo, "mfa", "correct-password-123")
	enc, err := encryptTOTPSecret("JBSWY3DPEHPK3PXP", make([]byte, 32), a.ID)
	if err != nil {
		t.Fatalf("enc: %v", err)
	}
	a.TOTPSecretEnc = enc
	a.TOTPVerified = true
	h := newTestAuth(repo, nil)
	rec := httptest.NewRecorder()
	// Correct password but no TOTP code → uniform 401 (no oracle).
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login", `{"username":"mfa","password":"correct-password-123"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (TOTP missing)", rec.Code)
	}
}

func TestLogin_TOTPWrongCode401(t *testing.T) {
	repo := newFakeAdminRepo()
	a := seedAdmin(t, repo, "mfa2", "correct-password-123")
	enc, _ := encryptTOTPSecret("JBSWY3DPEHPK3PXP", make([]byte, 32), a.ID)
	a.TOTPSecretEnc = enc
	a.TOTPVerified = true
	h := newTestAuth(repo, nil)
	rec := httptest.NewRecorder()
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login",
		`{"username":"mfa2","password":"correct-password-123","totp_code":"000000"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (bad TOTP)", rec.Code)
	}
}

func TestLogin_TOTPSuccessIssuesSession(t *testing.T) {
	repo := newFakeAdminRepo()
	key := make([]byte, 32)
	secret := "JBSWY3DPEHPK3PXP"
	a := seedAdmin(t, repo, "mfa3", "correct-password-123")
	enc, _ := encryptTOTPSecret(secret, key, a.ID)
	a.TOTPSecretEnc = enc
	a.TOTPVerified = true
	code, err := vaultcrypto.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	sessions := newFakeSessionRepo()
	h := newTestAuth(repo, sessions)
	rec := httptest.NewRecorder()
	body := `{"username":"mfa3","password":"correct-password-123","totp_code":"` + code + `"}`
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if len(sessions.sessions) != 1 {
		t.Fatalf("expected one session created, got %d", len(sessions.sessions))
	}
}

func TestLogin_SessionCreateError500(t *testing.T) {
	repo := newFakeAdminRepo()
	seedAdmin(t, repo, "noverify", "correct-password-123")
	sessions := newFakeSessionRepo()
	sessions.errCreate = errors.New("session insert failed")
	h := newTestAuth(repo, sessions)
	rec := httptest.NewRecorder()
	// No TOTP configured → skips TOTP block, fails at session create.
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login", `{"username":"noverify","password":"correct-password-123"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestLogin_LockoutAfterMaxFailures(t *testing.T) {
	repo := newFakeAdminRepo()
	a := seedAdmin(t, repo, "lockme", "correct-password-123")
	h := newTestAuth(repo, nil) // maxFailed = 3
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login", `{"username":"lockme","password":"bad-password-here"}`))
	}
	if repo.users[a.ID].LockedUntil == nil {
		t.Fatal("account should be locked after reaching maxFailed")
	}
}

// ---------------------------------------------------------------------------
// TOTPSetup — denial branches + success
// ---------------------------------------------------------------------------

func TestTOTPSetup_NoAdmin401(t *testing.T) {
	h := newTestAuth(nil, nil)
	rec := httptest.NewRecorder()
	h.TOTPSetup(rec, httptest.NewRequest(http.MethodPost, "/admin/admins/me/totp/setup", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestTOTPSetup_AlreadyConfigured409(t *testing.T) {
	repo := newFakeAdminRepo()
	a := &model.AdminUser{ID: "a1", Username: "x", TOTPVerified: true}
	repo.users[a.ID] = a
	h := newTestAuth(repo, nil)
	r := httptest.NewRequest(http.MethodPost, "/admin/admins/me/totp/setup", nil)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPSetup(rec, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestTOTPSetup_UpdateError500(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errUpdate = errors.New("update failed")
	a := &model.AdminUser{ID: "a1", Username: "x"}
	repo.users[a.ID] = a
	h := newTestAuth(repo, nil)
	r := httptest.NewRequest(http.MethodPost, "/admin/admins/me/totp/setup", nil)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPSetup(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// TOTPVerify — denial branches + success
// ---------------------------------------------------------------------------

func TestTOTPVerify_NoAdmin401(t *testing.T) {
	h := newTestAuth(nil, nil)
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, httptest.NewRequest(http.MethodPost, "/admin/admins/me/totp/verify", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestTOTPVerify_AlreadyVerified409(t *testing.T) {
	h := newTestAuth(nil, nil)
	a := &model.AdminUser{ID: "a1", TOTPVerified: true}
	r := jsonReq(http.MethodPost, "/admin/admins/me/totp/verify", `{"code":"123456"}`)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestTOTPVerify_NotSetUp400(t *testing.T) {
	h := newTestAuth(nil, nil)
	a := &model.AdminUser{ID: "a1"} // no TOTPSecretEnc
	r := jsonReq(http.MethodPost, "/admin/admins/me/totp/verify", `{"code":"123456"}`)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (not setup)", rec.Code)
	}
}

func TestTOTPVerify_WrongCode401(t *testing.T) {
	key := make([]byte, 32)
	a := &model.AdminUser{ID: "a1"}
	enc, _ := encryptTOTPSecret("JBSWY3DPEHPK3PXP", key, a.ID)
	a.TOTPSecretEnc = enc
	h := newTestAuth(nil, nil)
	r := jsonReq(http.MethodPost, "/admin/admins/me/totp/verify", `{"code":"000000"}`)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (wrong code)", rec.Code)
	}
}

func TestTOTPVerify_Success(t *testing.T) {
	repo := newFakeAdminRepo()
	key := make([]byte, 32)
	secret := "JBSWY3DPEHPK3PXP"
	a := &model.AdminUser{ID: "a1", Username: "x"}
	enc, _ := encryptTOTPSecret(secret, key, a.ID)
	a.TOTPSecretEnc = enc
	repo.users[a.ID] = a
	code, _ := vaultcrypto.GenerateTOTPCode(secret, time.Now())
	h := newTestAuth(repo, nil)
	r := jsonReq(http.MethodPost, "/admin/admins/me/totp/verify", `{"code":"`+code+`"}`)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !repo.users[a.ID].TOTPVerified {
		t.Fatal("admin should be marked TOTP-verified")
	}
}

// ---------------------------------------------------------------------------
// EnsureFirstAdmin — count error path
// ---------------------------------------------------------------------------

func TestEnsureFirstAdmin_CountErrorPropagates(t *testing.T) {
	repo := &countErrAdminRepo{fakeAdminRepo: newFakeAdminRepo()}
	if err := EnsureFirstAdmin(context.Background(), repo, ""); err == nil {
		t.Fatal("expected error when Count fails")
	}
}

func TestEnsureFirstAdmin_CreateErrorPropagates(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errCreate = errors.New("insert failed")
	if err := EnsureFirstAdmin(context.Background(), repo, ""); err == nil {
		t.Fatal("expected error when Create fails")
	}
}

// countErrAdminRepo forces Count to fail.
type countErrAdminRepo struct{ *fakeAdminRepo }

func (c *countErrAdminRepo) Count(_ context.Context) (int, error) {
	return 0, errors.New("count failed")
}

// ---------------------------------------------------------------------------
// SessionAuth — revoked / expired / admin-not-found / locked / 2FA branches
// ---------------------------------------------------------------------------

func sessionAuthHandler(sessions repository.AdminSessionRepository, admins repository.AdminUserRepository) http.Handler {
	return SessionAuth(sessions, admins)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// authedRequest builds a request whose bearer token resolves to session.
func authedRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestSessionAuth_RevokedSession401(t *testing.T) {
	sessions := newFakeSessionRepo()
	token := "tok-revoked"
	sessions.sessions["s1"] = &model.AdminSession{
		ID: "s1", AdminID: "a1", TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour), Revoked: true,
	}
	rec := httptest.NewRecorder()
	sessionAuthHandler(sessions, newFakeAdminRepo()).ServeHTTP(rec, authedRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (revoked)", rec.Code)
	}
}

func TestSessionAuth_ExpiredSession401(t *testing.T) {
	sessions := newFakeSessionRepo()
	token := "tok-expired"
	sessions.sessions["s1"] = &model.AdminSession{
		ID: "s1", AdminID: "a1", TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	rec := httptest.NewRecorder()
	sessionAuthHandler(sessions, newFakeAdminRepo()).ServeHTTP(rec, authedRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (expired)", rec.Code)
	}
}

func TestSessionAuth_AdminNotFound401(t *testing.T) {
	sessions := newFakeSessionRepo()
	token := "tok-orphan"
	sessions.sessions["s1"] = &model.AdminSession{
		ID: "s1", AdminID: "missing", TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	rec := httptest.NewRecorder()
	sessionAuthHandler(sessions, newFakeAdminRepo()).ServeHTTP(rec, authedRequest(token))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (admin not found)", rec.Code)
	}
}

func TestSessionAuth_AdminLocked403(t *testing.T) {
	sessions := newFakeSessionRepo()
	admins := newFakeAdminRepo()
	until := time.Now().Add(time.Hour)
	admins.users["a1"] = &model.AdminUser{ID: "a1", LockedUntil: &until, TOTPVerified: true}
	token := "tok-locked"
	sessions.sessions["s1"] = &model.AdminSession{
		ID: "s1", AdminID: "a1", TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	rec := httptest.NewRecorder()
	sessionAuthHandler(sessions, admins).ServeHTTP(rec, authedRequest(token))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (locked)", rec.Code)
	}
}

func TestSessionAuth_2FARequiredOnProtectedPath403(t *testing.T) {
	sessions := newFakeSessionRepo()
	admins := newFakeAdminRepo()
	admins.users["a1"] = &model.AdminUser{ID: "a1", TOTPVerified: false}
	token := "tok-no2fa"
	sessions.sessions["s1"] = &model.AdminSession{
		ID: "s1", AdminID: "a1", TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	// /admin/keys is not a TOTP setup path → blocked.
	rec := httptest.NewRecorder()
	sessionAuthHandler(sessions, admins).ServeHTTP(rec, authedRequest(token))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (2fa required)", rec.Code)
	}
}

func TestSessionAuth_2FAUnverifiedAllowedOnSetupPath(t *testing.T) {
	sessions := newFakeSessionRepo()
	admins := newFakeAdminRepo()
	admins.users["a1"] = &model.AdminUser{ID: "a1", TOTPVerified: false}
	token := "tok-setup"
	sessions.sessions["s1"] = &model.AdminSession{
		ID: "s1", AdminID: "a1", TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	r := httptest.NewRequest(http.MethodPost, "/admin/admins/me/totp/setup", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	sessionAuthHandler(sessions, admins).ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (setup path allowed pre-2FA)", rec.Code)
	}
}

func TestSessionAuth_HappyPathLoadsAdmin(t *testing.T) {
	sessions := newFakeSessionRepo()
	admins := newFakeAdminRepo()
	admins.users["a1"] = &model.AdminUser{ID: "a1", TOTPVerified: true}
	token := "tok-good"
	sessions.sessions["s1"] = &model.AdminSession{
		ID: "s1", AdminID: "a1", TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	var sawAdmin *model.AdminUser
	mw := SessionAuth(sessions, admins)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAdmin = GetAdmin(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, authedRequest(token))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if sawAdmin == nil || sawAdmin.ID != "a1" {
		t.Fatal("admin should be loaded into context")
	}
}

// ---------------------------------------------------------------------------
// LocalOnly — dev-mode 403 with audit insert
// ---------------------------------------------------------------------------

func TestLocalOnly_DevModeAuditsAndForbids(t *testing.T) {
	var inserted *model.AuditEntry
	auditRepo := &mocks.MockAuditRepo{InsertFn: func(_ context.Context, e *model.AuditEntry) error {
		inserted = e
		return nil
	}}
	h := LocalOnly(false, auditRepo)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	r.RemoteAddr = "10.0.0.5:9999"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if inserted == nil || inserted.RiskScore != 100 {
		t.Fatalf("expected a high-risk audit entry, got %+v", inserted)
	}
}

func TestLocalOnly_MalformedRemoteAddrForbidden(t *testing.T) {
	h := LocalOnly(false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	r.RemoteAddr = "not-an-address" // SplitHostPort fails → falls back to whole string, not loopback
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
