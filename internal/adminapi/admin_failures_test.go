package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// listErrAdminRepo makes the admin listing fail; fakeAdminRepo's List cannot.
type listErrAdminRepo struct{ *fakeAdminRepo }

func (r listErrAdminRepo) List(context.Context) ([]*model.AdminUser, error) {
	return nil, errors.New("db down")
}

func adminCtx(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), adminUserKey,
		&model.AdminUser{ID: "adm-1", Username: "root"}))
}

// The admin roster is what an operator reads to answer "who has access to this vault".
// An empty list returned because the database was unreachable answers that question with
// "nobody" — which is both wrong and exactly the reassurance an attacker would want them
// to have.
func TestListAdmins_DatabaseFailureIsNotAnEmptyRoster(t *testing.T) {
	h := &Handler{admins: listErrAdminRepo{newFakeAdminRepo()}}

	rec := httptest.NewRecorder()
	h.ListAdmins(rec, httptest.NewRequest(http.MethodGet, "/admin/admins", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 — a failed lookup must not read as 'there are no admins'", rec.Code)
	}
}

// Creating an admin does a uniqueness check first. If that check fails and the create
// went ahead anyway, two admins could end up sharing a username — and the login path
// looks admins up *by* username.
func TestCreateAdmin_UniquenessCheckFailureBlocksCreation(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errGetByU = errors.New("db down")

	h := &Handler{admins: repo, auditLog: audit.NewLogger(&mocks.MockAuditRepo{}, 0)}

	body := strings.NewReader(`{"username":"newadmin","password":"a-sufficiently-long-password","role":"viewer"}`)
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/admin/admins", body))
	rec := httptest.NewRecorder()

	h.CreateAdmin(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — an admin was created without confirming the username was free", rec.Code)
	}
	if len(repo.users) != 0 {
		t.Error("the admin was written despite the uniqueness check failing")
	}
}

// A create that fails at the database must not report success: the operator would walk
// away believing the new admin exists, and would find out otherwise during the next
// incident.
func TestCreateAdmin_WriteFailureIsNotReportedAsSuccess(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errCreate = errors.New("db down")

	h := &Handler{admins: repo, auditLog: audit.NewLogger(&mocks.MockAuditRepo{}, 0)}

	body := strings.NewReader(`{"username":"newadmin","password":"a-sufficiently-long-password","role":"viewer"}`)
	req := adminCtx(httptest.NewRequest(http.MethodPost, "/admin/admins", body))
	rec := httptest.NewRecorder()

	h.CreateAdmin(rec, req)

	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Fatalf("status = %d — the admin was reported created but never written", rec.Code)
	}
}

// admin_config holds the admin token hash among other things. A malformed body must be
// rejected outright rather than writing a zero value over a live setting.
func TestUpdateConfig_MalformedBodyIsRejected(t *testing.T) {
	repo := &mocks.MockAdminConfigRepo{
		SetFn: func(context.Context, string, string) error {
			t.Error("a malformed body still reached the store — it would blank the setting")
			return nil
		},
	}
	h := &Handler{adminConfig: repo, auditLog: audit.NewLogger(&mocks.MockAuditRepo{}, 0)}

	req := httptest.NewRequest(http.MethodPut, "/admin/config/admin_token_hash", strings.NewReader("not json"))
	req.SetPathValue("key", "admin_token_hash")
	rec := adminCtx(req)
	w := httptest.NewRecorder()

	h.UpdateConfig(w, rec)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// Deleting a config entry with no key names nothing. Proceeding would be a delete with an
// empty predicate, which is the shape of an accident nobody wants on a settings table.
func TestDeleteConfig_MissingKeyIsRejected(t *testing.T) {
	repo := &mocks.MockAdminConfigRepo{
		DeleteFn: func(context.Context, string) error {
			t.Error("a delete with no key reached the store")
			return nil
		},
	}
	h := &Handler{adminConfig: repo, auditLog: audit.NewLogger(&mocks.MockAuditRepo{}, 0)}

	req := httptest.NewRequest(http.MethodDelete, "/admin/config/", nil)
	req.SetPathValue("key", "")
	w := httptest.NewRecorder()

	h.DeleteConfig(w, adminCtx(req))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "missing_key") {
		t.Errorf("body = %s, want missing_key", body)
	}
}

// Admin-initiated erasure has the same rule as the self-service kind: a cascade that
// fails is a 500, not a 200. An operator running a deletion request on a user's behalf
// is the one who will tell the regulator it was done.
func TestAdminDeleteUser_ErasureFailureIsNotReportedAsDeleted(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
		SoftDeleteScrubFn: func(context.Context, string, string) error {
			return errors.New("db down")
		},
	}
	erasure := service.NewErasureService(
		users, &mocks.MockIdentityRepo{}, &mocks.MockBlobRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockSocialAccountRepo{}, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{},
		&mocks.MockAccountRecoveryRepo{}, audit.NewLogger(&mocks.MockAuditRepo{}, 0), nil, nil,
	)

	h := &Handler{
		users:    users,
		erasure:  erasure,
		auditLog: audit.NewLogger(&mocks.MockAuditRepo{}, 0),
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/users/u-1", nil)
	req.SetPathValue("id", "u-1")
	w := httptest.NewRecorder()

	h.DeleteUser(w, adminCtx(req))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — a failed erasure must not read as 'deleted'", w.Code)
	}
}

// An admin erasing an account that is already gone is a 404: nothing was destroyed, and
// the operator should not be told that it was.
func TestAdminDeleteUser_MissingUserIs404(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, nil },
	}
	erasure := service.NewErasureService(
		users, &mocks.MockIdentityRepo{}, &mocks.MockBlobRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockSocialAccountRepo{}, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{},
		&mocks.MockAccountRecoveryRepo{}, audit.NewLogger(&mocks.MockAuditRepo{}, 0), nil, nil,
	)

	h := &Handler{users: users, erasure: erasure, auditLog: audit.NewLogger(&mocks.MockAuditRepo{}, 0)}

	req := httptest.NewRequest(http.MethodDelete, "/admin/users/u-gone", nil)
	req.SetPathValue("id", "u-gone")
	w := httptest.NewRecorder()

	h.DeleteUser(w, adminCtx(req))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// SetIdentityService is how account import gets somewhere to persist a migrated marketing
// consent. Without it, import still creates accounts but drops the preference rather than
// storing one it cannot attach provenance to — so the wiring being present is what decides
// whether an imported flag is kept at all.
func TestSetIdentityService_WiresTheStore(t *testing.T) {
	h := &Handler{}
	if h.identity != nil {
		t.Fatal("identity service is set before wiring")
	}

	svc := &service.IdentityService{}
	h.SetIdentityService(svc)

	if h.identity != svc {
		t.Error("SetIdentityService did not wire the identity service")
	}
}
