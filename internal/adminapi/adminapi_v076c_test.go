package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// GetUser — missing id, repo error, not found, success
// ---------------------------------------------------------------------------

func TestGetUser_MissingID400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.GetUser(rec, httptest.NewRequest(http.MethodGet, "/admin/users/", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestGetUser_RepoError500(t *testing.T) {
	users := &mocks.MockUserRepo{GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
		return nil, errors.New("db down")
	}}
	h := newTestHandler(nil, users, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/admin/users/u1", nil)
	r.SetPathValue("id", "u1")
	rec := httptest.NewRecorder()
	h.GetUser(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestGetUser_NotFound404(t *testing.T) {
	users := &mocks.MockUserRepo{GetByIDFn: func(_ context.Context, _ string) (*model.User, error) {
		return nil, nil
	}}
	h := newTestHandler(nil, users, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/admin/users/u1", nil)
	r.SetPathValue("id", "u1")
	rec := httptest.NewRecorder()
	h.GetUser(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestGetUser_Success200(t *testing.T) {
	users := &mocks.MockUserRepo{GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Email: "u@x.test", EmailVerified: true, CreatedAt: time.Now()}, nil
	}}
	h := newTestHandler(nil, users, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/admin/users/u1", nil)
	r.SetPathValue("id", "u1")
	rec := httptest.NewRecorder()
	h.GetUser(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// LockUser — missing id, repo error, success (default + custom duration)
// ---------------------------------------------------------------------------

func TestLockUser_MissingID400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.LockUser(rec, withActor(httptest.NewRequest(http.MethodPost, "/admin/users//lock", nil)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestLockUser_RepoError500(t *testing.T) {
	users := &mocks.MockUserRepo{LockUntilFn: func(_ context.Context, _ string, _ time.Time) error {
		return errors.New("db down")
	}}
	h := newTestHandler(nil, users, nil, nil)
	r := withActor(jsonReq(http.MethodPost, "/admin/users/u1/lock", `{"duration":"1h"}`))
	r.SetPathValue("id", "u1")
	rec := httptest.NewRecorder()
	h.LockUser(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestLockUser_CustomDuration200(t *testing.T) {
	var gotUntil time.Time
	users := &mocks.MockUserRepo{LockUntilFn: func(_ context.Context, _ string, until time.Time) error {
		gotUntil = until
		return nil
	}}
	h := newTestHandler(nil, users, nil, nil)
	r := withActor(jsonReq(http.MethodPost, "/admin/users/u1/lock", `{"duration":"2h"}`))
	r.SetPathValue("id", "u1")
	rec := httptest.NewRecorder()
	h.LockUser(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	// 2h lock should land well past the 24h default fallback's lower bound.
	if !gotUntil.After(time.Now().Add(time.Hour)) {
		t.Fatalf("lock until not in the future: %v", gotUntil)
	}
}

func TestLockUser_InvalidDurationFallsBackTo200(t *testing.T) {
	users := &mocks.MockUserRepo{LockUntilFn: func(_ context.Context, _ string, _ time.Time) error {
		return nil
	}}
	h := newTestHandler(nil, users, nil, nil)
	// Garbage duration → ParseDuration fails → 24h default, still locks OK.
	r := withActor(jsonReq(http.MethodPost, "/admin/users/u1/lock", `{"duration":"not-a-duration"}`))
	r.SetPathValue("id", "u1")
	rec := httptest.NewRecorder()
	h.LockUser(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// CreateClient — RandomUUID/secret paths already covered; cover the
// role+scopes+redirect_uris success persistence assertion not yet exercised.
// ---------------------------------------------------------------------------

func TestCreateClient_PersistsRoleAndRedirects(t *testing.T) {
	var created *model.Client
	clients := &mocks.MockClientRepo{CreateFn: func(_ context.Context, c *model.Client) error {
		created = c
		return nil
	}}
	h := newTestHandler(nil, nil, clients, nil)
	rec := httptest.NewRecorder()
	body := `{"name":"svc2","role":"editor","scopes":["read","write"],"redirect_uris":["https://app/cb"]}`
	h.CreateClient(rec, withActor(jsonReq(http.MethodPost, "/admin/clients", body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	if created == nil || created.Role != "editor" || len(created.Scopes) != 2 || len(created.RedirectURIs) != 1 {
		t.Fatalf("client fields not persisted: %+v", created)
	}
	if !created.Active {
		t.Fatal("new client should be active")
	}
}
