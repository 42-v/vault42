package unit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Coverage-focused tests for the 0.7.0 release. Each test exercises a
// previously-uncovered branch in the user / email-OTP / admin handlers.

func v070User(users *mocks.MockUserRepo, devices *mocks.MockDeviceRepo, tokens *mocks.MockRefreshTokenRepo) *handler.UserHandler {
	return handler.NewUserHandler(users, devices, tokens, nil)
}

func v070OwnedDevice(id string) *model.Device {
	return &model.Device{ID: id, UserID: testUserID, FriendlyName: "phone"}
}

// v070AdminEnv builds an admin Handler with caller-supplied user and client
// repos so success paths (which need a present record) can be exercised.
func v070AdminEnv(users *mocks.MockUserRepo, clients *mocks.MockClientRepo) *adminapi.Handler {
	return adminapi.NewHandler(
		users, clients,
		&mocks.MockRefreshTokenRepo{}, &mocks.MockAuditRepo{},
		newMockAdminUserRepo(), newMockAdminSessionRepo(),
		&mocks.MockAdminConfigRepo{}, nil,
		audit.NewLogger(&mocks.MockAuditRepo{}, time.Hour),
		make([]byte, 32), "",
	)
}

func v070AdminReq(method, target, id, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if id != "" {
		r.SetPathValue("id", id)
	}
	return r.WithContext(adminCtx(r.Context()))
}

// --- UpdateProfile -------------------------------------------------------

func TestV070_UpdateProfile_Success(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) {
			return &model.User{ID: testUserID, Email: "a@b.com"}, nil
		},
		UpdateFn: func(context.Context, *model.User) error { return nil },
	}
	h := v070User(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{})

	body := map[string]any{"display_name": "New Name", "avatar_url": "https://e.x/a.png", "locale": "en-US"}
	req, w, keys := authedRequest(t, http.MethodPut, "/user/profile", body)
	serveWithAuth(t, "PUT /user/profile", h.UpdateProfile, keys, w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestV070_UpdateProfile_UpdateError(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) {
			return &model.User{ID: testUserID}, nil
		},
		UpdateFn: func(context.Context, *model.User) error { return context.DeadlineExceeded },
	}
	h := v070User(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{})

	req, w, keys := authedRequest(t, http.MethodPut, "/user/profile", map[string]any{"display_name": "X"})
	serveWithAuth(t, "PUT /user/profile", h.UpdateProfile, keys, w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

// --- DeleteDevice --------------------------------------------------------

func TestV070_DeleteDevice_TokenError(t *testing.T) {
	h := v070User(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Device, error) { return v070OwnedDevice(id), nil },
	}, &mocks.MockRefreshTokenRepo{
		RevokeByDeviceIDFn: func(context.Context, string) error { return context.DeadlineExceeded },
	})

	req, w, keys := authedRequest(t, http.MethodDelete, "/user/devices/dev-1", nil)
	serveWithAuth(t, "DELETE /user/devices/{id}", h.DeleteDevice, keys, w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

// --- RevokeAllSessions ---------------------------------------------------

func TestV070_RevokeAllSessions_DeviceError(t *testing.T) {
	h := v070User(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{
		DeleteAllForUserFn: func(context.Context, string) error { return context.DeadlineExceeded },
	}, &mocks.MockRefreshTokenRepo{})

	req, w, keys := authedRequest(t, http.MethodDelete, "/user/sessions", nil)
	serveWithAuth(t, "DELETE /user/sessions", h.RevokeAllSessions, keys, w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

// --- EmailOTP Resend (paths that never reach the AuthService) ------------

func TestV070_Resend_UserNil(t *testing.T) {
	h := handler.NewEmailOTPHandler(nil, &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, nil },
	}, false)

	req, w, keys := authedRequest(t, http.MethodPost, "/auth/2fa/email-otp/resend", nil)
	serveWithAuth(t, "POST /auth/2fa/email-otp/resend", h.Resend, keys, w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
}

func TestV070_Resend_GetByIDError(t *testing.T) {
	h := handler.NewEmailOTPHandler(nil, &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, context.DeadlineExceeded },
	}, false)

	req, w, keys := authedRequest(t, http.MethodPost, "/auth/2fa/email-otp/resend", nil)
	serveWithAuth(t, "POST /auth/2fa/email-otp/resend", h.Resend, keys, w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
}

// --- Capabilities --------------------------------------------------------

func TestV070_Capabilities_NilProviders(t *testing.T) {
	w := httptest.NewRecorder()
	handler.Capabilities(true, true, nil)(w, httptest.NewRequest(http.MethodGet, "/auth/capabilities", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"oauth_providers":[]`) {
		t.Fatalf("nil providers should serialize to []: %s", w.Body.String())
	}
}

// --- adminapi: CreateClient ---------------------------------------------

func TestV070_AdminCreateClient_Success(t *testing.T) {
	rec := runHandler(adminHandlerEnv().CreateClient, http.MethodPost, "/admin/clients", `{"name":"v070-client","role":"viewer"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"secret"`) {
		t.Fatalf("response missing generated secret: %s", rec.Body.String())
	}
}

func TestV070_AdminCreateClient_MissingName(t *testing.T) {
	rec := runHandler(adminHandlerEnv().CreateClient, http.MethodPost, "/admin/clients", `{"role":"viewer"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
}

// --- adminapi: CreateAdmin ----------------------------------------------

func TestV070_AdminCreateAdmin_Success(t *testing.T) {
	rec := runHandler(adminHandlerEnv().CreateAdmin, http.MethodPost, "/admin/admins",
		`{"username":"v070-admin","password":"correct-horse-battery-staple","role":"operator"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
}

// Three ways a CreateAdmin body fails validation. Each row breaks exactly one
// rule and leaves the others satisfied, so a check that is dropped fails its own
// row instead of hiding behind another rejection in the same request.
func TestV070_AdminCreateAdmin_InvalidBodiesAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "no password and no role", body: `{"username":"only-name"}`},
		{name: "a role outside the vocabulary", body: `{"username":"v070-bad","password":"correct-horse-battery-staple","role":"emperor"}`},
		{name: "a password under the length floor", body: `{"username":"v070-short","password":"tooshort","role":"operator"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := runHandler(adminHandlerEnv().CreateAdmin, http.MethodPost, "/admin/admins", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("a body with %s answered %d, want 400: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// --- adminapi: UpdateConfig ---------------------------------------------

func TestV070_AdminUpdateConfig_Success(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/admin/config/feature_flag", strings.NewReader(`{"value":"on"}`))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("key", "feature_flag")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().UpdateConfig(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

func TestV070_AdminUpdateConfig_InvalidKey(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/admin/config/bad", strings.NewReader(`{"value":"x"}`))
	r.SetPathValue("key", "bad key!")
	r = r.WithContext(adminCtx(r.Context()))
	rec := httptest.NewRecorder()
	adminHandlerEnv().UpdateConfig(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
}

// --- adminapi: GetClient / RotateClientSecret ---------------------------

func TestV070_AdminGetClient_Success(t *testing.T) {
	clients := &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Client, error) {
			return &model.Client{ID: id, Name: "c"}, nil
		},
	}
	rec := httptest.NewRecorder()
	v070AdminEnv(&mocks.MockUserRepo{}, clients).GetClient(rec, v070AdminReq(http.MethodGet, "/admin/clients/c1", "c1", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

func TestV070_AdminRotateClientSecret_Success(t *testing.T) {
	clients := &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Client, error) {
			return &model.Client{ID: id, Name: "c", Active: true}, nil
		},
	}
	rec := httptest.NewRecorder()
	v070AdminEnv(&mocks.MockUserRepo{}, clients).RotateClientSecret(rec, v070AdminReq(http.MethodPost, "/admin/clients/c1/rotate", "c1", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"secret"`) {
		t.Fatalf("rotate response missing new secret: %s", rec.Body.String())
	}
}
