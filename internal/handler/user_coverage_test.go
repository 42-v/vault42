package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Profile edge cases
// ---------------------------------------------------------------------------

func TestProfile_UserNotFound(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return nil, nil // user not found
		},
	}

	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req = setAuthContext(req, "nonexistent-user")
	rec := httptest.NewRecorder()

	h.Profile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "unauthorized" {
		t.Fatalf("expected error=unauthorized, got %q", result["error"])
	}
}

func TestProfile_RepoError(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return nil, errors.New("db error")
		},
	}

	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req = setAuthContext(req, "user-err")
	rec := httptest.NewRecorder()

	h.Profile(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestProfile_AllFields(t *testing.T) {
	now := time.Now()
	users := &mocks.MockUserRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:            id,
				Email:         "full@example.com",
				EmailVerified: true,
				DisplayName:   "Full User",
				Locale:        "sk",
				MFARequired:   true,
				CreatedAt:     now,
			}, nil
		},
	}

	mfaSvc := service.NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, true)
	h := NewUserHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, mfaSvc)

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req = setAuthContext(req, "full-user")
	rec := httptest.NewRecorder()

	h.Profile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["locale"] != "sk" {
		t.Fatalf("expected locale=sk, got %v", result["locale"])
	}
	if result["mfa_required"] != true {
		t.Fatalf("expected mfa_required=true, got %v", result["mfa_required"])
	}
	if result["mfa_enabled"] != false {
		t.Fatalf("expected mfa_enabled=false (no methods), got %v", result["mfa_enabled"])
	}
}

// ---------------------------------------------------------------------------
// Sessions edge cases
// ---------------------------------------------------------------------------

func TestSessions_RepoError(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.Device, error) {
			return nil, errors.New("db error")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/sessions", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Sessions(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSessions_Empty(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.Device, error) {
			return []*model.Device{}, nil // empty list
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/sessions", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Sessions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	sessions, ok := result["sessions"].([]interface{})
	if !ok {
		t.Fatal("expected sessions array in response")
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

// ---------------------------------------------------------------------------
// RevokeSession edge cases
// ---------------------------------------------------------------------------

func TestRevokeSession_MissingSessionID(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/", nil)
	req = setAuthContext(req, "user-123")
	// No path value set -> r.PathValue("id") returns ""
	rec := httptest.NewRecorder()

	h.RevokeSession(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "missing_session_id" {
		t.Fatalf("expected error=missing_session_id, got %q", result["error"])
	}
}

func TestRevokeSession_NotFound(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return nil, nil // device not found
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/nonexistent", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "nonexistent")
	rec := httptest.NewRecorder()

	h.RevokeSession(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeSession_WrongOwner(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{
				ID:     id,
				UserID: "other-user", // different user
			}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/session-xyz", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "session-xyz")
	rec := httptest.NewRecorder()

	h.RevokeSession(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeSession_DeleteError(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
		DeleteFn: func(ctx context.Context, id, userID string) error {
			return errors.New("db error")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/session-del-err", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "session-del-err")
	rec := httptest.NewRecorder()

	h.RevokeSession(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeSession_RepoError(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return nil, errors.New("db error")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/err-session", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "err-session")
	rec := httptest.NewRecorder()

	h.RevokeSession(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RevokeAllSessions edge cases
// ---------------------------------------------------------------------------

func TestRevokeAllSessions_RepoError(t *testing.T) {
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(ctx context.Context, userID string) error {
			return errors.New("db error")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, tokens, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.RevokeAllSessions(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Devices edge cases
// ---------------------------------------------------------------------------

func TestDevices_Unauthorized(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/devices", nil)
	// No auth context
	rec := httptest.NewRecorder()

	h.Devices(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDevices_RepoError(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.Device, error) {
			return nil, errors.New("db error")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/devices", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Devices(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDevices_Empty(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.Device, error) {
			return []*model.Device{}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/devices", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Devices(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	devs := result["devices"].([]interface{})
	if len(devs) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(devs))
	}
}

func TestDevices_NoFingerprintHash(t *testing.T) {
	now := time.Now()
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.Device, error) {
			return []*model.Device{
				{
					ID:              "device-1",
					UserID:          userID,
					FingerprintHash: "abcdef1234567890",
					FriendlyName:    "Test Device",
					LastSeenAt:      &now,
				},
			}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/user/devices", nil)
	req = setAuthContext(req, "user-123")
	rec := httptest.NewRecorder()

	h.Devices(rec, req)

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	devs := result["devices"].([]interface{})
	d := devs[0].(map[string]interface{})
	// fingerprint_hash should not be present in response
	if _, exists := d["fingerprint_hash"]; exists {
		t.Fatal("fingerprint_hash should not be present in device response")
	}
}

// ---------------------------------------------------------------------------
// RenameDevice edge cases
// ---------------------------------------------------------------------------

func TestRenameDevice_Unauthorized(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": "Test"})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-1", body)
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRenameDevice_MissingDeviceID(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodPatch, "/user/devices/", nil)
	req = setAuthContext(req, "user-123")
	// No path value
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "missing_device_id" {
		t.Fatalf("expected error=missing_device_id, got %q", result["error"])
	}
}

func TestRenameDevice_DeviceNotFound(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return nil, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": "Test"})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/missing", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "missing")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRenameDevice_WrongOwner(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "other-user"}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": "Test"})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-xyz", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-xyz")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRenameDevice_InvalidJSON(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-1", strings.NewReader("not json"))
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRenameDevice_EmptyName(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": ""})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-1", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "name_required" {
		t.Fatalf("expected error=name_required, got %q", result["error"])
	}
}

func TestRenameDevice_WhitespaceOnlyName(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": "   "})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-1", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "name_required" {
		t.Fatalf("expected error=name_required, got %q", result["error"])
	}
}

func TestRenameDevice_ControlChars(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": "name\x00with\x01control"})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-1", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "name_invalid_chars" {
		t.Fatalf("expected error=name_invalid_chars, got %q", result["error"])
	}
}

func TestRenameDevice_TabsAllowed(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
		UpdateFriendlyNameFn: func(ctx context.Context, id string, name string) error {
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": "name\twith\ttabs"})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-1", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRenameDevice_Exactly100Chars(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
		UpdateFriendlyNameFn: func(ctx context.Context, id string, name string) error {
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	name := strings.Repeat("A", 100)
	body := jsonBody(t, map[string]string{"friendly_name": name})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-1", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for 100-char name, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRenameDevice_UpdateError(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
		UpdateFriendlyNameFn: func(ctx context.Context, id string, name string) error {
			return errors.New("db error")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	body := jsonBody(t, map[string]string{"friendly_name": "Valid Name"})
	req := httptest.NewRequest(http.MethodPatch, "/user/devices/device-1", body)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()

	h.RenameDevice(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DeleteDevice edge cases
// ---------------------------------------------------------------------------

func TestDeleteDevice_Unauthorized(t *testing.T) {
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/devices/device-1", nil)
	req.SetPathValue("id", "device-1")
	// No auth context
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteDevice_NotFound(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return nil, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/devices/missing", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "missing")
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteDevice_Success(t *testing.T) {
	deleted := false
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
		DeleteFn: func(ctx context.Context, id, userID string) error {
			deleted = true
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/devices/device-del", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-del")
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["status"] != "device_removed" {
		t.Fatalf("expected status=device_removed, got %q", result["status"])
	}
	if !deleted {
		t.Fatal("expected Delete to have been called")
	}
}

func TestDeleteDevice_DeleteError(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
		DeleteFn: func(ctx context.Context, id, userID string) error {
			return errors.New("db error")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/devices/device-err", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-err")
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteDevice_RepoError(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Device, error) {
			return nil, errors.New("db error")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, &mocks.MockRefreshTokenRepo{}, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/devices/device-repo-err", nil)
	req = setAuthContext(req, "user-123")
	req.SetPathValue("id", "device-repo-err")
	rec := httptest.NewRecorder()

	h.DeleteDevice(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
