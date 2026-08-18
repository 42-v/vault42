package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// GET /user/sessions listed DEVICES and DELETE /user/sessions/{id} took a device
// id, but the unit a session actually is is the refresh-token family.
//
// findOrCreateDevice is documented as non-critical — "errors are logged but do
// not fail the auth flow" — and returns "" when both the lookup and the insert
// fail. Both the password path and the OAuth path then store the family with an
// empty device_id. Such a family is a live, refreshable session that appears in
// no listing and that the per-session revoke cannot address: the only way to end
// it is "sign out everywhere".
//
// The inverse held too. Two families sharing one device fingerprint showed as one
// row, so revoking "a session" killed both, and a device with no live family at
// all still listed as active.
func TestSessionsListsFamiliesNotDevices(t *testing.T) {
	now := time.Now().UTC()
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(_ context.Context, userID string) ([]*repository.ActiveFamily, error) {
			return []*repository.ActiveFamily{
				{FamilyID: "family-with-device", DeviceID: "device-1", CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)},
				{FamilyID: "family-no-device", DeviceID: "", CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)},
				{FamilyID: "family-sharing-device", DeviceID: "device-1", CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)},
			}, nil
		},
	}
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(_ context.Context, userID string) ([]*model.Device, error) {
			return []*model.Device{
				{ID: "device-1", UserID: userID, FriendlyName: "Chrome on Linux", IP: "192.0.2.1",
					UserAgent: "TestBrowser/1.0", LastSeenAt: &now, FirstSeenAt: now},
				// A device with no live family. It used to list as an active
				// session; it is not one.
				{ID: "device-stale", UserID: userID, FriendlyName: "Old Phone", FirstSeenAt: now},
			}, nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, tokens, nil)
	req := setAuthContext(httptest.NewRequest(http.MethodGet, "/user/sessions", nil), "user-123")
	rec := httptest.NewRecorder()
	h.Sessions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}

	var result SessionsResponse
	decodeResponse(t, rec, &result)
	if len(result.Sessions) != 3 {
		t.Fatalf("listed %d sessions, want 3 (one per live family, none for the device with no family)", len(result.Sessions))
	}
	if result.Total != 3 {
		t.Errorf("Total = %d, want 3", result.Total)
	}

	byID := map[string]SessionInfo{}
	for _, s := range result.Sessions {
		byID[s.ID] = s
	}
	if _, ok := byID["family-no-device"]; !ok {
		t.Error("a family whose device_id came back empty is invisible in the listing and therefore unrevocable")
	}
	if _, ok := byID["family-sharing-device"]; !ok {
		t.Error("two families on one device must list as two sessions, or revoking one kills both")
	}
	if _, ok := byID["device-stale"]; ok {
		t.Error("a device with no live refresh-token family is not an active session")
	}
	if got := byID["family-with-device"].FriendlyName; got != "Chrome on Linux" {
		t.Errorf("FriendlyName = %q, want the joined device label", got)
	}
	if got := byID["family-with-device"].IP; got != "192.0.2.1" {
		t.Errorf("IP = %q, want the joined device address", got)
	}
	if byID["family-no-device"].FriendlyName != "" {
		t.Errorf("a family with no device must not borrow another device's label, got %q", byID["family-no-device"].FriendlyName)
	}
}

// The revoke half of the same defect: the session the listing shows must be the
// session the delete ends.
func TestRevokeSessionRevokesTheFamilyIncludingOneWithNoDevice(t *testing.T) {
	now := time.Now().UTC()
	var revokedFamily string
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(context.Context, string) ([]*repository.ActiveFamily, error) {
			return []*repository.ActiveFamily{
				{FamilyID: "family-no-device", DeviceID: "", CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)},
			}, nil
		},
		RevokeFamilyFn: func(_ context.Context, familyID string) error {
			revokedFamily = familyID
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, tokens, nil)
	req := setAuthContext(httptest.NewRequest(http.MethodDelete, "/user/sessions/family-no-device", nil), "user-123")
	req.SetPathValue("id", "family-no-device")
	rec := httptest.NewRecorder()
	h.RevokeSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if revokedFamily != "family-no-device" {
		t.Fatalf("RevokeFamily called with %q, want the family id; a family with no device was previously unreachable", revokedFamily)
	}
}

// A family id that belongs to somebody else, or to nobody, is a 404 — the same
// answer the device path gave, so the endpoint is not an existence oracle for
// another account's session ids.
func TestRevokeSessionRefusesAFamilyTheCallerDoesNotOwn(t *testing.T) {
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(context.Context, string) ([]*repository.ActiveFamily, error) {
			return nil, nil
		},
		RevokeFamilyFn: func(context.Context, string) error {
			t.Error("RevokeFamily must not be called for a family the caller does not hold")
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, tokens, nil)
	req := setAuthContext(httptest.NewRequest(http.MethodDelete, "/user/sessions/somebody-elses-family", nil), "user-123")
	req.SetPathValue("id", "somebody-elses-family")
	rec := httptest.NewRecorder()
	h.RevokeSession(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// The id in the listing used to be a device id, and a client that cached one
// must not be met with a 404 on upgrade. A device id still revokes that device's
// tokens and removes the row, exactly as before.
func TestRevokeSessionStillAcceptsADeviceIDForOneRelease(t *testing.T) {
	var revokedDevice, deletedDevice string
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(context.Context, string) ([]*repository.ActiveFamily, error) { return nil, nil },
		RevokeByDeviceIDFn: func(_ context.Context, deviceID string) error {
			revokedDevice = deviceID
			return nil
		},
	}
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-123"}, nil
		},
		DeleteFn: func(_ context.Context, id, userID string) error {
			deletedDevice = id
			return nil
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, tokens, nil)
	req := setAuthContext(httptest.NewRequest(http.MethodDelete, "/user/sessions/device-1", nil), "user-123")
	req.SetPathValue("id", "device-1")
	rec := httptest.NewRecorder()
	h.RevokeSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if revokedDevice != "device-1" || deletedDevice != "device-1" {
		t.Fatalf("device fallback did not run: revoked=%q deleted=%q", revokedDevice, deletedDevice)
	}
}

// A listing that cannot read the families must not answer with a partial list
// that looks like "you have no other sessions".
func TestSessionsFailsWhenFamiliesCannotBeRead(t *testing.T) {
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(context.Context, string) ([]*repository.ActiveFamily, error) {
			return nil, context.DeadlineExceeded
		},
	}
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, tokens, nil)
	req := setAuthContext(httptest.NewRequest(http.MethodGet, "/user/sessions", nil), "user-123")
	rec := httptest.NewRecorder()
	h.Sessions(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// Device metadata is a nicety; a family is still a session without it. A device
// lookup failure must not hide live sessions from the only page that lists them.
func TestSessionsSurvivesADeviceLookupFailure(t *testing.T) {
	now := time.Now().UTC()
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(context.Context, string) ([]*repository.ActiveFamily, error) {
			return []*repository.ActiveFamily{
				{FamilyID: "family-1", DeviceID: "device-1", CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)},
			}, nil
		},
	}
	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(context.Context, string) ([]*model.Device, error) {
			return nil, context.DeadlineExceeded
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, tokens, nil)
	req := setAuthContext(httptest.NewRequest(http.MethodGet, "/user/sessions", nil), "user-123")
	rec := httptest.NewRecorder()
	h.Sessions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var result SessionsResponse
	decodeResponse(t, rec, &result)
	if len(result.Sessions) != 1 {
		t.Fatalf("listed %d sessions, want 1: a device lookup failure must not hide a live session", len(result.Sessions))
	}
}

// A family revoke that fails must not report the session ended.
func TestRevokeSessionReportsAFailedFamilyRevoke(t *testing.T) {
	now := time.Now().UTC()
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(context.Context, string) ([]*repository.ActiveFamily, error) {
			return []*repository.ActiveFamily{{FamilyID: "family-1", CreatedAt: now, LastUsedAt: now}}, nil
		},
		RevokeFamilyFn: func(context.Context, string) error { return context.DeadlineExceeded },
	}
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, tokens, nil)
	req := setAuthContext(httptest.NewRequest(http.MethodDelete, "/user/sessions/family-1", nil), "user-123")
	req.SetPathValue("id", "family-1")
	rec := httptest.NewRecorder()
	h.RevokeSession(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// A family listing that cannot be read must not fall through to the device
// alias, which would answer "revoked" for a session the caller may not own.
func TestRevokeSessionFailsWhenFamiliesCannotBeRead(t *testing.T) {
	tokens := &mocks.MockRefreshTokenRepo{
		ListActiveFamiliesFn: func(context.Context, string) ([]*repository.ActiveFamily, error) {
			return nil, context.DeadlineExceeded
		},
	}
	h := NewUserHandler(&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, tokens, nil)
	req := setAuthContext(httptest.NewRequest(http.MethodDelete, "/user/sessions/family-1", nil), "user-123")
	req.SetPathValue("id", "family-1")
	rec := httptest.NewRecorder()
	h.RevokeSession(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
