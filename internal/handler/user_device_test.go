package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Removing a device is how a user cuts off a laptop they no longer have. The tokens are
// revoked first, then the device row goes — and the order matters: if the revoke fails and
// the delete went ahead anyway, the device would vanish from the user's list while its
// refresh token kept minting sessions. The user would have no way to see it, and no way to
// try again.
//
// So a failed revoke must fail the whole request and leave the device where it is.
func TestRevokeSession_RevokeFailureLeavesTheDeviceInPlace(t *testing.T) {
	deleted := false
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-1"}, nil
		},
		DeleteFn: func(context.Context, string, string) error {
			deleted = true
			return nil
		},
	}
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeByDeviceIDFn: func(context.Context, string) error {
			return errors.New("db down")
		},
	}

	h := NewUserHandler(&mocks.MockUserRepo{}, devices, tokens, nil)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/dev-1", nil)
	req.SetPathValue("id", "dev-1")
	req = setAuthContext(req, "user-1")
	rec := httptest.NewRecorder()

	h.RevokeSession(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if deleted {
		t.Error("the device was removed from the user's list while its refresh token was still live")
	}
}
