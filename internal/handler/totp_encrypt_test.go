package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The TOTP secret is the MFA seed, and it is encrypted under the master key before it is
// stored, AAD-bound to the user it belongs to. If the encryption failed and setup carried
// on, the user would be shown a QR code — and would scan it into their authenticator — for
// a secret the server either never stored or stored in the clear.
//
// The first is a lockout: they enroll a factor the server cannot verify. The second is
// worse. Either way the request must fail before a QR code is ever rendered.
func TestTOTPSetup_UnusableMasterKeyStoresNothing(t *testing.T) {
	stored := false
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) { return nil, nil },
		CreateFn: func(context.Context, *model.TOTPSecret) error {
			stored = true
			return nil
		},
	}

	// 7 bytes is not an AES key: Encrypt must reject it.
	h := NewTOTPHandler(repo, bytes.Repeat([]byte{0x42}, 7), "Vault", &mocks.MockCache{}, nil, false)

	req := setAuthContext(httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil), "user-1")
	rec := httptest.NewRecorder()

	h.Setup(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if stored {
		t.Error("a TOTP secret was stored despite the encryption failing")
	}
	if body := rec.Body.String(); bytes.Contains([]byte(body), []byte("otpauth://")) {
		t.Error("a QR provisioning URI was returned for a secret that was never encrypted or stored")
	}
}
