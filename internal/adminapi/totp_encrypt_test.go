package adminapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The admin TOTP secret is encrypted under the master key and AAD-bound to the admin it
// belongs to — that binding is what stops one admin's TOTP ciphertext being swapped into
// another's row at the database level.
//
// If the encryption failed and setup carried on, the admin would be shown a QR code and
// would enroll it in their authenticator, while the server had stored either nothing or
// something it cannot decrypt. On the break-glass account, that is a lockout from the tool
// you reach for when everything else is already broken.
func TestAdminTOTPSetup_UnusableMasterKeyStoresNothing(t *testing.T) {
	repo := newFakeAdminRepo()
	admin := &model.AdminUser{ID: "adm-1", Username: "root"}
	repo.users[admin.ID] = admin

	// 7 bytes is not an AES key: Encrypt must reject it.
	h := NewAuthHandler(repo, &stubAdminSessionRepo{}, audit.NewLogger(&mocks.MockAuditRepo{}, 0),
		bytes.Repeat([]byte{0x42}, 7), "", time.Hour, 5, time.Hour)

	req := adminCtx(httptest.NewRequest(http.MethodPost, "/admin/totp/setup", nil))
	rec := httptest.NewRecorder()

	h.TOTPSetup(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
	}
	if repo.users[admin.ID].TOTPSecretEnc != "" {
		t.Error("a TOTP secret was stored despite the encryption failing")
	}
	if body := rec.Body.String(); bytes.Contains([]byte(body), []byte("otpauth://")) {
		t.Error("a QR provisioning URI was returned for a secret that was never encrypted")
	}
}
