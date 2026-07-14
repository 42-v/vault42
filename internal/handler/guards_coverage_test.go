package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/email"
)

// guardCall invokes a claims-gated handler with no authenticated claims in
// context and asserts it rejects the request (>= 400) rather than proceeding
// into nil service dependencies. This exercises the unauthorized-guard branch
// that every authenticated endpoint shares.
func guardCall(t *testing.T, name string, fn http.HandlerFunc, method, target, body string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, target, strings.NewReader(body))
		} else {
			r = httptest.NewRequest(method, target, nil)
		}
		rec := httptest.NewRecorder()
		fn(rec, r)
		if rec.Code < 400 {
			t.Fatalf("%s without claims = %d, want a client/server error", name, rec.Code)
		}
	})
}

func TestAuthenticatedHandlers_RejectWithoutClaims(t *testing.T) {
	account := &AccountHandler{}
	guardCall(t, "AccountHandler.Delete", account.Delete, http.MethodDelete, "/user/account", `{"password":"x"}`)

	export := &DataExportHandler{}
	guardCall(t, "DataExportHandler.Export", export.Export, http.MethodGet, "/user/data-export", "")

	totp := &TOTPHandler{}
	guardCall(t, "TOTPHandler.Setup", totp.Setup, http.MethodPost, "/auth/2fa/totp/setup", "")
	guardCall(t, "TOTPHandler.Disable", totp.Disable, http.MethodDelete, "/auth/2fa/totp", "")

	backup := &BackupCodeHandler{}
	guardCall(t, "BackupCodeHandler.Generate", backup.Generate, http.MethodPost, "/auth/2fa/backup-codes", "")

	otp := &EmailOTPHandler{}
	guardCall(t, "EmailOTPHandler.Resend", otp.Resend, http.MethodPost, "/auth/2fa/email-otp/resend", "")

	identity := &IdentityHandler{}
	guardCall(t, "IdentityHandler.Get", identity.Get, http.MethodGet, "/user/identity", "")
	guardCall(t, "IdentityHandler.Put", identity.Put, http.MethodPut, "/user/identity", `{}`)
	guardCall(t, "IdentityHandler.Delete", identity.Delete, http.MethodDelete, "/user/identity", "")

	blob := &BlobHandler{}
	guardCall(t, "BlobHandler.List", blob.List, http.MethodGet, "/user/blobs", "")
	guardCall(t, "BlobHandler.Upload", blob.Upload, http.MethodPost, "/user/blobs", `{}`)
	guardCall(t, "BlobHandler.Download", blob.Download, http.MethodGet, "/user/blobs/x", "")
	guardCall(t, "BlobHandler.Delete", blob.Delete, http.MethodDelete, "/user/blobs/x", "")

	user := &UserHandler{}
	guardCall(t, "UserHandler.Devices", user.Devices, http.MethodGet, "/user/devices", "")
	guardCall(t, "UserHandler.Sessions", user.Sessions, http.MethodGet, "/user/sessions", "")
	guardCall(t, "UserHandler.RevokeAllSessions", user.RevokeAllSessions, http.MethodDelete, "/user/sessions", "")
	guardCall(t, "UserHandler.RevokeSession", user.RevokeSession, http.MethodDelete, "/user/sessions/x", "")
	guardCall(t, "UserHandler.DeleteDevice", user.DeleteDevice, http.MethodDelete, "/user/devices/x", "")

	mfa := &MFAHandler{}
	guardCall(t, "MFAHandler.Status", mfa.Status, http.MethodGet, "/auth/2fa/status", "")

	pw := &PasswordHandler{}
	guardCall(t, "PasswordHandler.ChangePassword", pw.ChangePassword, http.MethodPost, "/user/password", `{"old_password":"x","new_password":"y"}`)

	webauthn := &WebAuthnHandler{}
	guardCall(t, "WebAuthnHandler.ListCredentials", webauthn.ListCredentials, http.MethodGet, "/auth/2fa/webauthn/credentials", "")
	guardCall(t, "WebAuthnHandler.RegisterBegin", webauthn.RegisterBegin, http.MethodPost, "/auth/2fa/webauthn/register/begin", "")
}

func TestPasswordHandler_SetMailer(t *testing.T) {
	h := &PasswordHandler{}
	h.SetMailer(nil) // nil is ignored
	if h.mailer != nil {
		t.Error("nil mailer should be ignored")
	}
	m := email.NewMailer(nil, nil, nil, email.Branding{}, nil)
	h.SetMailer(m)
	if h.mailer != m {
		t.Error("non-nil mailer should be stored")
	}
}
