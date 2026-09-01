package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/email"
)

// guardCall invokes a claims-gated handler with no authenticated claims in
// context and asserts it answers 401 unauthorized.
//
// It asserted `>= 400` until it was measured. That is not the claim the test
// name makes, and it is not a claim about authentication at all: any error the
// fixture happens to provoke satisfies it. Deleting the claims check from
// PasswordHandler.ChangePassword left this test green, because the body below
// said "old_password" where production reads "current_password" and decodeJSON
// sets DisallowUnknownFields, so the request died at 400 before reaching the
// branch under test. Deleting it from WebAuthnHandler.RegisterBegin left it
// green too, because an unconfigured handler answers 501 first. Five more rows
// passed only because a path value the handler needs was never set, so an empty
// id produced 400.
//
// Asserting the exact status and the exact error code is what makes those
// fixtures fail loudly instead of passing quietly, and every one of them is
// fixed below. pathValues carries the {id} segments the router would have
// populated, because a handler that never reaches its claims check is not
// evidence of anything.
func guardCall(t *testing.T, name string, fn http.HandlerFunc, method, target, body string, pathValues ...string) {
	t.Helper()
	if len(pathValues)%2 != 0 {
		t.Fatalf("%s: pathValues must be key/value pairs, got %d", name, len(pathValues))
	}
	t.Run(name, func(t *testing.T) {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, target, strings.NewReader(body))
		} else {
			r = httptest.NewRequest(method, target, nil)
		}
		for i := 0; i < len(pathValues); i += 2 {
			r.SetPathValue(pathValues[i], pathValues[i+1])
		}
		rec := httptest.NewRecorder()
		fn(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without claims = %d %s, want %d unauthorized. A handler that refuses "+
				"for some other reason is not evidence that it checks authentication.",
				name, rec.Code, strings.TrimSpace(rec.Body.String()), http.StatusUnauthorized)
		}
		if got := rec.Body.String(); !strings.Contains(got, `"unauthorized"`) {
			t.Fatalf("%s without claims returned 401 with body %s, want the unauthorized error code",
				name, strings.TrimSpace(got))
		}
	})
}

// Every assertion for this test lives in guardCall: the handlers are built with
// nil dependencies, so any of them that failed to reject would panic on the
// service it never should have reached.
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
	guardCall(t, "BlobHandler.Download", blob.Download, http.MethodGet, "/user/blobs/x", "", "id", "x")
	guardCall(t, "BlobHandler.Delete", blob.Delete, http.MethodDelete, "/user/blobs/x", "", "id", "x")

	user := &UserHandler{}
	guardCall(t, "UserHandler.Devices", user.Devices, http.MethodGet, "/user/devices", "")
	guardCall(t, "UserHandler.Sessions", user.Sessions, http.MethodGet, "/user/sessions", "")
	guardCall(t, "UserHandler.RevokeAllSessions", user.RevokeAllSessions, http.MethodDelete, "/user/sessions", "")
	guardCall(t, "UserHandler.RevokeSession", user.RevokeSession, http.MethodDelete, "/user/sessions/x", "", "id", "x")
	guardCall(t, "UserHandler.DeleteDevice", user.DeleteDevice, http.MethodDelete, "/user/devices/x", "", "id", "x")

	mfa := &MFAHandler{}
	guardCall(t, "MFAHandler.Status", mfa.Status, http.MethodGet, "/auth/2fa/status", "")

	pw := &PasswordHandler{}
	guardCall(t, "PasswordHandler.ChangePassword", pw.ChangePassword, http.MethodPost, "/user/password", `{"current_password":"x","new_password":"y"}`)

	// Named wa, not webauthn: the package of that name is imported here now, and
	// a local shadowing it would make the next line that needs the package fail
	// to compile for a reason that reads like nonsense.
	wa := &WebAuthnHandler{wan: guardTestWebAuthn(t)}
	guardCall(t, "WebAuthnHandler.ListCredentials", wa.ListCredentials, http.MethodGet, "/auth/2fa/webauthn/credentials", "")
	guardCall(t, "WebAuthnHandler.RegisterBegin", wa.RegisterBegin, http.MethodPost, "/auth/2fa/webauthn/register/begin", "")
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

// guardTestWebAuthn builds a configured WebAuthn so RegisterBegin reaches its
// claims check. With h.wan nil it answers 501 webauthn_not_configured first,
// which is a real refusal of a real misconfiguration and no evidence at all
// that the handler authenticates.
func guardTestWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Vault",
		RPID:          "localhost",
		RPOrigins:     []string{"https://localhost"},
	})
	if err != nil {
		t.Fatalf("webauthn config: %v", err)
	}
	return wan
}
