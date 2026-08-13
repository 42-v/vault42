package service

import (
	"encoding/json"
	"testing"
)

// TestLoginResultEmitsBothMFASpellings is the other half of a rename that was
// only half done.
//
// MFAStatus emits its factor list twice: mfa_methods is the canonical name and
// available_methods is kept as a deprecated alias for clients written before
// 1.0.0. LoginResult carries the same list, produced by the same login, and
// emitted only the old spelling. A client that reads mfa_methods works against
// GET /mfa/status and silently sees no factors on the login response that is
// actually telling it a second factor is required, which is the one place the
// list changes what the client must do next.
//
// requires_2fa has the same problem against mfa_required.
//
// Both spellings are asserted rather than just the new one, because the alias
// exists to keep live clients working and dropping it is a breaking change that
// must be deliberate.
func TestLoginResultEmitsBothMFASpellings(t *testing.T) {
	res := LoginResult{
		TokenType:        "Bearer",
		Requires2FA:      true,
		ChallengeToken:   "challenge",
		AvailableMethods: []string{"totp", "webauthn"},
	}

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal LoginResult: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"available_methods", "mfa_methods"} {
		list, ok := got[key].([]any)
		if !ok {
			t.Fatalf("%s is missing or not an array: %s", key, raw)
		}
		if len(list) != 2 || list[0] != "totp" || list[1] != "webauthn" {
			t.Errorf("%s = %v, want [totp webauthn]", key, list)
		}
	}

	for _, key := range []string{"requires_2fa", "mfa_required"} {
		if v, ok := got[key].(bool); !ok || !v {
			t.Errorf("%s = %v, want true: %s", key, got[key], raw)
		}
	}
}

// TestLoginResultOmitsMFAKeysWhenNoFactorIsRequired keeps the alias from
// becoming noise on the ordinary login.
//
// The overwhelming majority of logins complete in one step. Emitting
// mfa_required:false and an empty mfa_methods on every one of them would change
// the shape of the common response, and a client checking for the key's
// presence rather than its value would start seeing a second factor everywhere.
// Both spellings stay omitempty, and both have to disappear together.
func TestLoginResultOmitsMFAKeysWhenNoFactorIsRequired(t *testing.T) {
	raw, err := json.Marshal(LoginResult{AccessToken: "token", TokenType: "Bearer", ExpiresIn: 900})
	if err != nil {
		t.Fatalf("marshal LoginResult: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"requires_2fa", "mfa_required", "available_methods", "mfa_methods"} {
		if _, present := got[key]; present {
			t.Errorf("%s is present on a login that needed no second factor: %s", key, raw)
		}
	}
}

// TestLoginResultKeepsEveryNonMFAField guards the marshaller itself.
//
// Emitting two spellings means LoginResult now has a hand-written MarshalJSON,
// and the failure mode of a hand-written marshaller is a field silently dropped
// when someone adds one to the struct and not to the wire type. This asserts
// the full key set of a successful login rather than only the MFA keys.
func TestLoginResultKeepsEveryNonMFAField(t *testing.T) {
	raw, err := json.Marshal(LoginResult{
		AccessToken:  "access",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "refresh-must-not-appear",
		CookieMaxAge: 2592000,
	})
	if err != nil {
		t.Fatalf("marshal LoginResult: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": float64(900)}
	for key, wantVal := range want {
		if got[key] != wantVal {
			t.Errorf("%s = %v, want %v: %s", key, got[key], wantVal, raw)
		}
	}

	// The refresh token travels in a Set-Cookie header. A marshaller that
	// forgets the json:"-" puts the credential in the response body.
	for _, key := range []string{"refresh_token", "RefreshToken", "cookie_max_age", "CookieMaxAge"} {
		if _, present := got[key]; present {
			t.Errorf("%s reached the response body; it is cookie-only: %s", key, raw)
		}
	}
}
