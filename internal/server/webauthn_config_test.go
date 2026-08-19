package server

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
)

// webAuthnTestUser is a user holding one credential, which is the minimum
// BeginLogin accepts.
func webAuthnTestUser() *model.WebAuthnUser {
	return &model.WebAuthnUser{
		User: &model.User{ID: "11111111-1111-1111-1111-111111111111", Email: "user@vault.localhost"},
		Credentials: []webauthn.Credential{
			{ID: []byte("credential-id"), PublicKey: []byte("public-key")},
		},
	}
}

// wantCeremonyWindow fails unless the ceremony expires exactly one
// handler.WebAuthnCeremonyTTL after it began.
//
// The library stamps the deadline as now+timeout at some instant inside the
// call, so bracketing that call gives an exact bound with no tolerance to
// choose: the expiry must land between began+TTL and ended+TTL. Anything
// outside means the enforced window is a different duration from the TTL, not
// that the clock moved.
func wantCeremonyWindow(t *testing.T, ceremony string, expires, began, ended time.Time) {
	t.Helper()

	if expires.IsZero() {
		t.Fatalf("%s session carries no expiry: Timeouts.Enforce is off, so go-webauthn leaves "+
			"SessionData.Expires at the zero time and its own expiry check never runs. The challenge "+
			"then stays answerable for as long as whatever else happens to hold it", ceremony)
	}

	earliest, latest := began.Add(handler.WebAuthnCeremonyTTL), ended.Add(handler.WebAuthnCeremonyTTL)
	if expires.Before(earliest) || expires.After(latest) {
		t.Errorf("%s session expires %v after it began, want %v: the enforced ceremony deadline has "+
			"drifted from the lifetime of the cache entry holding the challenge, so one of the two "+
			"decides how long a challenge stays answerable and the other is decoration",
			ceremony, expires.Sub(began), handler.WebAuthnCeremonyTTL)
	}
}

// A WebAuthn ceremony must carry a deadline the server enforces itself.
//
// go-webauthn only stamps SessionData.Expires when Timeouts.*.Enforce is set,
// and only compares it when it is non-zero. Left at the default, both the stamp
// and the comparison are skipped, the timeout the browser is handed is advisory,
// and the sole thing retiring a challenge is the TTL on the cache entry that
// holds it. That makes the cache a security control rather than a cache: any
// backend, misconfiguration or future rewrite that keeps an entry past its TTL
// silently extends how long a challenge can be answered, and nothing in the
// WebAuthn code would report it.
//
// The deadline is checked against handler.WebAuthnCeremonyTTL rather than a
// literal so the enforced window and the cache entry cannot be given two
// different numbers.
func TestWebAuthnCeremoniesExpireOnADeadlineTheServerEnforcesItself(t *testing.T) {
	cfg := &config.Config{
		AppName: "Vault Test",
		Origin:  "https://vault.localhost",
	}

	wan, err := webauthn.New(webAuthnConfig(cfg))
	if err != nil {
		t.Fatalf("build the relying-party config the server runs on: %v", err)
	}

	user := webAuthnTestUser()

	began := time.Now()
	_, login, err := wan.BeginLogin(user)
	ended := time.Now()
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	wantCeremonyWindow(t, "assertion", login.Expires, began, ended)

	began = time.Now()
	_, registration, err := wan.BeginRegistration(user)
	ended = time.Now()
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	wantCeremonyWindow(t, "registration", registration.Expires, began, ended)
}
