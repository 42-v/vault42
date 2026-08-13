package attack

// Account takeover by presenting someone else's address at a social login.
//
// The callback in internal/handler/oauth.go binds a social identity to an
// existing local account when the provider reports a verified email and the
// local account reports one too. Everything after that follows: the social row
// carries (provider, provider_user_id), and the next login on that provider
// walks straight into the victim's session without a password.
//
// So the provider's verified flag is a load-bearing security decision, and the
// attacker's whole job is to get it set for an address that is not theirs.
// Putting the victim's address into the profile response is easy: it is a
// string the attacker types into an account they control, or that a compromised
// or hostile issuer returns. Proving ownership is the part they cannot do,
// which is why the flag has to come from the provider's own verification
// answer and from nothing else.
//
// The Facebook provider used to set the flag from `info.Email != ""`, turning
// step one into the whole attack. These tests hold the line from outside the
// oauth2 package: a generic OIDC issuer is constructible with a URL, so the
// hostile-issuer case can be driven over real HTTP. The Facebook, Google and
// GitHub mappings are covered in internal/oauth2, and the property that no
// provider may derive the flag from the shape of a string is enforced by
// tests/spec/oauth_email_verified_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/oauth2"
)

// atkVictimEmail is the address the attacker wants an account for. The local
// account holding it is verified, which is the interesting case: an unverified
// victim is refused on the account side no matter what the provider claims.
const atkVictimEmail = "victim@vault42.test"

// atkLinkableToExistingAccount restates the account-linking rule from
// internal/handler/oauth.go. It is restated rather than called because this
// test is about the input the providers control, and reaching into the handler
// would measure the gate instead of what is fed to it.
func atkLinkableToExistingAccount(providerSaysVerified, localAccountVerified bool) bool {
	return providerSaysVerified && localAccountVerified
}

// atkOIDCUserInfoIssuer serves the discovery document plus a userinfo endpoint
// returning profile, standing in for an issuer the attacker controls or has
// compromised.
func atkOIDCUserInfoIssuer(t *testing.T, profile map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(profile)
	})
	return srv
}

// TestOAuthEmailPresenceIsNotProofOfOwnership drives the takeover attempt end to
// end at the provider boundary: a profile carrying the victim's address must
// not produce a verified flag unless the issuer explicitly says the address was
// verified, and the linking rule must refuse in every other case.
func TestOAuthEmailPresenceIsNotProofOfOwnership(t *testing.T) {
	cases := []struct {
		name         string
		profile      map[string]any
		wantVerified bool
		wantLinkable bool
	}{
		{
			// The takeover attempt. Nothing in this response says the subject
			// proved ownership, so nothing may be inferred from the address.
			name:         "victim address with no verification claim",
			profile:      map[string]any{"sub": "attacker-subject", "email": atkVictimEmail},
			wantVerified: false,
			wantLinkable: false,
		},
		{
			name:         "victim address the issuer marks unverified",
			profile:      map[string]any{"sub": "attacker-subject", "email": atkVictimEmail, "email_verified": false},
			wantVerified: false,
			wantLinkable: false,
		},
		{
			// The legitimate owner returning through the provider. Without this
			// case the suite would pass on a provider that never verifies
			// anything, which breaks social login instead of securing it.
			name:         "victim address the issuer marks verified",
			profile:      map[string]any{"sub": "owner-subject", "email": atkVictimEmail, "email_verified": true},
			wantVerified: true,
			wantLinkable: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := atkOIDCUserInfoIssuer(t, tc.profile)
			p := oauth2.NewOIDCProvider("hostile-idp", srv.URL, "client-1", "client-secret", "https://app.test/cb", "")

			info, err := p.UserInfo(context.Background(), "attacker-access-token")
			if err != nil {
				t.Fatalf("UserInfo: %v", err)
			}
			if info.Email != atkVictimEmail {
				t.Fatalf("Email = %q, want %q: the fixture is not exercising the attack", info.Email, atkVictimEmail)
			}
			if info.EmailVerified != tc.wantVerified {
				t.Errorf("EmailVerified = %v, want %v for a profile carrying %q",
					info.EmailVerified, tc.wantVerified, atkVictimEmail)
			}

			// The local account is verified, so the provider's flag alone decides.
			if got := atkLinkableToExistingAccount(info.EmailVerified, true); got != tc.wantLinkable {
				t.Errorf("linkable = %v, want %v: a login that reaches the victim's user id "+
					"mints the victim's tokens on this and every later login", got, tc.wantLinkable)
			}
		})
	}
}

// TestOAuthVerifiedAddressStillNeedsAVerifiedLocalAccount pins the other half of
// the rule. A provider that verifies addresses is not authority over an account
// whose own address was never confirmed, because that account's address is
// itself unproven and may have been squatted at registration.
func TestOAuthVerifiedAddressStillNeedsAVerifiedLocalAccount(t *testing.T) {
	srv := atkOIDCUserInfoIssuer(t, map[string]any{
		"sub": "owner-subject", "email": atkVictimEmail, "email_verified": true,
	})
	p := oauth2.NewOIDCProvider("hostile-idp", srv.URL, "client-1", "client-secret", "https://app.test/cb", "")

	info, err := p.UserInfo(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if !info.EmailVerified {
		t.Fatalf("EmailVerified = false for an issuer that claims verification; the fixture is wrong")
	}
	if atkLinkableToExistingAccount(info.EmailVerified, false) {
		t.Error("a verified provider address linked to an unverified local account: " +
			"whoever registered that address without confirming it would receive the tokens")
	}
}
