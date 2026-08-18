package compliance

import (
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/service"
)

// =============================================================================
// ASVS 5.0.0 V6.8.4 and V10.3.4 — the authentication-context clauses.
//
// The two requirements are mirror images and were carried as one accepted risk
// (CR-21) on a single sentence: "no acr, amr or aal claim is issued and
// AALForMethods has no non-test caller". Both halves of that sentence stopped
// being true, so the rows are proven here instead of excused.
//
//   - V6.8.4 is the relying-party side. vault42 consumes an upstream IdP and
//     the requirement's final sentence is the operative one: absent acr/amr
//     from the provider, the application must assume the minimum strength
//     mechanism was used. That assumption is what these assertions pin.
//   - V10.3.4 is the resource-server side. vault42 requires authentication
//     recentness for specific functions and checks it against a claim in the
//     presented access token, and it now emits the OIDC claims the requirement
//     names so a downstream resource server can do the same.
//
// Neither test asserts that the upstream acr is ignored forever. They assert
// what the register currently claims: that the level a federated session
// reaches is the floor, and that the recentness gate reads the presented token.
// A change to either is a change the register has to move with.
// =============================================================================

// TestASVS_V6_8_4_FederatedLoginAssumesTheMinimumAuthenticationStrength proves
// the fallback clause of V6.8.4 against the shipped OAuth callback.
//
// Verbatim, the clause: "If the IdP does not provide this information, the
// application must have a documented fallback approach that assumes that the
// minimum strength authentication mechanism was used".
//
// vault42 never asks an upstream provider how it authenticated the user, so the
// fallback is not a branch — it is the only path. A provider assertion is
// modeled as MethodFederated, which AALForMethods treats as a first factor and
// never as a possession factor, so a federated-only session is stamped at the
// floor. Anything above the floor has to be earned by a second factor vault42
// verified itself, which is the property that makes ignoring the upstream acr
// safe rather than merely convenient.
func TestASVS_V6_8_4_FederatedLoginAssumesTheMinimumAuthenticationStrength(t *testing.T) {
	// The floor. A provider assertion alone is one factor whatever the provider
	// says about it.
	if got := service.AALForMethods([]string{service.MethodFederated}, false); got != service.AAL1 {
		t.Errorf("V6.8.4: a federated-only login reached AAL%d, want AAL1. The fallback this row "+
			"rests on is that an unverified upstream assertion is assumed to be the minimum "+
			"strength mechanism; anything higher is a strength vault42 did not observe.", got)
	}
	// userVerified is the WebAuthn UV flag. It must not lift a federated login,
	// or a caller passing it would raise the assumed strength without a second
	// factor existing.
	if got := service.AALForMethods([]string{service.MethodFederated}, true); got != service.AAL1 {
		t.Errorf("V6.8.4: a federated-only login with the user-verification flag set reached "+
			"AAL%d, want AAL1. UV describes a WebAuthn authenticator, not an IdP assertion.", got)
	}
	// Federated is a first factor, never a second one: it may combine with a
	// possession factor vault42 verified, and that is the only way up.
	if got := service.AALForMethods([]string{service.MethodFederated, service.MethodTOTP}, false); got != service.AAL2 {
		t.Errorf("V6.8.4: federated + TOTP reached AAL%d, want AAL2. The second factor vault42 "+
			"verifies itself is what raises the assumed strength.", got)
	}
	if got := service.AALForMethods([]string{service.MethodFederated, service.MethodPassword}, false); got == service.AAL2 || got == service.AAL3 {
		t.Errorf("V6.8.4: two first factors reached AAL%d. MethodFederated must never count as "+
			"the possession factor that completes AAL2.", got)
	}

	// The acr the callback stamps is the AAL1 URN, so a relying party reading
	// the token sees the assumption rather than having to infer it.
	if got := service.ACRForAAL(service.AAL1); !strings.Contains(got, "1") || !strings.HasPrefix(got, "urn:vault42:aal:") {
		t.Errorf("V6.8.4: the acr for the floor is %q, which no longer names the assurance level "+
			"a reader has to be able to compare against.", got)
	}
	// RFC 8176 registers no value for "an assertion from another issuer", so
	// vault42 emits none. An amr value here would name a check this server did
	// not make, which is the failure the requirement is aimed at.
	if got := service.AMRForMethods([]string{service.MethodFederated}, false); len(got) != 0 {
		t.Errorf("V6.8.4: a federated-only login emitted amr %v. vault42 verified no authenticator "+
			"of its own on that path, so naming one asserts a check it did not perform.", got)
	}

	// The callback has to actually apply the fallback. The AuthContext it builds
	// is the whole control: methods = the provider assertion only, UV clear.
	callback := readCodeOnly(t, "internal/handler/oauth.go")
	if !strings.Contains(callback, "service.NewAuthContext(time.Now(), []string{service.MethodFederated}, false)") {
		t.Error("V6.8.4: the OAuth callback no longer issues its token pair with an AuthContext of " +
			"MethodFederated alone. Either it now reads the provider's acr/amr — in which case this " +
			"row's argument changes from 'assumes the minimum' to 'verifies what the IdP returned' " +
			"and the register has to say so — or the strength assumption has been dropped.")
	}
	// A provider assertion never satisfies an enrolled second factor: the
	// callback still routes an MFA-enrolled user through the challenge, carrying
	// the federated first factor rather than claiming a password.
	if !strings.Contains(callback, "IssueChallengeToken(r.Context(), userID, fp, service.MethodFederated)") {
		t.Error("V6.8.4: the OAuth callback no longer issues a second-factor challenge carrying " +
			"MethodFederated. If a federated login can now complete without vault42's own second " +
			"factor, the assumed minimum strength is being used to skip a check rather than to " +
			"bound a claim.")
	}
}

// TestASVS_V10_3_4_RecentnessIsVerifiedAgainstThePresentedAccessToken proves
// V10.3.4 against the confirmation gate.
//
// Verbatim: "if the resource server requires specific authentication strength,
// methods, or recentness, it verifies that the presented access token satisfies
// these constraints. For example, if present, using the OIDC 'acr', 'amr' and
// 'auth_time' claims respectively."
//
// vault42 requires recentness for the destructive account operations, and the
// check is bound to the presented token: middleware.Confirmed stores the jti of
// the access token that performed POST /auth/confirm and refuses any other one,
// so a confirmation cannot be carried across a rotation. That is a strictly
// tighter binding than comparing auth_time, which survives rotation and is
// self-asserted by the issuer.
//
// The example mechanism is covered too: the access token now carries acr, amr
// and auth_time, so a downstream resource server can apply the same constraint
// the way the requirement describes.
func TestASVS_V10_3_4_RecentnessIsVerifiedAgainstThePresentedAccessToken(t *testing.T) {
	mw := readCodeOnly(t, "internal/middleware/auth.go")
	if !strings.Contains(mw, "func Confirmed(") {
		t.Fatal("V10.3.4: middleware.Confirmed is gone. It is the only place a recentness " +
			"constraint is enforced, so without it the resource server requires a recentness it " +
			"never checks.")
	}
	// The binding to the presented token is the clause. A gate that only asked
	// "did this user confirm recently" would be satisfied by a token minted
	// after the confirmation, which is the case the requirement exists for.
	if !strings.Contains(mw, "val != claims.ID") {
		t.Error("V10.3.4: the confirmation gate no longer compares the stored jti against the " +
			"presented token's own claim. Without that comparison the constraint is checked " +
			"against server-side state rather than against the access token, which is what this " +
			"requirement asks for.")
	}
	if !strings.Contains(mw, "requires_confirmation") {
		t.Error("V10.3.4: the confirmation gate no longer fails closed with requires_confirmation")
	}

	// The gate has to be in front of the functions that require it. Counting the
	// mounts rather than naming one route keeps this from passing on a single
	// survivor after the others are unwired.
	routes := readCodeOnly(t, "internal/server/server.go")

	// The confirmed(...) route builder carries the gate for six second-factor
	// management routes on its own, and the count below cannot see it go: the
	// clean tree has four confirmMw call sites, so deleting the one inside that
	// closure lands exactly on the floor of three and the count stays green
	// while TOTP setup and disable, both WebAuthn registration steps, credential
	// deletion and backup-code generation all lose their only password re-entry.
	// Resolve the closure rather than counting the text.
	//
	// The behavioral half is
	// TestSecondFactorManagementRefusesATokenThatHasNotConfirmedItsPassword in
	// package server, which drives all six with a valid but unconfirmed token.
	if idx := strings.Index(routes, "confirmed := func("); idx < 0 {
		t.Error("V10.3.4: internal/server no longer defines a confirmed(...) route builder; the " +
			"six second-factor management routes take their recentness gate from it")
	} else {
		body := routes[idx:]
		if end := strings.Index(body, "\n\t}"); end > 0 {
			body = body[:end]
		}
		if !strings.Contains(body, "confirmMw(") {
			t.Errorf("V10.3.4: the confirmed(...) route builder no longer applies confirmMw, so "+
				"second-factor enrollment and removal are reachable with a stolen access token and "+
				"no password. It is defined as %s", body)
		}
	}

	const confirmedRouteFloor = 3
	if n := strings.Count(routes, "confirmMw("); n < confirmedRouteFloor {
		t.Errorf("V10.3.4: confirmMw guards %d call sites, below the floor of %d. The register "+
			"claims the recentness constraint is enforced on the destructive account operations "+
			"(DELETE /user/identity and both blob deletes); fewer mounts means it is not.",
			n, confirmedRouteFloor)
	}
	for _, route := range []string{`"DELETE /user/identity"`, `"DELETE /user/blobs/{id}"`} {
		if !strings.Contains(routes, route) {
			t.Errorf("V10.3.4: %s is no longer mounted; re-derive which functions require "+
				"recentness before leaving this row Met", route)
		}
	}

	// The worked example the requirement gives, made available to a downstream
	// resource server rather than only to vault42's own middleware.
	claims := readCodeOnly(t, "internal/crypto/jwt.go")
	for _, claim := range []string{`json:"acr,omitempty"`, `json:"amr,omitempty"`, `json:"auth_time,omitempty"`} {
		if !strings.Contains(claims, claim) {
			t.Errorf("V10.3.4: VaultClaims no longer declares %s. The requirement names acr, amr "+
				"and auth_time as the way a resource server checks strength, methods and "+
				"recentness; dropping one removes that option for every downstream service.", claim)
		}
	}
	// A claim that is never populated is a field, not evidence. The issuance
	// path has to set it from an observed authentication event.
	token := readCodeOnly(t, "internal/service/token.go")
	for _, field := range []string{"ACR:", "AMR:", "AuthTime:"} {
		if !strings.Contains(token, field) {
			t.Errorf("V10.3.4: the token issuance path no longer populates %s, so the claim would "+
				"be omitted from every token", strings.TrimSuffix(field, ":"))
		}
	}
	// The strength a resource server would read has to move with the factors.
	if service.ACRForAAL(service.AALForMethods([]string{service.MethodPassword}, false)) ==
		service.ACRForAAL(service.AALForMethods([]string{service.MethodPassword, service.MethodTOTP}, false)) {
		t.Error("V10.3.4: a single-factor and a two-factor login now stamp the same acr, so a " +
			"resource server requiring a specific authentication strength cannot distinguish them " +
			"from the presented token.")
	}
}
