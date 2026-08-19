package handler

import (
	"log"
	"net/http"

	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/service"
)

// revokeSessionsAfterFactorChange tears down every refresh-token family the
// subject holds, after their second factor was enrolled, disabled or removed.
//
// Why the mutating factor routes need it at all. Nothing on the refresh path
// re-reads the enrolled factors: Refresh consults the account-state flags and
// the family's own rotation state, and neither changes when a factor does. So a
// live session is invisible to a factor change by construction, and the family
// an attacker is rotating survives the response that tells the victim they have
// contained the compromise, for the whole absolute session lifetime
// (VAULT_MAX_SESSION_LIFETIME, 720h by default).
//
// That matters because rotating the second factor is exactly what the product
// tells a user to do when they think a device or an authenticator was taken.
// Deleting the possibly-cloned passkey, disabling and re-enrolling TOTP and
// printing a fresh set of backup codes all returned 200 and revoked nothing,
// while the only levers that did work — password change, sign-out-everywhere,
// admin lock — are not the ones the MFA screen offers.
//
// Every family, including the caller's own. Two reasons, in order:
//
//   - It is what the password-change path does. updatePassword calls the same
//     RevokeAllForUser with no exception for the acting session, and one
//     revocation rule is worth more than a second, subtly different one.
//   - The handler could not implement an exception if it wanted to. The access
//     token carries no family id (crypto.VaultClaims has sub, jti, roles,
//     scopes, fingerprint and token type, and no family), so "revoke everything
//     but mine" would mean adding a claim, i.e. a new mechanism, to spare the
//     caller a re-login.
//
// The cost is small and the routes are the reason. All five sit behind
// confirmed(...), so the caller re-entered their password moments ago, and the
// access token they are holding survives to its own TTL — only the refresh
// families die. The flow in progress therefore completes; what does not survive
// is the ability to rotate any family forward, which is precisely the thing a
// stolen session needs.
//
// A failed revoke is returned rather than logged and dropped. The factor change
// has already been written at every call site, so failing the request reports a
// torn state — but the alternative is a 200 that reads exactly like successful
// containment while the attacker keeps every session, and a victim who stops
// looking. The password-change path makes the same trade for the same reason.
// The caller's next move is the lever that does work: sign out everywhere, or
// change the password.
//
// A nil AuthService means the handler was built without one, which also
// disables the MFA lockout gate and MFA login completion. There is nothing to
// revoke through and nothing to report; production wiring always passes one.
func revokeSessionsAfterFactorChange(r *http.Request, authSvc *service.AuthService, userID, factor, action string) error {
	if authSvc == nil {
		return nil
	}
	err := authSvc.RevokeAllTokensForUser(r.Context(), userID)
	if err != nil {
		log.Printf("handler: CRITICAL session revocation failed after %s was %s for user %s: %v",
			factor, action, httputil.SafeLogValue(userID), err)
	}
	return err
}
