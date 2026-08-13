package handler

import (
	"errors"
	"net/http"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/service"
)

// completeMFAIfChallenge checks whether the current token is a 2FA challenge
// token and, if so, completes the MFA login flow by issuing real tokens. It
// returns true if the response was written (caller should return), false if the
// caller should continue with its own response.
func completeMFAIfChallenge(w http.ResponseWriter, r *http.Request, claims *vaultcrypto.VaultClaims, authSvc *service.AuthService, secureCookies bool) bool {
	if claims.TokenType != "2fa_challenge" || authSvc == nil {
		return false
	}

	ip := middleware.ClientIP(r)
	ua := r.Header.Get("User-Agent")
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             ip,
		UserAgent:      ua,
		AcceptLanguage: r.Header.Get("Accept-Language"),
		TLSFingerprint: middleware.TLSFingerprint(r),
	})
	// Enforce the device/network binding the challenge token carries (audit M1):
	// a challenge minted for one device must not be redeemed from another.
	if !authSvc.ChallengeFingerprintMatches(r.Context(), claims.Subject, claims.Fingerprint, fp, ip, ua) {
		WriteError(w, http.StatusUnauthorized, "invalid_token")
		return true
	}
	result, err := authSvc.CompleteMFALogin(r.Context(), claims.Subject, fp, ip, ua, claims.ID)
	if err != nil {
		// CompleteMFALogin re-reads account state and deliberately refuses a
		// banned, disabled, locked or deleted account, because the challenge TTL
		// is exactly the window in which an operator's ban has to take effect.
		// Login, Refresh and the OAuth callback all map those refusals to a 403
		// naming the policy. This transport mapped two errors and sent
		// everything else to 500.
		//
		// So the gate worked and then reported itself as a server fault. A bulk
		// ban spiked the 5xx rate, and a caller could not tell a refusal by
		// policy from a vault42 that was broken. The order below matches
		// internal/handler/auth.go so the four transports cannot drift apart
		// again.
		switch {
		case errors.Is(err, service.ErrChallengeConsumed):
			WriteError(w, http.StatusUnauthorized, "challenge_consumed")
		case errors.Is(err, service.ErrTokenInvalid):
			WriteError(w, http.StatusUnauthorized, "invalid_token")
		case errors.Is(err, service.ErrAccountLocked):
			WriteError(w, http.StatusForbidden, "account_locked")
		case errors.Is(err, service.ErrAccountBanned):
			WriteError(w, http.StatusForbidden, "account_banned")
		case errors.Is(err, service.ErrAccountDisabled):
			WriteError(w, http.StatusForbidden, "account_disabled")
		case errors.Is(err, service.ErrTooManySessions):
			WriteError(w, http.StatusTooManyRequests, "too_many_sessions")
		default:
			WriteError(w, http.StatusInternalServerError, "internal_error")
		}
		return true
	}
	setRefreshCookie(w, result.RefreshToken, secureCookies, result.CookieMaxAge)
	WriteJSON(w, http.StatusOK, result)
	return true
}
