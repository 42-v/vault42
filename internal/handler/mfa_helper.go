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
	result, err := authSvc.CompleteMFALogin(r.Context(), claims.Subject, fp, ip, ua, claims.ID)
	if err != nil {
		if errors.Is(err, service.ErrChallengeConsumed) {
			WriteError(w, http.StatusUnauthorized, "challenge_consumed")
			return true
		}
		if errors.Is(err, service.ErrTooManySessions) {
			WriteError(w, http.StatusTooManyRequests, "too_many_sessions")
			return true
		}
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return true
	}
	setRefreshCookie(w, result.RefreshToken, secureCookies, result.CookieMaxAge)
	WriteJSON(w, http.StatusOK, result)
	return true
}
