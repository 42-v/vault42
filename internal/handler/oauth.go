package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/sanitize"
	"github.com/42-v/vault42/internal/service"
)

// OAuthHandler handles OAuth2 social login endpoints.
type OAuthHandler struct {
	providers     map[string]oauth2.Provider
	hmacSecret    []byte
	cache         cache.Cache
	origin        string
	users         repository.UserRepository
	social        repository.SocialAccountRepository
	tokens        repository.RefreshTokenRepository
	authSvc       *service.AuthService
	tokenSvc      *service.TokenService
	mfaSvc        *service.MFAService
	auditLog      *audit.Logger
	secureCookies bool
}

// NewOAuthHandler creates a new OAuth handler.
func NewOAuthHandler(
	providers map[string]oauth2.Provider,
	hmacSecret []byte,
	c cache.Cache,
	origin string,
	users repository.UserRepository,
	social repository.SocialAccountRepository,
	tokens repository.RefreshTokenRepository,
	authSvc *service.AuthService,
	tokenSvc *service.TokenService,
	mfaSvc *service.MFAService,
	auditLog *audit.Logger,
	secureCookies bool,
) *OAuthHandler {
	return &OAuthHandler{
		providers: providers, hmacSecret: hmacSecret, cache: c,
		origin: origin, users: users, social: social, tokens: tokens,
		authSvc: authSvc, tokenSvc: tokenSvc, mfaSvc: mfaSvc, auditLog: auditLog,
		secureCookies: secureCookies,
	}
}

// Authorize handles GET /auth/oauth2/authorize.
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	providerName := r.URL.Query().Get("provider")
	provider, ok := h.providers[providerName]
	if !ok {
		WriteError(w, http.StatusBadRequest, "unknown_provider")
		return
	}

	// Generate PKCE challenge
	verifier, err := vaultcrypto.RandomHex(32)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	challenge := vaultcrypto.SHA256Base64URL(verifier)

	// Generate state with HMAC signature + expiry
	nonce, err := vaultcrypto.RandomHex(32)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())

	// Bind the flow to the initiating browser (audit M3): mint a random CSRF
	// token, set it as a short-lived host-only cookie, and embed its hash in the
	// signed state. The callback recomputes the hash from the cookie and compares,
	// so a state minted for one browser cannot be replayed into another (OAuth
	// login CSRF / session fixation).
	csrfToken, err := vaultcrypto.RandomHex(32)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	csrfHash := vaultcrypto.SHA256Hex(csrfToken)

	statePayload := fmt.Sprintf("%s.%s.%s.%s", providerName, nonce, expiry, csrfHash)
	sig := vaultcrypto.HMACSign([]byte(statePayload), h.hmacSecret)
	state := fmt.Sprintf("%s.%s", statePayload, sig)

	setOAuthStateCookie(w, csrfToken, h.secureCookies)

	// Store verifier in cache (keyed by nonce) — failure here means the callback will reject the state
	if err := h.cache.Set(r.Context(), "oauth_state:"+nonce, verifier, 10*time.Minute); err != nil {
		log.Printf("oauth: failed to store PKCE verifier: %v", err)
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Audit log
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.OAuth2Authorize, "", "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{
				"provider": providerName,
			}, 0)
	}

	authURL := provider.AuthURL(state, nonce, challenge)
	if !isSafeAuthorizeRedirect(authURL) {
		// providerName reaches us from the request path. Quote it so a crafted
		// value cannot forge extra log records (CWE-117).
		log.Printf("oauth: provider %s produced an unsafe authorize URL", strconv.Quote(providerName))
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- authURL is server-configured (static provider map) and validated by isSafeAuthorizeRedirect to be an absolute https URL
}

const oauthStateCookie = "__Host-oauth_state" // #nosec G101 -- cookie name constant, not a credential

// setOAuthStateCookie binds the OAuth flow to the initiating browser. SameSite=Lax
// (not Strict) so it survives the top-level GET redirect back from the provider;
// host-only + HttpOnly so it is not script-readable or scoped to other hosts.
func setOAuthStateCookie(w http.ResponseWriter, token string, secure bool) {
	// #nosec G124 -- Secure is derived from TLS state at runtime; HttpOnly + SameSite=Lax pinned.
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

func clearOAuthStateCookie(w http.ResponseWriter, secure bool) {
	// #nosec G124 -- Secure is derived from TLS state at runtime; HttpOnly + SameSite=Lax pinned.
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// isSafeAuthorizeRedirect reports whether a provider-supplied authorize URL is a
// well-formed absolute https:// URL. The authorize endpoint is server-configured
// (built from the static provider map, never from request input), so this is
// defense-in-depth against a misconfigured provider — and it sanitizes the value
// flowing into http.Redirect, closing the open-redirect taint path (gosec G710).
func isSafeAuthorizeRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != ""
}

// linkableToExistingAccount reports whether a provider identity may be attached
// to an account that already holds this email address. Both sides have to be
// verified: the IdP's assertion about the address, and the account's own
// email_verified. Either half alone lets an attacker who can assert an address
// they do not own inherit somebody else's account, and the link is permanent,
// so it becomes a standing passwordless login as that user.
//
// It is a function rather than two inline conditions because the callback
// reaches this decision twice, and the second site did not have it. The
// lookup-hit branch enforced the predicate while the 23505 race fallback adopted
// whichever row won the race, which is the same takeover with a race window in
// front of it. Both sites call this now so they cannot drift apart again.
func linkableToExistingAccount(userInfo *oauth2.UserInfo, existing *model.User) bool {
	return userInfo.EmailVerified && existing.EmailVerified
}

// logRefusedLink records a refused identity link. Both refusal sites log the
// same shape so the two are indistinguishable in an incident review.
func logRefusedLink(providerName string, userInfo *oauth2.UserInfo, existing *model.User) {
	log.Printf("oauth: refusing to link %s to existing user %s (oauth_verified=%v, user_verified=%v)", // #nosec G706 -- sanitized via SafeLogValue
		httputil.SafeLogValue(providerName), existing.ID, userInfo.EmailVerified, existing.EmailVerified)
}

// Callback handles GET /auth/oauth2/callback/{provider}.
//
//nolint:gocognit,gocyclo // OAuth2 callback enforces the full state-validation + nonce-binding + PKCE-exchange flow inline; splitting would scatter the security invariants
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		providerName = r.URL.Query().Get("provider")
	}

	_, ok := h.providers[providerName]
	if !ok {
		WriteError(w, http.StatusBadRequest, "unknown_provider")
		return
	}

	// Check for error response from provider (RFC 6749 §4.1.2.1)
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		log.Printf("oauth: provider %s returned error: %s (%s)", httputil.SafeLogValue(providerName), httputil.SafeLogValue(errCode), httputil.SafeLogValue(r.URL.Query().Get("error_description"))) // #nosec G706 -- sanitized via SafeLogValue
		WriteError(w, http.StatusBadRequest, "provider_denied")
		return
	}

	// Validate state parameter
	state := r.URL.Query().Get("state")
	if state == "" {
		WriteError(w, http.StatusBadRequest, "missing_state")
		return
	}

	// Parse state: "provider.nonce.expiry.signature"
	lastDot := strings.LastIndex(state, ".")
	if lastDot < 0 {
		WriteError(w, http.StatusBadRequest, "invalid_state")
		return
	}
	payload := state[:lastDot]
	sig := state[lastDot+1:]

	// Verify HMAC signature
	if !vaultcrypto.HMACVerify([]byte(payload), h.hmacSecret, sig) {
		WriteError(w, http.StatusBadRequest, "invalid_state")
		return
	}

	// Parse payload parts: "provider.nonce.expiry.csrfHash"
	parts := strings.SplitN(payload, ".", 4)
	if len(parts) != 4 || parts[0] != providerName {
		WriteError(w, http.StatusBadRequest, "invalid_state")
		return
	}
	nonce := parts[1]

	// Verify the flow completes in the same browser that started it (audit M3):
	// the state embeds the hash of a CSRF token mirrored in a host-only cookie.
	// Without this, any HMAC-valid state minted for another browser could be
	// replayed into the victim's browser (session fixation). Clear the one-shot
	// cookie before exchanging the code, regardless of outcome.
	csrfCookie, cookieErr := r.Cookie(oauthStateCookie)
	clearOAuthStateCookie(w, h.secureCookies)
	if cookieErr != nil || csrfCookie.Value == "" ||
		!vaultcrypto.SecureCompare(parts[3], vaultcrypto.SHA256Hex(csrfCookie.Value)) {
		WriteError(w, http.StatusBadRequest, "invalid_state")
		return
	}

	expiry, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		WriteError(w, http.StatusBadRequest, "state_expired")
		return
	}

	// Atomically retrieve and delete PKCE verifier (prevents race condition on reuse)
	verifier, err := h.cache.GetAndDelete(r.Context(), "oauth_state:"+nonce)
	if err != nil || verifier == "" {
		WriteError(w, http.StatusBadRequest, "invalid_or_reused_state")
		return
	}

	// Exchange code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		WriteError(w, http.StatusBadRequest, "missing_code")
		return
	}

	provider := h.providers[providerName]
	tokenResp, err := provider.Exchange(r.Context(), code, verifier)
	if err != nil {
		log.Printf("oauth: exchange failed for %s: %v", httputil.SafeLogValue(providerName), err) // #nosec G706 -- sanitized via SafeLogValue
		WriteError(w, http.StatusBadGateway, "provider_error")
		return
	}

	// For OIDC providers, prefer the cryptographically-verified, nonce-bound ID
	// token over the access-token userinfo call. nonce is the state nonce we
	// minted at /authorize and round-tripped through the signed state.
	var userInfo *oauth2.UserInfo
	if oidcProvider, ok := provider.(*oauth2.OIDCProvider); ok && tokenResp.IDToken != "" {
		userInfo, err = oidcProvider.VerifyIDToken(r.Context(), tokenResp.IDToken, nonce)
		if err != nil {
			log.Printf("oauth: id_token verification failed for %s: %v", httputil.SafeLogValue(providerName), err) // #nosec G706 -- sanitized via SafeLogValue
			WriteError(w, http.StatusBadGateway, "provider_error")
			return
		}
	}

	// Fetch user info from provider (non-OIDC, or OIDC issuer with no id_token).
	if userInfo == nil {
		userInfo, err = provider.UserInfo(r.Context(), tokenResp.AccessToken)
		if err != nil {
			log.Printf("oauth: user info failed for %s: %v", httputil.SafeLogValue(providerName), err) // #nosec G706 -- sanitized via SafeLogValue
			WriteError(w, http.StatusBadGateway, "provider_error")
			return
		}
	}

	// Find or create user
	var userID string
	if h.social != nil {
		existing, _ := h.social.GetByProviderAndID(r.Context(), providerName, userInfo.ID)
		if existing != nil {
			userID = existing.UserID
		}
	}

	if userID == "" && userInfo.Email != "" {
		// Check if a user with this email already exists
		existingUser, _ := h.users.GetByEmail(r.Context(), userInfo.Email)
		if existingUser != nil {
			if !linkableToExistingAccount(userInfo, existingUser) {
				logRefusedLink(providerName, userInfo, existingUser)
				WriteError(w, http.StatusConflict, "email_already_registered")
				return
			}
			userID = existingUser.ID
		} else {
			// Create new user
			newID, err := vaultcrypto.RandomUUID()
			if err != nil {
				WriteError(w, http.StatusInternalServerError, "internal_error")
				return
			}
			now := time.Now()
			if err := h.users.Create(r.Context(), &model.User{
				ID:            newID,
				Email:         userInfo.Email,
				PasswordHash:  "!oauth", // sentinel: unparseable by Argon2id, prevents password login
				EmailVerified: userInfo.EmailVerified,
				DisplayName:   sanitize.String(userInfo.Name, 100),
				AvatarURL:     sanitize.AvatarURL(userInfo.AvatarURL),
				CreatedAt:     now,
				UpdatedAt:     now,
			}); err != nil {
				// Handle concurrent registration race: if another request created
				// a user with this email between our lookup and insert, look them up.
				//
				// The re-lookup lands on a row this flow has never vetted, so it has
				// to re-apply the same predicate as the lookup-hit branch above
				// rather than trust the row for having won a race. Skipping it was a
				// takeover with a race window: a victim registers victim@ex.com
				// (email_verified=false), an attacker completes a social login
				// asserting that address, the GetByEmail above misses, the victim's
				// INSERT commits first, the attacker's Create comes back 23505 and
				// the attacker adopted the victim's id with their own IdP account
				// linked to it. UNIQUE(provider, provider_user_id) does not cover
				// this: it stops one IdP account attaching twice, not a new IdP
				// account attaching to somebody else's user row.
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" {
					raceUser, lookupErr := h.users.GetByEmail(r.Context(), userInfo.Email)
					if lookupErr != nil || raceUser == nil {
						WriteError(w, http.StatusInternalServerError, "internal_error")
						return
					}
					if !linkableToExistingAccount(userInfo, raceUser) {
						logRefusedLink(providerName, userInfo, raceUser)
						WriteError(w, http.StatusConflict, "email_already_registered")
						return
					}
					userID = raceUser.ID
				} else {
					WriteError(w, http.StatusInternalServerError, "internal_error")
					return
				}
			} else {
				userID = newID
				// A provider that does not vouch for the address creates an
				// unverified account, and without this mail that account can never
				// become verified. GET /auth/verify-email consumes a token it never
				// issues, so the only token that exists is one the user was sent;
				// send none and there is no route left. The address is taken from
				// here on, so a later login through a provider that does verify it
				// is refused with 409 email_already_registered, and the user is
				// locked out of an account they cannot reach and an address they
				// cannot reuse.
				//
				// A provider that did verify the address created a verified account
				// above, which needs no mail. Delivery is fire-and-forget: the row
				// is committed, and a mailer outage must not fail the callback.
				if !userInfo.EmailVerified && h.authSvc != nil {
					h.authSvc.SendSignupVerification(r.Context(), userInfo.Email, userID, "")
				}
			}
		}

		// Link social account — the social link is the identity bridge;
		// if it fails, the OAuth flow must fail to prevent orphaned users.
		if h.social != nil {
			saID, err := vaultcrypto.RandomUUID()
			if err != nil {
				WriteError(w, http.StatusInternalServerError, "internal_error")
				return
			}
			if err := h.social.Create(r.Context(), &model.SocialAccount{
				ID:             saID,
				UserID:         userID,
				Provider:       providerName,
				ProviderUserID: userInfo.ID,
				Email:          userInfo.Email,
				CreatedAt:      time.Now(),
			}); err != nil {
				log.Printf("oauth: failed to link social account for %s", httputil.SafeLogValue(userID)) // #nosec G706 -- sanitized via SafeLogValue
				WriteError(w, http.StatusInternalServerError, "internal_error")
				return
			}
		}
	}

	if userID == "" {
		WriteError(w, http.StatusBadRequest, "unable_to_identify_user")
		return
	}

	// Enforce account state on the OAuth path too (parity with password login +
	// token refresh; 2nd-pass review): OAuth must not become a bypass for a
	// banned/disabled/deleted/locked account. An unclaimed imported account is
	// claimed here, because the OAuth provider has verified ownership of the email
	// and that is a valid claim, clearing import_pending so later logins behave
	// normally.
	acct, _ := h.users.GetByID(r.Context(), userID)
	if acct == nil || acct.Deleted {
		WriteError(w, http.StatusForbidden, "account_unavailable")
		return
	}
	if acct.Banned {
		WriteError(w, http.StatusForbidden, "account_banned")
		return
	}
	if acct.Disabled {
		WriteError(w, http.StatusForbidden, "account_disabled")
		return
	}
	// The lock was missing from this gate while the comment above already claimed
	// parity, and that gap made POST /admin/users/{id}/lock useless against the
	// attacker it exists for. Login answered account_locked and Refresh burned the
	// family, so an operator responding to a suspected takeover saw both of those
	// paths close, while an attacker holding a linked social identity completed a
	// callback and collected a brand new refresh family. The lock stopped every
	// login that had not happened yet except the one already in play.
	//
	// Both sources count, matching Login: the persisted locked_until an operator
	// writes, and the cache auto-lockout the failed-password counter trips.
	// MFAVerifyLocked is the exported reader for that counter.
	//
	// This sits ahead of the import claim and ahead of the 2FA branch on purpose.
	// A locked row must not be claimed (import_pending is cleared once and never
	// comes back), and a locked account must not receive a challenge token, which
	// is a bearer credential carrying its own window to finish in.
	if acct.LockedUntil != nil && time.Now().Before(*acct.LockedUntil) {
		WriteError(w, http.StatusForbidden, "account_locked")
		return
	}
	if h.authSvc != nil && h.authSvc.MFAVerifyLocked(r.Context(), acct.ID) {
		WriteError(w, http.StatusForbidden, "account_locked")
		return
	}
	if acct.ImportPending {
		if err := h.users.ClearImportPending(r.Context(), acct.ID); err != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
	}

	// Compute fingerprint
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             middleware.ClientIP(r),
		UserAgent:      r.Header.Get("User-Agent"),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		TLSFingerprint: middleware.TLSFingerprint(r),
	})

	// Check if user has MFA enabled — issue challenge token instead of full tokens
	if h.mfaSvc != nil {
		requiresMFA, err := h.mfaSvc.RequiresMFA(r.Context(), userID, false)
		if err != nil {
			log.Printf("oauth: MFA status check failed for %s: %v", httputil.SafeLogValue(userID), err) // #nosec G706 -- sanitized via SafeLogValue
			// Fail closed: if MFA status is indeterminate, require it rather than
			// issuing full tokens and silently bypassing a user's second factor.
			requiresMFA = true
		}
		if requiresMFA {
			challengeToken, err := h.tokenSvc.IssueChallengeToken(userID, fp)
			if err != nil {
				WriteError(w, http.StatusInternalServerError, "internal_error")
				return
			}

			if h.auditLog != nil {
				h.auditLog.Log(r.Context(), audit.OAuth2Callback, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
					r.Header.Get("User-Agent"), fp, "", map[string]interface{}{
						"provider":     providerName,
						"mfa_required": true,
					}, 0)
			}

			fragment := url.Values{}
			fragment.Set("requires_2fa", "true")
			fragment.Set("challenge_token", challengeToken)
			redirectURL := h.origin + "/oauth/callback#" + fragment.Encode()
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
	}

	// Issue tokens
	pair, err := h.tokenSvc.IssueTokenPair(
		userID, []string{"user"}, []string{"read", "write"},
		"", fp, "", false,
	)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Store refresh token (hashed) in database
	tokenHash := vaultcrypto.SHA256Hex(pair.RefreshToken)
	rtID, err := vaultcrypto.RandomUUID()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if h.tokens != nil {
		// The concurrent-session cap applies here for the same reason it applies to a
		// password login: this path writes a refresh-token family. The MFA-completing
		// OAuth path is already covered because it finishes through CompleteMFALogin.
		// Client credentials are structurally exempt rather than missing, since that
		// path discards its refresh token and creates no family at all.
		if h.authSvc != nil {
			if err := h.authSvc.CheckSessionLimit(r.Context(), userID); err != nil {
				WriteError(w, http.StatusTooManyRequests, "session_limit_reached")
				return
			}
		}
		if err := h.tokens.Create(r.Context(), &model.RefreshToken{
			ID:              rtID,
			UserID:          userID,
			TokenHash:       tokenHash,
			FamilyID:        pair.FamilyID,
			FingerprintHash: fp,
			ExpiresAt:       pair.RefreshExpAt,
			CreatedAt:       time.Now(),
		}); err != nil {
			log.Printf("oauth: failed to store refresh token for %s: %v", httputil.SafeLogValue(userID), err) // #nosec G706 -- sanitized via SafeLogValue
			WriteError(w, http.StatusInternalServerError, "internal_error")
			return
		}
	}

	// Set refresh token cookie
	setRefreshCookie(w, pair.RefreshToken, h.secureCookies, int(time.Until(pair.RefreshExpAt).Seconds()))

	// Audit log
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.OAuth2Callback, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), fp, "", map[string]interface{}{
				"provider": providerName,
			}, 0)
	}

	// Store access token behind a one-time code instead of placing it in the URL fragment.
	// The SPA calls POST /auth/oauth2/exchange with the code to retrieve the token.
	exchangeCode, err := vaultcrypto.RandomHex(32)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	exchangeCodeHash := vaultcrypto.SHA256Hex(exchangeCode)
	exchangeData, _ := json.Marshal(OAuthExchangeData{ // #nosec G117 -- OAuth2 response field name per RFC 6749
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.tokenSvc.AccessTokenTTL().Seconds()),
	})
	// A-5: fp is part of the cache key (not just a payload field) so a wrong-
	// fingerprint Exchange call returns the same "invalid_or_expired_code"
	// 400 as a non-existent code — preventing an enumeration channel that
	// distinguishes "code valid but fingerprint mismatch" from "code expired".
	// Do NOT split this into a separate error path during future refactors.
	h.cache.Set(r.Context(), "oauth_code:"+exchangeCodeHash+":"+fp, string(exchangeData), 60*time.Second) // #nosec G104 -- short-lived one-time code; failure means exchange fails

	fragment := url.Values{}
	fragment.Set("code", exchangeCode)
	redirectURL := h.origin + "/oauth/callback#" + fragment.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Exchange handles POST /auth/oauth2/exchange.
// Exchanges a one-time code (from the OAuth2 callback redirect) for the access token.
func (h *OAuthHandler) Exchange(w http.ResponseWriter, r *http.Request) {
	var input struct {
		// Code is the one-time exchange value from the OAuth2 callback
		// fragment. Required. Empty is 400 invalid_request. Lookup is
		// SHA-256 of this value plus the request fingerprint; a miss or
		// fingerprint change is 400 invalid_or_expired_code so the two
		// cases cannot be distinguished.
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &input); err != nil || input.Code == "" {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	codeHash := vaultcrypto.SHA256Hex(input.Code)
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             middleware.ClientIP(r),
		UserAgent:      r.Header.Get("User-Agent"),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		TLSFingerprint: middleware.TLSFingerprint(r),
	})
	data, err := h.cache.GetAndDelete(r.Context(), "oauth_code:"+codeHash+":"+fp)
	if err != nil || data == "" {
		WriteError(w, http.StatusBadRequest, "invalid_or_expired_code")
		return
	}

	var tokenData OAuthExchangeData
	if err := json.Unmarshal([]byte(data), &tokenData); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, tokenData)
}
