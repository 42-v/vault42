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
	statePayload := fmt.Sprintf("%s.%s.%s", providerName, nonce, expiry)
	sig := vaultcrypto.HMACSign([]byte(statePayload), h.hmacSecret)
	state := fmt.Sprintf("%s.%s", statePayload, sig)

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
	http.Redirect(w, r, authURL, http.StatusFound)
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

	// Parse payload parts: "provider.nonce.expiry"
	parts := strings.SplitN(payload, ".", 3)
	if len(parts) != 3 || parts[0] != providerName {
		WriteError(w, http.StatusBadRequest, "invalid_state")
		return
	}
	nonce := parts[1]
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

	// Fetch user info from provider
	userInfo, err := provider.UserInfo(r.Context(), tokenResp.AccessToken)
	if err != nil {
		log.Printf("oauth: user info failed for %s: %v", httputil.SafeLogValue(providerName), err) // #nosec G706 -- sanitized via SafeLogValue
		WriteError(w, http.StatusBadGateway, "provider_error")
		return
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
			// SECURITY: Only link to existing account when BOTH the OAuth provider
			// confirms the email is verified AND the existing account's email is verified.
			// This prevents account takeover via unverified OAuth emails.
			if !userInfo.EmailVerified || !existingUser.EmailVerified {
				log.Printf("oauth: refusing to link %s to existing user %s (oauth_verified=%v, user_verified=%v)", // #nosec G706 -- sanitized via SafeLogValue
					httputil.SafeLogValue(providerName), existingUser.ID, userInfo.EmailVerified, existingUser.EmailVerified)
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
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "23505" {
					raceUser, lookupErr := h.users.GetByEmail(r.Context(), userInfo.Email)
					if lookupErr != nil || raceUser == nil {
						WriteError(w, http.StatusInternalServerError, "internal_error")
						return
					}
					userID = raceUser.ID
				} else {
					WriteError(w, http.StatusInternalServerError, "internal_error")
					return
				}
			} else {
				userID = newID
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
