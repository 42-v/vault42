package handler

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// WebAuthnHandler handles WebAuthn/FIDO2 endpoints.
type WebAuthnHandler struct {
	webauthnRepo  repository.WebAuthnRepository
	userRepo      repository.UserRepository
	cache         cache.Cache
	wan           *webauthn.WebAuthn
	authSvc       *service.AuthService
	secureCookies bool
}

// NewWebAuthnHandler creates a new WebAuthn handler.
func NewWebAuthnHandler(repo repository.WebAuthnRepository, userRepo repository.UserRepository, c cache.Cache, wan *webauthn.WebAuthn, authSvc *service.AuthService, secureCookies bool) *WebAuthnHandler {
	return &WebAuthnHandler{webauthnRepo: repo, userRepo: userRepo, cache: c, wan: wan, authSvc: authSvc, secureCookies: secureCookies}
}

// RegisterBegin handles POST /auth/2fa/webauthn/register/begin.
func (h *WebAuthnHandler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	if h.wan == nil {
		WriteError(w, http.StatusNotImplemented, "webauthn_not_configured")
		return
	}
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Load existing credentials for exclusion list
	existing, err := h.webauthnRepo.ListByUser(r.Context(), claims.Subject)
	if err != nil {
		log.Printf("webauthn: failed to list credentials for %s: %v", httputil.SafeLogValue(claims.Subject), err)
	}
	wanCreds := modelCredsToWebAuthn(existing)

	wanUser := &model.WebAuthnUser{User: user, Credentials: wanCreds}

	creation, session, err := h.wan.BeginRegistration(wanUser)
	if err != nil {
		log.Printf("webauthn: begin registration failed: %v", err)
		WriteError(w, http.StatusInternalServerError, "webauthn_error")
		return
	}

	// Store session data in cache (5 min TTL)
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	cacheKey := "webauthn_reg:" + claims.Subject
	if err := h.cache.Set(r.Context(), cacheKey, string(sessionBytes), 5*time.Minute); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, creation)
}

// RegisterFinish handles POST /auth/2fa/webauthn/register/finish.
func (h *WebAuthnHandler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	if h.wan == nil {
		WriteError(w, http.StatusNotImplemented, "webauthn_not_configured")
		return
	}
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Atomically retrieve and consume session data (prevents reuse race)
	cacheKey := "webauthn_reg:" + claims.Subject
	sessionStr, err := h.cache.GetAndDelete(r.Context(), cacheKey)
	if err != nil || sessionStr == "" {
		WriteError(w, http.StatusBadRequest, "no_pending_registration")
		return
	}

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionStr), &session); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Load existing credentials
	existing, _ := h.webauthnRepo.ListByUser(r.Context(), claims.Subject)
	wanCreds := modelCredsToWebAuthn(existing)
	wanUser := &model.WebAuthnUser{User: user, Credentials: wanCreds}

	credential, err := h.wan.FinishRegistration(wanUser, session, r)
	if err != nil {
		log.Printf("webauthn: finish registration failed: %v", err)
		WriteError(w, http.StatusBadRequest, "webauthn_verification_failed")
		return
	}

	// Store credential in DB
	credID, err := vaultcrypto.RandomUUID()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if err := h.webauthnRepo.Create(r.Context(), &model.WebAuthnCredential{
		ID:           credID,
		UserID:       claims.Subject,
		CredentialID: credential.ID,
		PublicKey:    credential.PublicKey,
		SignCount:    int(credential.Authenticator.SignCount), // #nosec G115 -- uint32 fits in int
		CreatedAt:    time.Now(),
	}); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "webauthn_registered"})
}

// VerifyBegin handles POST /auth/2fa/webauthn/verify/begin.
func (h *WebAuthnHandler) VerifyBegin(w http.ResponseWriter, r *http.Request) {
	if h.wan == nil {
		WriteError(w, http.StatusNotImplemented, "webauthn_not_configured")
		return
	}
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	existing, err := h.webauthnRepo.ListByUser(r.Context(), claims.Subject)
	if err != nil || len(existing) == 0 {
		WriteError(w, http.StatusBadRequest, "no_webauthn_credentials")
		return
	}
	wanCreds := modelCredsToWebAuthn(existing)
	wanUser := &model.WebAuthnUser{User: user, Credentials: wanCreds}

	assertion, session, err := h.wan.BeginLogin(wanUser)
	if err != nil {
		log.Printf("webauthn: begin login failed: %v", err)
		WriteError(w, http.StatusInternalServerError, "webauthn_error")
		return
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	cacheKey := "webauthn_auth:" + claims.Subject
	if err := h.cache.Set(r.Context(), cacheKey, string(sessionBytes), 5*time.Minute); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, assertion)
}

// VerifyFinish handles POST /auth/2fa/webauthn/verify/finish.
func (h *WebAuthnHandler) VerifyFinish(w http.ResponseWriter, r *http.Request) {
	if h.wan == nil {
		WriteError(w, http.StatusNotImplemented, "webauthn_not_configured")
		return
	}
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Atomically retrieve and consume session data (prevents reuse race)
	cacheKey := "webauthn_auth:" + claims.Subject
	sessionStr, err := h.cache.GetAndDelete(r.Context(), cacheKey)
	if err != nil || sessionStr == "" {
		WriteError(w, http.StatusBadRequest, "no_pending_verification")
		return
	}

	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionStr), &session); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	existing, _ := h.webauthnRepo.ListByUser(r.Context(), claims.Subject)
	wanCreds := modelCredsToWebAuthn(existing)
	wanUser := &model.WebAuthnUser{User: user, Credentials: wanCreds}

	credential, err := h.wan.FinishLogin(wanUser, session, r)
	if err != nil {
		log.Printf("webauthn: finish login failed: %v", err)
		WriteError(w, http.StatusUnauthorized, "webauthn_verification_failed")
		return
	}

	// A-2: go-webauthn returns success with CloneWarning=true when the new
	// sign count is not strictly greater than the stored one. FIDO2 §6.1.4.5
	// treats this as evidence the authenticator may have been cloned. Revoke
	// every active refresh-token family for the user and reject the assertion.
	if credential.Authenticator.CloneWarning {
		// Both fields reach us from the caller (token subject, assertion
		// credential). Quote them so neither can inject CR/LF and forge extra
		// log records (CWE-117).
		log.Printf("webauthn: CRITICAL clone warning user=%s cred=%s",
			strconv.Quote(claims.Subject), strconv.Quote(hex.EncodeToString(credential.ID)))
		_ = h.authSvc.RevokeAllTokensForUser(r.Context(), claims.Subject)
		WriteError(w, http.StatusUnauthorized, "cloned_authenticator_detected")
		return
	}

	// Update sign count in DB — fail the verification if this fails to prevent
	// replay attacks with cloned authenticators that go undetected due to stale counts.
	for _, stored := range existing {
		if string(stored.CredentialID) == string(credential.ID) {
			if err := h.webauthnRepo.UpdateSignCount(r.Context(), stored.ID, int(credential.Authenticator.SignCount)); err != nil {
				log.Printf("webauthn: CRITICAL sign count update failed for user %s: %v", claims.Subject, err)
				WriteError(w, http.StatusInternalServerError, "webauthn_error")
				return
			}
			break
		}
	}

	// If this is a 2FA challenge (login flow), issue real tokens
	if completeMFAIfChallenge(w, r, claims, h.authSvc, h.secureCookies) {
		return
	}

	WriteJSON(w, http.StatusOK, VerifiedResponse{Verified: true})
}

// ListCredentials handles GET /auth/2fa/webauthn/credentials.
func (h *WebAuthnHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	creds, err := h.webauthnRepo.ListByUser(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	result := make([]CredentialInfo, 0, len(creds))
	for _, c := range creds {
		result = append(result, CredentialInfo{
			ID:        c.ID,
			SignCount: c.SignCount,
			CreatedAt: c.CreatedAt,
		})
	}

	WriteJSON(w, http.StatusOK, CredentialListResponse{Credentials: result})
}

// DeleteCredential handles DELETE /auth/2fa/webauthn/credentials/{id}.
// Requires recent password confirmation.
func (h *WebAuthnHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	credID := r.PathValue("id")
	if credID == "" {
		WriteError(w, http.StatusBadRequest, "missing_credential_id")
		return
	}

	// Verify credential belongs to this user by listing their credentials
	creds, err := h.webauthnRepo.ListByUser(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	found := false
	for _, c := range creds {
		if c.ID == credID {
			found = true
			break
		}
	}
	if !found {
		WriteError(w, http.StatusNotFound, "credential_not_found")
		return
	}

	if err := h.webauthnRepo.Delete(r.Context(), credID, claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "credential_removed"})
}

// modelCredsToWebAuthn converts stored credentials to the go-webauthn Credential type.
func modelCredsToWebAuthn(creds []*model.WebAuthnCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		out[i] = webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(c.SignCount), // #nosec G115 -- SignCount stored as non-negative int
			},
		}
	}
	return out
}
