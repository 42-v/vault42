package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/audit"
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
	auditLog      *audit.Logger
}

// NewWebAuthnHandler creates a new WebAuthn handler.
func NewWebAuthnHandler(repo repository.WebAuthnRepository, userRepo repository.UserRepository, c cache.Cache, wan *webauthn.WebAuthn, authSvc *service.AuthService, secureCookies bool) *WebAuthnHandler {
	return &WebAuthnHandler{webauthnRepo: repo, userRepo: userRepo, cache: c, wan: wan, authSvc: authSvc, secureCookies: secureCookies}
}

// SetAuditLog attaches the audit logger. Called once at wiring time; a nil
// logger is ignored.
func (h *WebAuthnHandler) SetAuditLog(l *audit.Logger) {
	if l != nil {
		h.auditLog = l
	}
}

// logEvent records a WebAuthn credential lifecycle event against the user's
// trail.
//
// A passkey is a permanent key on the account, and until 1.0.0 binding one left
// no record: this handler had no logger, so an attacker on a stolen session
// could enroll their own authenticator, then keep logging in as the owner long
// after the stolen session expired, and the trail showed only the owner's own
// logins. Removal is recorded for the same reason in reverse, since taking the
// owner's key off the account is how the lockout is made to stick.
//
// Best-effort on purpose. A trail that can refuse an assertion the authenticator
// just signed would convert an audit outage into an authentication outage.
func (h *WebAuthnHandler) logEvent(r *http.Request, event, userID string, meta map[string]interface{}) {
	if h.auditLog == nil {
		return
	}
	h.auditLog.Log(r.Context(), event, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
		r.Header.Get("User-Agent"), "", "", meta, 0)
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
		Flags:        int(credential.Flags.MsgpByte()),
		CreatedAt:    time.Now(),
	}); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	h.logEvent(r, audit.TwoFASetup, claims.Subject, map[string]interface{}{
		"method":        "webauthn",
		"action":        "enrolled",
		"credential_id": credID,
	})

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

	// Parsed here rather than inside FinishLogin so the flags of a credential
	// enrolled before they were persisted can be adopted from this assertion.
	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		log.Printf("webauthn: parse assertion failed: %v", err)
		WriteError(w, http.StatusUnauthorized, "webauthn_verification_failed")
		return
	}
	adoptUnknownCredentialFlags(wanCreds, parsed)

	wanUser := &model.WebAuthnUser{User: user, Credentials: wanCreds}

	credential, err := h.wan.ValidateLogin(wanUser, session, parsed)
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
		if string(stored.CredentialID) != string(credential.ID) {
			continue
		}
		if err := h.webauthnRepo.UpdateSignCount(r.Context(), stored.ID, int(credential.Authenticator.SignCount)); err != nil {
			log.Printf("webauthn: CRITICAL sign count update failed for user %s: %v", claims.Subject, err)
			WriteError(w, http.StatusInternalServerError, "webauthn_error")
			return
		}
		// BackupState changes whenever a synced passkey moves in or out of its
		// backup, and a credential enrolled before flags were stored records
		// them here for the first time. go-webauthn compares the stored flags
		// against the next assertion, so a stale value rejects the next login.
		// Written after the sign count: that is the anti-clone control and must
		// land first, while a lost flags write is recovered by the adoption path
		// on the following assertion.
		if flags := int(credential.Flags.MsgpByte()); flags != stored.Flags {
			if err := h.webauthnRepo.UpdateFlags(r.Context(), stored.ID, flags); err != nil {
				log.Printf("webauthn: CRITICAL flags update failed for user %s: %v", httputil.SafeLogValue(claims.Subject), err)
				WriteError(w, http.StatusInternalServerError, "webauthn_error")
				return
			}
		}
		break
	}

	// Recorded before the login is completed and regardless of how it ends. The
	// assertion was verified here; whether the session that follows is issued
	// or refused by account policy is a separate fact the login path records for
	// itself, and folding the two together would lose every verification that
	// happened against a banned or locked account.
	h.logEvent(r, audit.TwoFAVerify, claims.Subject, map[string]interface{}{"method": "webauthn"})

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

	// Filed under the enrollment event with action=removed because the
	// vocabulary in internal/audit has no removal constant; a query for factor
	// changes must therefore read the action key rather than the event type
	// alone.
	h.logEvent(r, audit.TwoFASetup, claims.Subject, map[string]interface{}{
		"method":        "webauthn",
		"action":        "removed",
		"credential_id": credID,
	})

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "credential_removed"})
}

// modelCredsToWebAuthn converts stored credentials to the go-webauthn Credential type.
func modelCredsToWebAuthn(creds []*model.WebAuthnCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		out[i] = webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Flags:     webauthn.CredentialFlagsFromMsgpByte(byte(c.Flags & 0xFF)),
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(c.SignCount), // #nosec G115 -- SignCount stored as non-negative int
			},
		}
	}
	return out
}

// adoptUnknownCredentialFlags fills in the authenticator flags of credentials
// that have none recorded (stored value 0) from the assertion about to be
// validated.
//
// go-webauthn rejects a login outright when the stored BackupEligible flag
// disagrees with the assertion, so a credential enrolled before flags were
// persisted could never authenticate again: it would claim BE=0 forever while a
// synced passkey asserts BE=1. 0 is unambiguously "never recorded" because user
// presence is mandatory in every ceremony, so bit 0 is set in any genuine value.
//
// This is not a downgrade path. ValidateLogin verifies the assertion signature
// against the stored public key before the credential is returned, and nothing
// is persisted unless that succeeds, so only the holder of the credential
// private key can influence the adopted flags -- and that holder can already
// authenticate. BackupEligible is self-asserted by the authenticator and, under
// the "none" attestation this service accepts, was never attested at
// registration either; the library treats it as a consistency check, and
// consistency can only be established from the first assertion we can verify.
func adoptUnknownCredentialFlags(creds []webauthn.Credential, parsed *protocol.ParsedCredentialAssertionData) {
	for i := range creds {
		if creds[i].Flags.ProtocolValue() != 0 || !bytes.Equal(creds[i].ID, parsed.RawID) {
			continue
		}
		creds[i].Flags = webauthn.NewCredentialFlags(parsed.Response.AuthenticatorData.Flags)
	}
}
