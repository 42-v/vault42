package handler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// ClientHandler handles client credential endpoints.
type ClientHandler struct {
	clients  repository.ClientRepository
	tokenSvc *service.TokenService
	auditLog *audit.Logger
}

// NewClientHandler creates a new client handler.
func NewClientHandler(clients repository.ClientRepository, tokenSvc *service.TokenService, auditLog *audit.Logger) *ClientHandler {
	return &ClientHandler{clients: clients, tokenSvc: tokenSvc, auditLog: auditLog}
}

// clientAuthFailureIDLimit caps the attempted client id written to the audit
// record. The id is attacker-controlled on the unknown-client path, and an
// unbounded one lets anyone write arbitrarily large rows into the audit table
// at one row per request.
const clientAuthFailureIDLimit = 128

// auditClientAuthFailure records a rejected client-credentials grant.
//
// Every rejection was silent. audit.ClientAuth was emitted only after a
// successful grant, so the four failure paths (unparseable credentials, unknown
// client, inactive client, wrong secret) wrote a 401 and nothing else. The only
// other control on this endpoint is a 10/minute IP-keyed limiter, so a
// distributed brute force against a service client's secret, the credential
// that gates kms:unwrap, mint:token and the service-document store, produced no
// audit trail at all: nothing to alert on, and nothing to reconstruct
// afterwards.
//
// The reason is recorded because the audit log is not visible to the caller.
// Distinguishing an unknown client from a wrong secret is exactly what the 401
// must not do and exactly what an investigator needs.
func (h *ClientHandler) auditClientAuthFailure(r *http.Request, clientID, reason string) {
	if h.auditLog == nil {
		return
	}
	if len(clientID) > clientAuthFailureIDLimit {
		clientID = clientID[:clientAuthFailureIDLimit]
	}
	h.auditLog.Log(r.Context(), audit.ClientAuth, "", clientID, middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
		r.Header.Get("User-Agent"), "", "", map[string]interface{}{
			"result": "failure",
			"reason": reason,
		}, 30)
}

// Token handles POST /client/token (client credentials grant).
func (h *ClientHandler) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192) // explicit limit for gosec G120 visibility

	clientID, clientSecret, ok := parseClientCredentials(r)
	if !ok {
		h.auditClientAuthFailure(r, "", "unparseable_credentials")
		WriteError(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}

	client, err := h.clients.GetByID(r.Context(), clientID)
	if err != nil || client == nil {
		// Burn time to prevent timing attacks (use VerifyPassword for timing parity with the found-client path)
		if _, dummyErr := vaultcrypto.VerifyPassword("dummy", vaultcrypto.DummyHash); errors.Is(dummyErr, vaultcrypto.ErrArgon2Overloaded) {
			WriteError(w, http.StatusServiceUnavailable, "server_busy")
			return
		}
		h.auditClientAuthFailure(r, clientID, "unknown_client")
		WriteError(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}

	if !client.Active {
		// Burn time to prevent timing-based enumeration of revoked vs valid clients
		if _, dummyErr := vaultcrypto.VerifyPassword(clientSecret, client.SecretHash); errors.Is(dummyErr, vaultcrypto.ErrArgon2Overloaded) {
			WriteError(w, http.StatusServiceUnavailable, "server_busy")
			return
		}
		h.auditClientAuthFailure(r, client.ID, "inactive_client")
		WriteError(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}

	// Verify secret
	valid, verifyErr := vaultcrypto.VerifyPassword(clientSecret, client.SecretHash)
	if errors.Is(verifyErr, vaultcrypto.ErrArgon2Overloaded) {
		WriteError(w, http.StatusServiceUnavailable, "server_busy")
		return
	}
	if verifyErr != nil || !valid {
		h.auditClientAuthFailure(r, client.ID, "wrong_secret")
		WriteError(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}

	// Parse requested scopes. PostFormValue for the same reason the credentials
	// use it: the grant is a body-only request, so a proxy that inspects bodies
	// sees the whole of it and no component can be smuggled past in the URL.
	var requestedScopes []string
	if scopeStr := r.PostFormValue("scope"); scopeStr != "" {
		requestedScopes = strings.Split(scopeStr, " ")
	}

	// Intersection of requested and allowed scopes
	grantedScopes := intersectScopes(requestedScopes, client.Scopes)
	if len(requestedScopes) > 0 && len(grantedScopes) == 0 {
		WriteError(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	if len(grantedScopes) == 0 {
		grantedScopes = client.Scopes
	}

	pair, err := h.tokenSvc.IssueTokenPair(
		r.Context(), client.ID, []string{client.Role}, grantedScopes,
		client.ID, "", "", false,
	)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	// Audit log
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.ClientAuth, client.ID, client.ID, middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{
				"client_name": client.Name,
				"scopes":      strings.Join(grantedScopes, " "),
			}, 0)
	}

	WriteJSON(w, http.StatusOK, ClientTokenResponse{
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.tokenSvc.AccessTokenTTL().Seconds()),
		Scope:       strings.Join(grantedScopes, " "),
	})
}

func parseClientCredentials(r *http.Request) (clientID, clientSecret string, ok bool) {
	// Try Authorization header first (Basic auth)
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(auth[6:])
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return parts[0], parts[1], true
			}
		}
	}

	// Try request body.
	//
	// PostFormValue, not FormValue: FormValue calls ParseForm, which merges the
	// URL query into r.Form, so it answers with the query value whenever the body
	// omits the key. That made
	// POST /client/token?client_id=..&client_secret=.. authenticate, which RFC
	// 6749 2.3.1 forbids ("MUST NOT be included in the request URI") because a
	// URL is retained by every component on the path that a body is not: the
	// TLS-terminating ingress access log, any CDN or WAF, Referer on a later
	// navigation, shell history, APM traces. The credential this endpoint takes
	// gates kms:unwrap, mint:token and the service-document store and is
	// long-lived, so the exposure is neither small nor short. vault42's own
	// logger drops the query (internal/middleware/logger.go), which is exactly
	// why the server has to refuse the parameter rather than rely on scrubbing:
	// the leak lands outside vault42.
	clientID = r.PostFormValue("client_id")
	clientSecret = r.PostFormValue("client_secret")
	if clientID != "" && clientSecret != "" {
		return clientID, clientSecret, true
	}

	return "", "", false
}

func intersectScopes(requested, allowed []string) []string {
	if len(requested) == 0 {
		return nil
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = true
	}
	var result []string
	for _, s := range requested {
		if allowedSet[s] {
			result = append(result, s)
		}
	}
	return result
}
