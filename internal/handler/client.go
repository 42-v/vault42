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

// Token handles POST /client/token (client credentials grant).
func (h *ClientHandler) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192) // explicit limit for gosec G120 visibility

	clientID, clientSecret, ok := parseClientCredentials(r)
	if !ok {
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
		WriteError(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}

	if !client.Active {
		// Burn time to prevent timing-based enumeration of revoked vs valid clients
		if _, dummyErr := vaultcrypto.VerifyPassword(clientSecret, client.SecretHash); errors.Is(dummyErr, vaultcrypto.ErrArgon2Overloaded) {
			WriteError(w, http.StatusServiceUnavailable, "server_busy")
			return
		}
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
		WriteError(w, http.StatusUnauthorized, "invalid_client_credentials")
		return
	}

	// Parse requested scopes
	var requestedScopes []string
	if scopeStr := r.FormValue("scope"); scopeStr != "" {
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
		client.ID, []string{client.Role}, grantedScopes,
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

	// Try request body
	clientID = r.FormValue("client_id")
	clientSecret = r.FormValue("client_secret")
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
