package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/service"
)

// MintScope is the scope POST /mint requires.
//
// It is its own scope on purpose. Reusing kms:unwrap would mean a client
// authorized to unwrap an envelope was thereby authorized to forge a subject,
// and the two capabilities have nothing to do with each other.
const MintScope = "mint:token"

// AuditTokenMinted records a token issued for a subject vault42 did not
// authenticate.
//
// It is a distinct event type from login_success, token_refresh and client_auth
// so a minted token is never mistaken for a self-authenticated one in the log.
// That distinction is the whole audit story for this endpoint: the signature on
// a minted token is indistinguishable from any other, so the log is the only
// place the difference is recorded.
const AuditTokenMinted = "token_minted"

// mintMaxBody bounds the request body. The route carries no exemption from the
// global 8 KiB cap; this is the explicit belt-and-braces limit the client token
// endpoint also applies.
const mintMaxBody = 8 * 1024

// MintRequestBody is the POST /mint request.
type MintRequestBody struct {
	// Subject is the identifier the caller asserts. Required. vault42 does not
	// look it up and does not require it to be a vault42 user.
	Subject string `json:"subject"`
	// Roles and Scopes are optional and must be subsets of the operator's
	// allow-lists.
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	// TTLSeconds is optional; zero means the configured default.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// MintResponse is the POST /mint response.
type MintResponse struct {
	// AccessToken is the signed assertion.
	AccessToken string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	// TokenType is the HTTP presentation scheme, per RFC 6749. It is NOT the
	// JWT's own token_type claim, which is "mint" and is what keeps a minted
	// token out of vault42's own authenticated routes.
	TokenType string   `json:"token_type"`
	ExpiresIn int      `json:"expires_in"`
	Subject   string   `json:"subject"`
	Audience  string   `json:"audience"`
	Issuer    string   `json:"issuer"`
	Roles     []string `json:"roles,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	KID       string   `json:"kid"`
	JTI       string   `json:"jti"`
}

// MintHandler serves POST /mint.
type MintHandler struct {
	svc      *service.MintService
	auditLog *audit.Logger
}

// NewMintHandler creates a mint handler over the given service.
func NewMintHandler(svc *service.MintService, auditLog *audit.Logger) *MintHandler {
	return &MintHandler{svc: svc, auditLog: auditLog}
}

// Mint handles POST /mint.
//
// The route is mounted only when minting is configured, behind the JWT Auth
// middleware and RequireScope(MintScope), so reaching this method already
// proves an authenticated client-credential holder that an operator explicitly
// granted the mint scope.
//
// Two further assertions are made here rather than left to the wiring. The
// caller must be a service client, because a scope check alone is only
// accidentally sufficient: user tokens cannot carry mint:token today only
// because the user issuance sites hardcode their scopes. And the request is
// audited on every path, success or failure, because an unaudited mint is an
// unattributable subject assertion.
func (h *MintHandler) Mint(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		// Defense in depth: the route wiring always authenticates first.
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if claims.ClientID == "" {
		h.audit(r, "", "", "client_credentials_required")
		WriteError(w, http.StatusForbidden, "client_credentials_required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, mintMaxBody)

	var req MintRequestBody
	if err := decodeJSON(r, &req); err != nil {
		h.audit(r, claims.ClientID, "", "invalid_request")
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if req.TTLSeconds < 0 {
		h.audit(r, claims.ClientID, req.Subject, "invalid_ttl")
		WriteError(w, http.StatusBadRequest, "invalid_ttl")
		return
	}

	result, err := h.svc.Mint(service.MintRequest{
		Subject: req.Subject,
		Roles:   req.Roles,
		Scopes:  req.Scopes,
		TTL:     time.Duration(req.TTLSeconds) * time.Second,
	})
	if err != nil {
		status, code := mintErrorCode(err)
		h.audit(r, claims.ClientID, req.Subject, code)
		WriteError(w, status, code)
		return
	}

	h.auditIssued(r, claims.ClientID, result)

	WriteJSON(w, http.StatusOK, MintResponse{
		AccessToken: result.Token,
		TokenType:   "Bearer",
		ExpiresIn:   result.ExpiresIn,
		Subject:     result.Subject,
		Audience:    result.Audience,
		Issuer:      result.Issuer,
		Roles:       result.Roles,
		Scopes:      result.Scopes,
		KID:         result.KID,
		JTI:         result.JTI,
	})
}

// auditIssued records a successful mint.
//
// userID carries the asserted subject and clientID the service that asserted
// it, so the log answers "who was spoken for, and by whom". The token itself is
// never logged; the jti is, so a downstream incident can be traced back to the
// exact assertion without the assertion being replayable from the log.
func (h *MintHandler) auditIssued(r *http.Request, clientID string, result *service.MintResult) {
	if h.auditLog == nil {
		return
	}
	// #nosec G104 -- audit is best-effort and must never block the mint path
	h.auditLog.Log(r.Context(), AuditTokenMinted, result.Subject, clientID, middleware.ClientIP(r),
		r.Header.Get("User-Agent"), "", "", map[string]interface{}{
			"minted":     true,
			"jti":        result.JTI,
			"kid":        result.KID,
			"audience":   result.Audience,
			"roles":      result.Roles,
			"scopes":     result.Scopes,
			"expires_in": result.ExpiresIn,
			"success":    true,
		}, mintRiskScore)
}

// audit records a rejected mint. A refused assertion is as interesting as an
// accepted one: a client probing for roles it cannot mint is the early signal
// that the credential has been taken.
// It takes no success flag on purpose. The accepted path audits separately at
// mintRiskScore, so a caller passing success here would file an accepted mint
// under the rejection score and quietly corrupt the one signal this event exists
// to carry.
func (h *MintHandler) audit(r *http.Request, clientID, subject, reason string) {
	if h.auditLog == nil {
		return
	}
	// #nosec G104 -- audit is best-effort and must never block the mint path
	h.auditLog.Log(r.Context(), AuditTokenMinted, subject, clientID, middleware.ClientIP(r),
		r.Header.Get("User-Agent"), "", "", map[string]interface{}{
			"minted":  true,
			"success": false,
			"reason":  reason,
		}, mintRejectedRiskScore)
}

// Risk scores. A mint is a credential-issuing event, so a success scores like
// one and a refusal scores higher: a rejected mint means a trusted service
// asked for something the operator did not allow.
const (
	mintRiskScore         = 30
	mintRejectedRiskScore = 45
)

// mintErrorCode maps a mint failure to a status and a stable error code.
func mintErrorCode(err error) (int, string) {
	switch {
	case errors.Is(err, service.ErrMintSubjectInvalid):
		return http.StatusBadRequest, "invalid_subject"
	case errors.Is(err, service.ErrMintRoleNotPermitted):
		return http.StatusForbidden, "role_not_permitted"
	case errors.Is(err, service.ErrMintScopeNotPermitted):
		return http.StatusForbidden, "scope_not_permitted"
	case errors.Is(err, service.ErrMintTTLInvalid):
		return http.StatusBadRequest, "invalid_ttl"
	case errors.Is(err, service.ErrMintUnavailable):
		return http.StatusServiceUnavailable, "server_busy"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}
