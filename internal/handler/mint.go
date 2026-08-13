package handler

import (
	"errors"
	"net/http"

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

// mintMaxBody bounds the request body. The route carries no exemption from the
// global 8 KiB cap; this is the explicit belt-and-braces limit the client token
// endpoint also applies.
const mintMaxBody = 8 * 1024

// MintRequestBody is the POST /mint request.
type MintRequestBody struct {
	// Subject is the identifier the caller asserts. Required. 1-128 bytes
	// matching ^[A-Za-z0-9][A-Za-z0-9._@-]*$. vault42 does not look it up
	// and does not require it to be a vault42 user; the charset exists so
	// a signed claim and an audit row cannot carry control characters or
	// whitespace.
	Subject string `json:"subject"`
	// Roles is an optional set that must be a subset of VAULT_MINT_ROLES.
	// Omit or send [] for none. The allow-list is empty by default, so a
	// freshly enabled mint issues bare subject assertions. One bad member
	// rejects the whole request; admin and super_admin are refused
	// regardless of the allow-list.
	Roles []string `json:"roles,omitempty"`
	// Scopes is an optional set that must be a subset of VAULT_MINT_SCOPES.
	// Same deny-by-default rule as Roles. mint:token, kms:unwrap, the
	// svcdoc scopes and admin scopes cannot be minted, so a minted token
	// cannot pivot onto vault42's privileged endpoints.
	Scopes []string `json:"scopes,omitempty"`
	// TTLSeconds is optional. 0 or omitted means VAULT_MINT_TOKEN_TTL.
	// Otherwise it must satisfy 0 < ttl <= VAULT_MINT_MAX_TTL (hard-capped
	// at 900s). A value above the ceiling is refused, not clamped, so a
	// misconfigured caller finds out now rather than when tokens expire
	// mid-flight.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// MintResponse is the POST /mint response.
type MintResponse struct {
	// AccessToken is the signed RS256 assertion. There is no refresh
	// token and no stored session; the assertion cannot be rotated or
	// revoked before ExpiresIn elapses. It carries a minted_by claim naming
	// the client that requested it, which is how a relying party attributes
	// an assertion it did not authenticate; that claim confers nothing.
	AccessToken string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	// TokenType is the HTTP presentation scheme, per RFC 6749. It is NOT the
	// JWT's own token_type claim, which is "mint" and is what keeps a minted
	// token out of vault42's own authenticated routes.
	TokenType string `json:"token_type"`
	// ExpiresIn is the granted lifetime in seconds, not necessarily the
	// requested TTLSeconds.
	ExpiresIn int `json:"expires_in"`
	// Subject is an echo of the asserted subject, equal to the token's sub.
	Subject string `json:"subject"`
	// Audience is VAULT_MINT_AUDIENCE, equal to the token's aud. Startup
	// refuses a configuration where this equals VAULT_ORIGIN, so a minted
	// token cannot satisfy vault42's own audience check.
	Audience string `json:"audience"`
	// Issuer is VAULT_ORIGIN, equal to the token's iss.
	Issuer string `json:"issuer"`
	// Roles is the granted set. Omitted when none were requested, so an
	// empty grant is absent rather than [].
	Roles []string `json:"roles,omitempty"`
	// Scopes is the granted set. Omitted when none were requested.
	Scopes []string `json:"scopes,omitempty"`
	// KID is the signing-key id, resolvable against GET /.well-known/jwks.json.
	KID string `json:"kid"`
	// JTI is the token's unique id. It is also written on the token_minted
	// audit event so a downstream incident traces back to this assertion
	// without the token itself being logged.
	JTI string `json:"jti"`
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

	// The wire carries a lifetime in seconds and the service takes a Duration,
	// so the conversion is bounded before the multiply rather than after it. A
	// Duration is int64 nanoseconds and wraps, and a wrapped product can land
	// back inside the ceiling, which would turn an out-of-range request into an
	// issued token rather than the refusal below.
	ttl, err := service.MintTTLFromSeconds(req.TTLSeconds)
	if err != nil {
		status, code := mintErrorCode(err)
		h.audit(r, claims.ClientID, req.Subject, code)
		WriteError(w, status, code)
		return
	}

	result, err := h.svc.Mint(service.MintRequest{
		Subject: req.Subject,
		Roles:   req.Roles,
		Scopes:  req.Scopes,
		TTL:     ttl,
		// The authenticated client, never anything from the body. MintRequestBody
		// has no field for this, so a caller cannot name a different tenant's
		// client as the one that spoke.
		MintedBy: claims.ClientID,
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
	h.auditLog.Log(r.Context(), audit.TokenMinted, result.Subject, clientID, middleware.ClientIP(r),
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
	h.auditLog.Log(r.Context(), audit.TokenMinted, subject, clientID, middleware.ClientIP(r),
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
