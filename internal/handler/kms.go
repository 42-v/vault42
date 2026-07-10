package handler

import (
	"encoding/base64"
	"net/http"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/kms"
	"github.com/42-v/vault42/internal/middleware"
)

// unwrapFailed is the single opaque error surfaced for EVERY unwrap failure
// after authentication/authorization — malformed body, bad base64, empty kid,
// tampered ciphertext, or wrong KEK. Keeping the message, status, and audit
// outcome identical across these paths denies an attacker a decryption oracle.
const unwrapFailed = "unwrap_failed"

// KMSHandler serves the KEK envelope-unwrap oracle (POST /kms/unwrap): the
// vault42-rooted data-root release life42 depends on. It never releases the
// KEK — only the unwrapped payload, and only to an authorized caller.
type KMSHandler struct {
	kms      *kms.Service
	auditLog *audit.Logger
}

// NewKMSHandler creates a KMS unwrap handler over the given service.
func NewKMSHandler(svc *kms.Service, auditLog *audit.Logger) *KMSHandler {
	return &KMSHandler{kms: svc, auditLog: auditLog}
}

// Unwrap handles POST /kms/unwrap. It is mounted behind the JWT Auth middleware
// and RequireScope("kms:unwrap"): reaching this handler already proves the
// caller is an authenticated client-credential holder with the unwrap scope.
//
// All post-authorization failures collapse to an identical 400 unwrap_failed so
// the endpoint reveals only success vs failure, never why an envelope was
// rejected. Key material is never logged.
func (h *KMSHandler) Unwrap(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		// Defense in depth: the route wiring always authenticates first.
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req KMSUnwrapRequest
	if err := decodeJSON(r, &req); err != nil {
		h.audit(r, claims.ClientID, "", false)
		WriteError(w, http.StatusBadRequest, unwrapFailed)
		return
	}

	// base64.StdEncoding matches the life42 client's wire encoding. A decode
	// failure is treated identically to a crypto failure (uniform error).
	envelope, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		h.audit(r, claims.ClientID, req.Kid, false)
		WriteError(w, http.StatusBadRequest, unwrapFailed)
		return
	}

	plaintext, err := h.kms.Unwrap(req.Kid, envelope)
	if err != nil {
		// err is always kms.ErrUnwrap — a single opaque value. Do not surface it.
		h.audit(r, claims.ClientID, req.Kid, false)
		WriteError(w, http.StatusBadRequest, unwrapFailed)
		return
	}

	h.audit(r, claims.ClientID, req.Kid, true)
	WriteJSON(w, http.StatusOK, KMSUnwrapResponse{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
}

// audit records the unwrap attempt with the KEK kid and outcome only. It never
// logs the ciphertext, the plaintext, or any derived key material.
func (h *KMSHandler) audit(r *http.Request, clientID, kid string, ok bool) {
	if h.auditLog == nil {
		return
	}
	risk := 0
	if !ok {
		risk = 20
	}
	// #nosec G104 -- audit is best-effort and must never block the KMS path
	h.auditLog.Log(r.Context(), audit.KMSUnwrap, clientID, clientID, middleware.ClientIP(r),
		r.Header.Get("User-Agent"), "", "",
		map[string]interface{}{"kid": kid, "success": ok}, risk)
}
