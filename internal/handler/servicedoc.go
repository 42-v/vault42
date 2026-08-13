package handler

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/service"
)

// Audit event types for the service document store.
//
// The svcdoc_ prefix is load-bearing in the same way blob_ is: the audit
// scrubber drops an event class's sensitive keys by prefix, and these events
// must never carry a document body. Nothing here logs one, since the metadata
// is deliberately limited to the key, the size, the visibility and the outcome,
// but the prefix keeps that true if a future caller is careless.
const (
	// AuditSvcDocPut records a service document being created or replaced.
	AuditSvcDocPut = "svcdoc_put"
	// AuditSvcDocGet records a service document being read.
	AuditSvcDocGet = "svcdoc_get"
	// AuditSvcDocDelete records a service document being deleted.
	AuditSvcDocDelete = "svcdoc_delete"
)

// ClientRateLimitKey buckets a rate limiter by the authenticated client rather
// than by source IP.
//
// Every existing limiter keys on IP, which is right for a browser-facing route
// and wrong for a service one: a caller behind a single in-cluster pod presents
// one source address for its entire fleet of requests, so an IP bucket throttles
// all of its services as one. Requests with no client claim fall back to IP, so
// an unauthenticated probe cannot borrow another caller's bucket.
func ClientRateLimitKey(r *http.Request) string {
	claims := middleware.GetClaims(r.Context())
	if claims != nil && claims.ClientID != "" {
		return "client:" + claims.ClientID
	}
	return "ip:" + middleware.ClientIP(r)
}

// ServiceDocumentHandler serves the service-scoped JSON document store.
//
// Every route is mounted behind the JWT Auth middleware plus RequireScope, so
// reaching a method already proves an authenticated caller with the right
// scope. That is not sufficient on its own; see requireClient.
type ServiceDocumentHandler struct {
	svc      *service.DocumentService
	auditLog *audit.Logger
}

// NewServiceDocumentHandler creates a service document handler.
func NewServiceDocumentHandler(svc *service.DocumentService, auditLog *audit.Logger) *ServiceDocumentHandler {
	return &ServiceDocumentHandler{svc: svc, auditLog: auditLog}
}

// ServiceDocumentResponse is returned after a write. There is no single-document
// metadata route; a reader gets the document itself, or the list.
type ServiceDocumentResponse struct {
	// Key is an echo of the {key} path segment.
	Key string `json:"key"`
	// Owner is the writing client's registered name. Omitted on PUT
	// /service/documents/{subject}/{key}: the write path never resolves a
	// name, so this key is absent there. Listings and exports populate it
	// when the client lookup succeeds.
	Owner string `json:"owner,omitempty"`
	// OwnerID is the writing client's UUID. On PUT it is always the
	// caller.
	OwnerID string `json:"owner_id"`
	// Visibility is "private" (readable only by the writer) or "shared"
	// (readable by any svcdoc:read holder for the same subject and key).
	// The default on every write, including when ?visibility= is absent,
	// is private.
	Visibility string `json:"visibility"`
	// SizeBytes is the canonical plaintext size, which may differ from the
	// submitted byte count because keys are sorted and numbers are kept as
	// literals.
	SizeBytes int `json:"size_bytes"`
	// StoredBytes is the ciphertext size, which is what the per-subject
	// byte quota charges.
	StoredBytes int `json:"stored_bytes"`
	// CreatedAt is the first write of this (client, subject, key) triple,
	// RFC3339 UTC. A replacement preserves it.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is this write, RFC3339 UTC.
	UpdatedAt time.Time `json:"updated_at"`
}

// ServiceDocumentListResponse is returned by GET /service/documents/{subject}.
type ServiceDocumentListResponse struct {
	// Subject is an echo of the {subject} path segment, including the
	// literal _global for service-owned documents.
	Subject string `json:"subject"`
	// Documents is metadata of every document the caller may read for this
	// subject (own rows, then other clients' shared rows). Always an
	// array; [] when none exist. Bodies are never included.
	Documents []*service.DocumentMeta `json:"documents"`
	// Count is len(Documents). Always present, including on an empty list.
	Count int `json:"count"`
	// Quota is this subject's usage. used_bytes is cross-client ciphertext
	// for the subject; used_count is this caller's document count for the
	// subject. The two limits have different scopes on purpose.
	Quota *service.DocumentQuota `json:"quota"`
}

// requireClient resolves the calling service client, rejecting anything that is
// not one.
//
// RequireScope checks only the scopes array. Today a user token can never carry
// a svcdoc scope, because the four user-token issuance sites hardcode
// ["read","write"], so the scope check happens to be sufficient. That is an
// accident of the current code and not an invariant: a change to user-scope
// issuance would silently open a service-owned store to end-user tokens. The
// ownership axis of this store is the client id, so the handler asserts it
// directly and a token without one has no place here regardless of its scopes.
func requireClient(w http.ResponseWriter, r *http.Request) (clientID string, ok bool) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return "", false
	}
	if claims.ClientID == "" {
		WriteError(w, http.StatusForbidden, "client_credentials_required")
		return "", false
	}
	return claims.ClientID, true
}

// Put handles PUT /service/documents/{subject}/{key}. The request body is the
// document itself, so it is not decoded through decodeJSON: there is no fixed
// field set to reject unknown members against.
func (h *ServiceDocumentHandler) Put(w http.ResponseWriter, r *http.Request) {
	clientID, ok := requireClient(w, r)
	if !ok {
		return
	}
	subject, docKey, ok := h.pathParts(w, r)
	if !ok {
		return
	}

	visibility, visOK := service.ParseVisibility(r.URL.Query().Get("visibility"))
	if !visOK {
		WriteError(w, http.StatusBadRequest, "invalid_visibility")
		return
	}

	// The route prefix is exempt from the global 8 KiB body cap so a 64 KiB
	// document is not truncated mid-transfer with no useful error. An exemption
	// without a reader of its own is an unbounded-body hole, so the limit is
	// re-applied here, sized from the same configured maximum the service
	// validates against plus the existing 1 KiB slack convention.
	r.Body = http.MaxBytesReader(w, r.Body, int64(h.svc.MaxDocumentBytes())+1024)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, http.StatusRequestEntityTooLarge, "document_too_large")
		return
	}

	meta, created, err := h.svc.Put(r.Context(), clientID, subject, docKey, raw, visibility)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.audit(r, AuditSvcDocPut, subject, clientID, map[string]interface{}{
		"doc_key":    docKey,
		"size_bytes": meta.SizeBytes,
		"visibility": meta.Visibility,
		"created":    created,
	})

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	WriteJSON(w, status, ServiceDocumentResponse{
		Key:         meta.Key,
		OwnerID:     meta.OwnerID,
		Visibility:  meta.Visibility,
		SizeBytes:   meta.SizeBytes,
		StoredBytes: meta.StoredBytes,
		CreatedAt:   meta.CreatedAt,
		UpdatedAt:   meta.UpdatedAt,
	})
}

// Get handles GET /service/documents/{subject}/{key} and returns the document
// body. An optional ?owner=<client_name> names the publishing service when more
// than one shares the same key.
func (h *ServiceDocumentHandler) Get(w http.ResponseWriter, r *http.Request) {
	clientID, ok := requireClient(w, r)
	if !ok {
		return
	}
	subject, docKey, ok := h.pathParts(w, r)
	if !ok {
		return
	}

	body, meta, err := h.svc.Get(r.Context(), clientID, subject, docKey, r.URL.Query().Get("owner"))
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.audit(r, AuditSvcDocGet, subject, clientID, map[string]interface{}{
		"doc_key":  docKey,
		"owner_id": meta.OwnerID,
		"mine":     meta.Mine,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Document-Owner", meta.OwnerID)
	w.Header().Set("X-Document-Visibility", meta.Visibility)
	w.WriteHeader(http.StatusOK)
	w.Write(body) // #nosec G104 G705 -- stored document body; write errors are non-actionable in HTTP handlers
}

// Delete handles DELETE /service/documents/{subject}/{key}.
func (h *ServiceDocumentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	clientID, ok := requireClient(w, r)
	if !ok {
		return
	}
	subject, docKey, ok := h.pathParts(w, r)
	if !ok {
		return
	}

	if err := h.svc.Delete(r.Context(), clientID, subject, docKey); err != nil {
		h.writeError(w, err)
		return
	}

	h.audit(r, AuditSvcDocDelete, subject, clientID, map[string]interface{}{"doc_key": docKey})
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "deleted"})
}

// List handles GET /service/documents/{subject}. It returns metadata only.
func (h *ServiceDocumentHandler) List(w http.ResponseWriter, r *http.Request) {
	clientID, ok := requireClient(w, r)
	if !ok {
		return
	}
	subject := r.PathValue("subject")
	if subject == "" {
		WriteError(w, http.StatusBadRequest, "missing_subject")
		return
	}

	metas, quota, err := h.svc.List(r.Context(), clientID, subject)
	if err != nil {
		h.writeError(w, err)
		return
	}

	WriteJSON(w, http.StatusOK, ServiceDocumentListResponse{
		Subject:   subject,
		Documents: metas,
		Count:     len(metas),
		Quota:     quota,
	})
}

// pathParts extracts and presence-checks the two path segments. Their contents
// are validated in the service, against the same rules the migration's CHECK
// constraint enforces.
func (h *ServiceDocumentHandler) pathParts(w http.ResponseWriter, r *http.Request) (subject, docKey string, ok bool) {
	subject = r.PathValue("subject")
	if subject == "" {
		WriteError(w, http.StatusBadRequest, "missing_subject")
		return "", "", false
	}
	docKey = r.PathValue("key")
	if docKey == "" {
		WriteError(w, http.StatusBadRequest, "missing_key")
		return "", "", false
	}
	return subject, docKey, true
}

// audit records one document operation.
//
// The actor split is deliberate and differs from client_auth and kms_unwrap,
// which file the client id in both fields because those events have no user.
// Here there genuinely is one, and filing it under userID is what puts the
// event in that user's data export. Global documents have no user, so the field
// is left empty rather than filled with the sentinel.
func (h *ServiceDocumentHandler) audit(r *http.Request, event, subject, clientID string, meta map[string]interface{}) {
	if h.auditLog == nil {
		return
	}
	userID := subject
	if subject == service.GlobalSubject {
		userID = ""
	}
	// #nosec G104 -- audit is best-effort and must never block the document path
	h.auditLog.Log(r.Context(), event, userID, clientID, middleware.ClientIP(r),
		r.Header.Get("User-Agent"), "", "", meta, 0)
}

// writeError maps service errors to status codes.
//
// A write or read against a private document owned by another client resolves
// to document_not_found, never to a forbidden: distinguishing the two would
// make the store an existence oracle across service boundaries.
func (h *ServiceDocumentHandler) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrSvcDocInvalidKey):
		WriteError(w, http.StatusBadRequest, "invalid_key")
	case errors.Is(err, service.ErrSvcDocInvalidSubject):
		WriteError(w, http.StatusBadRequest, "invalid_subject")
	case errors.Is(err, service.ErrSvcDocInvalidDocument):
		WriteError(w, http.StatusBadRequest, "invalid_document")
	case errors.Is(err, service.ErrSvcDocTooLarge):
		WriteError(w, http.StatusRequestEntityTooLarge, "document_too_large")
	case errors.Is(err, service.ErrSvcDocQuotaExceeded):
		WriteError(w, http.StatusConflict, "quota_exceeded")
	case errors.Is(err, service.ErrSvcDocNotFound), errors.Is(err, service.ErrSvcDocUnknownOwner):
		WriteError(w, http.StatusNotFound, "document_not_found")
	case errors.Is(err, service.ErrSvcDocAmbiguous):
		WriteError(w, http.StatusConflict, "ambiguous_document")
	case errors.Is(err, service.ErrSvcDocSharedDisabled):
		WriteError(w, http.StatusForbidden, "shared_visibility_disabled")
	default:
		WriteError(w, http.StatusInternalServerError, "internal_error")
	}
}
