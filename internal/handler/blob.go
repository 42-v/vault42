package handler

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/service"
)

// BlobHandler handles encrypted blob storage endpoints.
type BlobHandler struct {
	svc         *service.BlobService
	auditLog    *audit.Logger
	minBlobSize int
	maxBlobSize int
}

// NewBlobHandler creates a new blob handler.
func NewBlobHandler(svc *service.BlobService, auditLog *audit.Logger, minBlobSize, maxBlobSize int) *BlobHandler {
	return &BlobHandler{svc: svc, auditLog: auditLog, minBlobSize: minBlobSize, maxBlobSize: maxBlobSize}
}

// Upload handles POST /user/blobs.
func (h *BlobHandler) Upload(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Enforce max body size (maxBlobSize + 1KB for headers/metadata)
	r.Body = http.MaxBytesReader(w, r.Body, int64(h.maxBlobSize)+1024)

	var data []byte
	var label string
	var err error

	ct := r.Header.Get("Content-Type")
	if ct != "" && len(ct) > 19 && ct[:19] == "multipart/form-data" {
		// Multipart upload
		// #nosec G120 -- explicit maxMemory = configured maxBlobSize + 1KiB slack.
		if err := r.ParseMultipartForm(int64(h.maxBlobSize) + 1024); err != nil {
			WriteError(w, http.StatusRequestEntityTooLarge, "blob_too_large")
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			WriteError(w, http.StatusBadRequest, "missing_file")
			return
		}
		defer file.Close()
		data, err = io.ReadAll(file)
		if err != nil {
			WriteError(w, http.StatusRequestEntityTooLarge, "blob_too_large")
			return
		}
		label = r.FormValue("label")
	} else {
		// Raw upload
		data, err = io.ReadAll(r.Body)
		if err != nil {
			WriteError(w, http.StatusRequestEntityTooLarge, "blob_too_large")
			return
		}
		label = r.Header.Get("X-Blob-Label")
	}

	if len(data) == 0 {
		WriteError(w, http.StatusBadRequest, "empty_blob")
		return
	}

	if h.minBlobSize > 0 && len(data) < h.minBlobSize {
		WriteError(w, http.StatusBadRequest, "blob_too_small")
		return
	}

	// Sanitize label: reject control characters, UTF-8-safe truncation
	label = strings.TrimSpace(label)
	for _, c := range label {
		if c < 0x20 { // U+0000–U+001F control characters
			WriteError(w, http.StatusBadRequest, "invalid_label")
			return
		}
	}
	if utf8.RuneCountInString(label) > 255 {
		runes := []rune(label)
		label = string(runes[:255])
	}

	blob, err := h.svc.Upload(r.Context(), claims.Subject, data, label)
	if err != nil {
		h.writeUploadError(w, err)
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "blob_upload", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{
				"blob_id":    blob.ID,
				"size_bytes": blob.SizeBytes,
			}, 0)
	}

	WriteJSON(w, http.StatusCreated, BlobUploadResponse{
		ID:          blob.ID,
		Label:       label,
		SizeBytes:   blob.SizeBytes,
		StoredBytes: blob.StoredBytes,
		Checksum:    blob.Checksum,
		CreatedAt:   blob.CreatedAt,
	})
}

// UploadNamed handles PUT /user/blobs/named/{name}.
func (h *BlobHandler) UploadNamed(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		WriteError(w, http.StatusBadRequest, "missing_name")
		return
	}
	if utf8.RuneCountInString(name) > 255 {
		WriteError(w, http.StatusBadRequest, "name_too_long")
		return
	}
	if !validRefName(name) {
		WriteError(w, http.StatusBadRequest, "invalid_name")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, int64(h.maxBlobSize)+1024)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, http.StatusRequestEntityTooLarge, "blob_too_large")
		return
	}

	if len(data) == 0 {
		WriteError(w, http.StatusBadRequest, "empty_blob")
		return
	}

	if h.minBlobSize > 0 && len(data) < h.minBlobSize {
		WriteError(w, http.StatusBadRequest, "blob_too_small")
		return
	}

	blob, err := h.svc.UploadNamed(r.Context(), claims.Subject, data, name)
	if err != nil {
		h.writeUploadError(w, err)
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "blob_upload_named", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{
				"blob_id": blob.ID,
				"named":   true,
			}, 0)
	}

	WriteJSON(w, http.StatusOK, BlobUploadResponse{
		ID:          blob.ID,
		Label:       name,
		SizeBytes:   blob.SizeBytes,
		StoredBytes: blob.StoredBytes,
		Checksum:    blob.Checksum,
		CreatedAt:   blob.CreatedAt,
	})
}

// DownloadNamed handles GET /user/blobs/named/{name}.
func (h *BlobHandler) DownloadNamed(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		WriteError(w, http.StatusBadRequest, "missing_name")
		return
	}

	data, label, checksum, err := h.svc.DownloadNamed(r.Context(), claims.Subject, name)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if data == nil {
		WriteError(w, http.StatusNotFound, "blob_not_found")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "blob_download_named", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{
				"named": true,
			}, 0)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Blob-Checksum", checksum)
	if label != "" {
		w.Header().Set("X-Blob-Label", sanitizeLabelForHeader(label))
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data) // #nosec G104 G705 -- binary blob response; write errors are non-actionable in HTTP handlers
}

// DeleteNamed handles DELETE /user/blobs/named/{name}.
func (h *BlobHandler) DeleteNamed(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		WriteError(w, http.StatusBadRequest, "missing_name")
		return
	}

	if err := h.svc.DeleteNamed(r.Context(), claims.Subject, name); err != nil {
		if errors.Is(err, service.ErrBlobNotFound) {
			WriteError(w, http.StatusNotFound, "blob_not_found")
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "blob_delete_named", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{
				"named": true,
			}, 0)
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "deleted"})
}

// List handles GET /user/blobs.
func (h *BlobHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	metas, quota, err := h.svc.List(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	WriteJSON(w, http.StatusOK, BlobListResponse{
		Blobs: metas,
		Count: len(metas),
		Quota: quota,
	})
}

// Download handles GET /user/blobs/{id}.
func (h *BlobHandler) Download(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	blobID := r.PathValue("id")
	if blobID == "" {
		WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	data, label, checksum, err := h.svc.Download(r.Context(), claims.Subject, blobID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if data == nil {
		WriteError(w, http.StatusNotFound, "blob_not_found")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "blob_download", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{
				"blob_id": blobID,
			}, 0)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Blob-Checksum", checksum)
	if label != "" {
		w.Header().Set("X-Blob-Label", sanitizeLabelForHeader(label))
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data) // #nosec G104 G705 -- binary blob response; write errors are non-actionable in HTTP handlers
}

// Delete handles DELETE /user/blobs/{id}.
func (h *BlobHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	blobID := r.PathValue("id")
	if blobID == "" {
		WriteError(w, http.StatusBadRequest, "missing_id")
		return
	}

	if err := h.svc.Delete(r.Context(), claims.Subject, blobID); err != nil {
		if errors.Is(err, service.ErrBlobNotFound) {
			WriteError(w, http.StatusNotFound, "blob_not_found")
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "blob_delete", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{
				"blob_id": blobID,
			}, 0)
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "deleted"})
}

// writeUploadError maps service errors to HTTP responses for upload operations.
func (h *BlobHandler) writeUploadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrBlobTooSmall):
		WriteError(w, http.StatusBadRequest, "blob_too_small")
	case errors.Is(err, service.ErrBlobTooLarge):
		WriteError(w, http.StatusRequestEntityTooLarge, "blob_too_large")
	case errors.Is(err, service.ErrQuotaExceeded):
		WriteError(w, http.StatusConflict, "quota_exceeded")
	default:
		WriteError(w, http.StatusInternalServerError, "internal_error")
	}
}

// sanitizeLabelForHeader strips all control characters (U+0000–U+001F) from a
// blob label before setting it as an HTTP response header value. This prevents
// header injection via tabs, null bytes, or other non-printable characters.
// validRefName reports whether a named-blob reference matches the documented
// [a-zA-Z0-9_-]+ charset (docs/spec.md, docs/api.md).
func validRefName(name string) bool {
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func sanitizeLabelForHeader(label string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1 // drop control characters
		}
		return r
	}, label)
}
