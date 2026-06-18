package adminapi

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/seed"
)

const maxImportBatch = 1000

type importUser struct {
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	Disabled  bool     `json:"disabled"`
	Banned    bool     `json:"banned"`
	BanReason string   `json:"ban_reason"`
	LegacyID  string   `json:"legacy_id"`
	Locale    string   `json:"locale"`
}

type importResult struct {
	Email  string `json:"email"`
	Status string `json:"status"` // imported | skipped | error
	Error  string `json:"error,omitempty"`
}

// ImportUsers handles POST /admin/users/import — batch-create passwordless,
// import_pending accounts from a source system (e.g. BeOn3). Idempotent on email
// (CreateImported is ON CONFLICT DO NOTHING). Admin-reserved roles are stripped.
// On first login each imported account is forced through the magic-link reset.
func (h *Handler) ImportUsers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source string       `json:"source"` // imported_from tag (e.g. "beon3")
		Users  []importUser `json:"users"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(req.Users) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "empty_batch")
		return
	}
	if len(req.Users) > maxImportBatch {
		httputil.WriteError(w, http.StatusBadRequest, "batch_too_large")
		return
	}
	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "import"
	}

	results := make([]importResult, 0, len(req.Users))
	var imported int
	for _, u := range req.Users {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		if _, err := mail.ParseAddress(email); err != nil {
			results = append(results, importResult{Email: u.Email, Status: "error", Error: "invalid_email"})
			continue
		}
		// Skip if the email already exists (idempotent / non-clobbering).
		if existing, _ := h.users.GetByEmail(r.Context(), email); existing != nil {
			results = append(results, importResult{Email: email, Status: "skipped"})
			continue
		}
		id, err := vaultcrypto.RandomUUID()
		if err != nil {
			results = append(results, importResult{Email: email, Status: "error", Error: "internal_error"})
			continue
		}
		locale := u.Locale
		if locale == "" {
			locale = "en"
		}
		now := time.Now()
		user := &model.User{
			ID: id, Email: email, Locale: locale,
			Roles:        seed.FilterUserRoles(u.Roles), // strip admin-tier names
			Disabled:     u.Disabled,
			Banned:       u.Banned,
			BanReason:    u.BanReason,
			ImportedFrom: source,
			LegacyID:     u.LegacyID,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := h.users.CreateImported(r.Context(), user); err != nil {
			results = append(results, importResult{Email: email, Status: "error", Error: "create_failed"})
			continue
		}
		imported++
		results = append(results, importResult{Email: email, Status: "imported"})
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "admin:users_import", "", "", "", "", "", "", // #nosec G104 -- audit is best-effort
			map[string]any{"source": source, "submitted": len(req.Users), "imported": imported}, 0)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"source": source, "submitted": len(req.Users), "imported": imported, "results": results,
	})
}
