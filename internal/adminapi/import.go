package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/sanitize"
	"github.com/42-v/vault42/internal/seed"
	"github.com/42-v/vault42/internal/service"
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

	// MarketingEmails carries the source system's marketing preference. It is
	// stored with source=import, which is deliberately NOT treated as affirmative
	// consent: a migrated flag may be a default the user was never shown (this is
	// exactly the case for BeOn3, whose column defaults to true and whose consent
	// checkbox ships pre-ticked). The value is preserved so the operator can run a
	// re-permission campaign against it; it does not by itself authorise sending.
	MarketingEmails *bool `json:"marketing_emails,omitempty"`
}

type importResult struct {
	Email  string `json:"email"`
	Status string `json:"status"` // imported | skipped | error
	Error  string `json:"error,omitempty"`
}

// ImportUsers handles POST /admin/users/import — batch-create passwordless,
// import_pending accounts from a source system (e.g. the legacy platform). Idempotent on email
// (CreateImported is ON CONFLICT DO NOTHING). Admin-reserved roles are stripped.
// On first login each imported account is forced through the magic-link reset.
func (h *Handler) ImportUsers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source string       `json:"source"` // imported_from tag (e.g. "legacy")
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
	var imported, consentFailed int
	for _, u := range req.Users {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		if !sanitize.Email(email) {
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
		if u.MarketingEmails != nil {
			switch {
			case h.identity == nil:
				// No identity service wired, so the preference cannot be stored with
				// its provenance. Count it and say so per-row rather than silently
				// dropping it: the operator would otherwise see imported/0-failed and
				// believe a marketing list migrated when none of it did.
				consentFailed++
				results = append(results, importResult{Email: email, Status: "imported", Error: "consent_not_stored"})
				imported++
				continue
			default:
				data := &service.IdentityData{}
				data.StampMarketingConsent(*u.MarketingEmails, service.ConsentSourceImport, source)
				if err := h.identity.Upsert(r.Context(), id, data); err != nil {
					// The account is already created; a lost preference must not fail
					// the import. Record it and move on — a dropped flag fails closed
					// (no consent), which is the safe direction.
					consentFailed++
				}
			}
		}
		imported++
		results = append(results, importResult{Email: email, Status: "imported"})
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "admin:users_import", "", "", "", "", "", "", // #nosec G104 -- audit is best-effort
			map[string]any{
				"source": source, "submitted": len(req.Users), "imported": imported,
				"consent_failed": consentFailed,
			}, 0)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"source": source, "submitted": len(req.Users), "imported": imported,
		"consent_failed": consentFailed, "results": results,
	})
}
