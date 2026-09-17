package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/sanitize"
	"github.com/42-v/vault42/internal/seed"
	"github.com/42-v/vault42/internal/service"
)

const maxImportBatch = 1000

// The columns this endpoint writes into, by width.
//
// auth.users.imported_from is VARCHAR(64) (migrations/006_account_import.sql)
// and auth.users.ban_reason is VARCHAR(500) (migrations/004_user_account_flags.sql).
// locale is VARCHAR(10) (001) and is bounded by sanitize.Locale, which already
// owns that number for the two other write paths.
//
// Nothing checked any of them. A 100-character `source` is written to every row,
// so CreateImported fails with 22001 for every record; the loop catches each
// failure on its own, so the endpoint answers 200 OK with "imported": 0 and a
// thousand rows of "create_failed", and nothing in the response names the one
// field that caused it. An operator reads that as a thousand bad records.
const (
	maxImportSourceLen    = 64
	maxImportBanReasonLen = 500
)

type importUser struct {
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	Disabled  bool     `json:"disabled"`
	Banned    bool     `json:"banned"`
	BanReason string   `json:"ban_reason"`
	LegacyID  string   `json:"legacy_id"`
	Locale    string   `json:"locale"`

	// MustResetPassword puts the account under a forced password reset the
	// moment it is created (migration 039). Its first login then verifies
	// nothing, mails a reset link and refuses, and the account is ordinary
	// again once that reset completes.
	//
	// This is the answer to a source system whose password hashes vault42
	// cannot verify -- a bcrypt, an MD5, anything that is not Argon2id. Without
	// it those accounts answer every correct password with invalid_credentials
	// and no explanation, because there is nothing here that can check them.
	// Absent or false imports the account with no such demand, which is right
	// for a migration that carries no credentials at all: import_pending
	// already covers that case and mails its own claim link.
	MustResetPassword bool `json:"must_reset_password,omitempty"`

	// MarketingEmails carries the source system's marketing preference. It is
	// stored with source=import, which is deliberately NOT treated as affirmative
	// consent: a migrated flag may be a default the user was never shown (this is
	// exactly the case for BeOn3, whose column defaults to true and whose consent
	// checkbox ships pre-ticked). The value is preserved so the operator can run a
	// re-permission campaign against it; it does not by itself authorize sending.
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
	// Rejected, not truncated, and rejected before the loop.
	//
	// `source` is batch-wide: it is written to every row, so an over-long one is
	// not a bad record among good ones, it is a bad request. Truncating it would
	// silently file a thousand accounts under a tag the operator did not choose
	// and cannot search for later, and the import is idempotent on
	// (imported_from, legacy_id) -- so a truncated tag also makes the re-run that
	// was supposed to be a no-op create every account a second time.
	//
	// Runes, not bytes, because VARCHAR(64) counts characters. The sibling clamp
	// in internal/sanitize measures bytes on purpose, which is conservative in
	// the direction that cannot fail when the answer is to TRUNCATE. Here the
	// answer is to refuse, and being conservative would refuse a tag PostgreSQL
	// would have accepted.
	if utf8.RuneCountInString(source) > maxImportSourceLen {
		httputil.WriteError(w, http.StatusBadRequest, "source_too_long")
		return
	}

	results := make([]importResult, 0, len(req.Users))
	var imported, consentFailed, forcedReset int
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
		// The same clamp the other two write paths apply (internal/service/auth.go
		// on register, internal/handler/user.go on profile update): it bounds the
		// tag to the column's ten characters, refuses anything that is not a
		// language tag, and falls back to "en" -- which is also the empty case
		// this used to handle on its own.
		locale := sanitize.Locale(u.Locale)
		now := time.Now()
		user := &model.User{
			ID: id, Email: email, Locale: locale,
			Roles:        seed.FilterUserRoles(u.Roles), // strip admin-tier names
			Disabled:     u.Disabled,
			Banned:       u.Banned,
			BanReason:    sanitize.String(u.BanReason, maxImportBanReasonLen),
			ImportedFrom: source,
			LegacyID:     u.LegacyID,
			CreatedAt:    now,
			UpdatedAt:    now,

			MustResetPassword: u.MustResetPassword,
		}
		if err := h.users.CreateImported(r.Context(), user); err != nil {
			results = append(results, importResult{Email: email, Status: "error", Error: "create_failed"})
			continue
		}
		if u.MustResetPassword {
			forcedReset++
		}
		if u.MarketingEmails != nil {
			if h.identity == nil {
				// No identity service wired, so the preference cannot be stored with
				// its provenance. Count it and say so per-row rather than silently
				// dropping it: the operator would otherwise see imported/0-failed and
				// believe a marketing list migrated when none of it did.
				consentFailed++
				results = append(results, importResult{Email: email, Status: "imported", Error: "consent_not_stored"})
				imported++
				continue
			}
			data := &service.IdentityData{}
			data.StampMarketingConsent(*u.MarketingEmails, service.ConsentSourceImport, source)
			if err := h.identity.Upsert(r.Context(), id, data); err != nil {
				// The account is already created; a lost preference must not fail
				// the import. Record it and move on — a dropped flag fails closed
				// (no consent), which is the safe direction.
				consentFailed++
			}
		}
		imported++
		results = append(results, importResult{Email: email, Status: "imported"})
	}

	if h.auditLog != nil {
		actor := GetAdmin(r.Context())
		h.auditLog.Log(r.Context(), "admin:users_import", actor.ID, "", r.RemoteAddr, r.UserAgent(), "", "", // #nosec G104 -- audit is best-effort
			map[string]any{
				"source": source, "submitted": len(req.Users), "imported": imported,
				"consent_failed": consentFailed, "must_reset_password": forcedReset,
				"reason": "admin_import",
			})
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"source": source, "submitted": len(req.Users), "imported": imported,
		"consent_failed": consentFailed, "must_reset_password": forcedReset,
		"results": results,
	})
}
