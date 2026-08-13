package handler

import (
	"net/http"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/repository"
)

// SocialHandler exposes a user's federated identity links.
//
// Linking an external provider stores that provider's user ID, the email it
// asserted, and encrypted access/refresh tokens. Until now there was no way to
// remove any of it short of erasing the whole account, which made unlinking an
// all-or-nothing choice a user should not have to make (Art. 17 is per-purpose,
// not per-account).
type SocialHandler struct {
	social   repository.SocialAccountRepository
	auditLog *audit.Logger
}

// NewSocialHandler creates a social account handler.
func NewSocialHandler(social repository.SocialAccountRepository, auditLog *audit.Logger) *SocialHandler {
	return &SocialHandler{social: social, auditLog: auditLog}
}

// socialAccountView is the safe projection of a link. The encrypted provider
// tokens are deliberately absent: the user needs to know a provider is linked,
// not hold its credentials.
//
// CreatedAt is a time.Time so it encodes exactly like every other timestamp in
// the API. Hand-formatting it truncated the value to whole seconds, which made
// this the one endpoint whose timestamps a client had to parse differently.
type socialAccountView struct {
	// ID is the link UUID. DELETE /user/social/{id} addresses it.
	ID string `json:"id"`
	// Provider is the configured IdP name (google, github, ...).
	Provider string `json:"provider"`
	// Email is the address the IdP asserted at link time. Omitted when
	// the provider released none.
	Email string `json:"email,omitempty"`
	// CreatedAt is when the link was stored, RFC3339 UTC. Encoded as
	// time.Time so it matches every other timestamp in the API.
	CreatedAt time.Time `json:"created_at"`
}

// List handles GET /user/social — the linked providers for the caller.
func (h *SocialHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	accounts, err := h.social.ListByUser(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	out := make([]socialAccountView, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, socialAccountView{
			ID:        a.ID,
			Provider:  a.Provider,
			Email:     a.Email,
			CreatedAt: a.CreatedAt.UTC(),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"accounts": out, "total": len(out)})
}

// Unlink handles DELETE /user/social/{id} — removes one federated link and the
// provider tokens stored with it.
//
// The repo scopes the delete by user ID as well as link ID, so a caller cannot
// unlink another user's provider by guessing an ID. A link that does not exist
// (or is not the caller's) is reported as deleted rather than 404: the response
// must not become an oracle for whether an ID belongs to somebody else.
func (h *SocialHandler) Unlink(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if err := h.social.Delete(r.Context(), id, claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "social_unlink", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort
			r.Header.Get("User-Agent"), "", "", map[string]interface{}{"link_id": id}, 0)
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "unlinked"})
}
