package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/service"
)

// IdentityHandler handles identity profile endpoints.
type IdentityHandler struct {
	svc      *service.IdentityService
	auditLog *audit.Logger
}

// NewIdentityHandler creates a new identity handler.
func NewIdentityHandler(svc *service.IdentityService, auditLog *audit.Logger) *IdentityHandler {
	return &IdentityHandler{svc: svc, auditLog: auditLog}
}

// logConsent records a consent decision in the audit trail. The trail is what
// answers "prove this user opted in" (Art. 7(1)) and "prove withdrawal was
// honoured" (Art. 7(3)); the profile only holds the current state.
func (h *IdentityHandler) logConsent(r *http.Request, userID string, granted bool, source string) {
	if h.auditLog == nil {
		return
	}
	event := audit.ConsentWithdrawn
	if granted {
		event = audit.ConsentGranted
	}
	h.auditLog.Log(r.Context(), event, userID, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort
		r.Header.Get("User-Agent"), "", "", map[string]interface{}{
			"purpose": "marketing_email",
			"source":  source,
		}, 0)
}

var (
	countryCodeRe = regexp.MustCompile(`^[A-Z]{2}$`)
	dateRe        = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// identityInput is the JSON request body for PUT /user/identity.
type identityInput struct {
	GivenName       string                     `json:"given_name"`
	FamilyName      string                     `json:"family_name"`
	Username        string                     `json:"username"`
	Country         string                     `json:"country"`
	State           string                     `json:"state"`
	DateOfBirth     string                     `json:"date_of_birth"`
	Sex             string                     `json:"sex"`
	MarketingEmails *bool                      `json:"marketing_emails"`
	Billing         *billingInput              `json:"billing"`
	Dynamic         map[string]json.RawMessage `json:"dynamic"`
}

type billingInput struct {
	AddressLine1 string `json:"address_line_1"`
	AddressLine2 string `json:"address_line_2"`
	City         string `json:"city"`
	PostalCode   string `json:"postal_code"`
	Country      string `json:"country"`
	VATID        string `json:"vat_id"`
}

// Get handles GET /user/identity.
func (h *IdentityHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	data, updatedAt, err := h.svc.Get(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if data == nil {
		WriteError(w, http.StatusNotFound, "identity_not_found")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "identity_read", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", nil, 0)
	}

	resp := IdentityResponse{
		GivenName:       data.GivenName,
		FamilyName:      data.FamilyName,
		Username:        data.Username,
		Country:         data.Country,
		State:           data.State,
		DateOfBirth:     data.DateOfBirth,
		Sex:             data.Sex,
		MarketingEmails: data.MarketingEmails,
		UpdatedAt:       updatedAt.Format(time.RFC3339),
		Billing:         data.Billing,
		Dynamic:         data.Dynamic,
	}
	WriteJSON(w, http.StatusOK, resp)
}

// Put handles PUT /user/identity.
func (h *IdentityHandler) Put(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var input identityInput
	if err := decodeJSON(r, &input); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if err := validateIdentity(&input); err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	data := &service.IdentityData{
		GivenName:   truncate(input.GivenName, 100),
		FamilyName:  truncate(input.FamilyName, 100),
		Username:    input.Username,
		Country:     input.Country,
		State:       input.State,
		DateOfBirth: input.DateOfBirth,
		Sex:         truncate(input.Sex, 50),
		Dynamic:     input.Dynamic,
	}
	// The user actively submitted this preference, so it is affirmative consent —
	// stamp it with its provenance rather than storing a bare bool.
	if input.MarketingEmails != nil {
		data.StampMarketingConsent(*input.MarketingEmails, service.ConsentSourceProfile, "")
		h.logConsent(r, claims.Subject, *input.MarketingEmails, service.ConsentSourceProfile)
	}
	if input.Billing != nil {
		data.Billing = &service.BillingInfo{
			AddressLine1: truncate(input.Billing.AddressLine1, 200),
			AddressLine2: truncate(input.Billing.AddressLine2, 200),
			City:         truncate(input.Billing.City, 100),
			PostalCode:   truncate(input.Billing.PostalCode, 20),
			Country:      input.Billing.Country,
			VATID:        truncate(input.Billing.VATID, 50),
		}
	}

	// Service-side Validate (username/state/sex/dynamic size+shape) is the
	// authoritative gate; surface its rejections as 400, not 500.
	if err := h.svc.Upsert(r.Context(), claims.Subject, data); err != nil {
		if errors.Is(err, service.ErrInvalidProfile) {
			WriteError(w, http.StatusBadRequest, "invalid_profile")
			return
		}
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "identity_write", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", nil, 0)
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "updated"})
}

// Delete handles DELETE /user/identity.
func (h *IdentityHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.svc.Delete(r.Context(), claims.Subject); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "identity_delete", claims.Subject, "", middleware.ClientIP(r), // #nosec G104 -- audit is best-effort, never blocks auth flow
			r.Header.Get("User-Agent"), "", "", nil, 0)
	}

	WriteJSON(w, http.StatusOK, StatusResponse{Status: "deleted"})
}

// Unsubscribe handles POST /user/marketing/unsubscribe.
//
// Art. 7(3): withdrawing consent must be as easy as giving it. Granting is a
// checkbox, so withdrawal is a single call with no body and no confirmation
// step. It is idempotent — unsubscribing twice is not an error — and it only
// clears the marketing preference; the account and every other purpose are
// untouched.
func (h *IdentityHandler) Unsubscribe(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	data, _, err := h.svc.Get(r.Context(), claims.Subject)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if data == nil {
		// No profile yet. Still record the withdrawal rather than no-opping: an
		// account import could otherwise land a legacy opt-in on this user later
		// and silently re-grant a consent they have already refused.
		data = &service.IdentityData{}
	}

	data.StampMarketingConsent(false, service.ConsentSourceUnsubscribe, "")
	if err := h.svc.Upsert(r.Context(), claims.Subject, data); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}

	h.logConsent(r, claims.Subject, false, service.ConsentSourceUnsubscribe)
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "unsubscribed"})
}

func validateIdentity(input *identityInput) error {
	if input.Country != "" && !countryCodeRe.MatchString(input.Country) {
		return errMsg("invalid_country")
	}
	if input.DateOfBirth != "" {
		if !dateRe.MatchString(input.DateOfBirth) {
			return errMsg("invalid_date_of_birth")
		}
		dob, err := time.Parse("2006-01-02", input.DateOfBirth)
		if err != nil || dob.After(time.Now()) {
			return errMsg("invalid_date_of_birth")
		}
	}
	if input.Billing != nil && input.Billing.Country != "" {
		if !countryCodeRe.MatchString(input.Billing.Country) {
			return errMsg("invalid_billing_country")
		}
	}
	return nil
}

type errMsg string

func (e errMsg) Error() string { return string(e) }

func truncate(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes])
}
