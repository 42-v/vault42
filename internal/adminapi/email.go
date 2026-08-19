package adminapi

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/model"
)

const maxSubjectLen = 255

// actor returns the username of the authenticated admin, or "" if absent.
func (h *Handler) actor(r *http.Request) string {
	if a := GetAdmin(r.Context()); a != nil {
		return a.Username
	}
	return ""
}

// ===================== Email branding =====================

type emailBrandingView struct {
	App          string    `json:"app"`
	AppName      string    `json:"app_name,omitempty"`
	LogoURL      string    `json:"logo_url,omitempty"`
	PrimaryColor string    `json:"primary_color,omitempty"`
	FromName     string    `json:"from_name,omitempty"`
	FromAddress  string    `json:"from_address,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
	UpdatedBy    string    `json:"updated_by,omitempty"`
}

func toBrandingView(b *model.EmailBranding) emailBrandingView {
	return emailBrandingView{
		App: b.App, AppName: b.AppName, LogoURL: b.LogoURL, PrimaryColor: b.PrimaryColor,
		FromName: b.FromName, FromAddress: b.FromAddress, UpdatedAt: b.UpdatedAt, UpdatedBy: b.UpdatedBy,
	}
}

// ListEmailBranding handles GET /admin/email-branding.
func (h *Handler) ListEmailBranding(w http.ResponseWriter, r *http.Request) {
	if h.emailBranding == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "email_config_unavailable")
		return
	}
	items, err := h.emailBranding.List(r.Context())
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	views := make([]emailBrandingView, 0, len(items))
	for _, b := range items {
		views = append(views, toBrandingView(b))
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"branding": views})
}

// GetEmailBranding handles GET /admin/email-branding/{app}.
func (h *Handler) GetEmailBranding(w http.ResponseWriter, r *http.Request) {
	if h.emailBranding == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "email_config_unavailable")
		return
	}
	app := r.PathValue("app")
	if !email.ValidApp(app) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_app")
		return
	}
	b, err := h.emailBranding.Get(r.Context(), app)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if b == nil {
		httputil.WriteError(w, http.StatusNotFound, "not_found")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, toBrandingView(b))
}

// PutEmailBranding handles PUT /admin/email-branding/{app} — create or replace.
func (h *Handler) PutEmailBranding(w http.ResponseWriter, r *http.Request) {
	if h.emailBranding == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "email_config_unavailable")
		return
	}
	app := r.PathValue("app")
	if !email.ValidApp(app) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_app")
		return
	}
	var req struct {
		AppName      string `json:"app_name"`
		LogoURL      string `json:"logo_url"`
		PrimaryColor string `json:"primary_color"`
		FromName     string `json:"from_name"`
		FromAddress  string `json:"from_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(req.AppName) > maxSubjectLen || len(req.FromName) > maxSubjectLen {
		httputil.WriteError(w, http.StatusBadRequest, "field_too_long")
		return
	}
	if req.LogoURL != "" && !email.ValidLogoURL(req.LogoURL) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_logo_url")
		return
	}
	if req.PrimaryColor != "" && !email.ValidHexColor(req.PrimaryColor) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_color")
		return
	}
	fromAddress := req.FromAddress
	if req.FromAddress != "" {
		parsed, err := mail.ParseAddress(req.FromAddress)
		if err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "invalid_from_address")
			return
		}
		// Store the canonical address so the send-path allowlist check sees the
		// same value the parser does (no display-name/quoting differential).
		fromAddress = parsed.Address
	}
	b := &model.EmailBranding{
		App: app, AppName: req.AppName, LogoURL: req.LogoURL, PrimaryColor: req.PrimaryColor,
		FromName: req.FromName, FromAddress: fromAddress, UpdatedBy: h.actor(r),
	}
	if err := h.emailBranding.Upsert(r.Context(), b); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "admin:email_branding_set", h.actor(r), "", r.RemoteAddr, r.UserAgent(), "", "", // #nosec G104 -- audit is best-effort
			map[string]any{"app": app})
	}
	if stored, err := h.emailBranding.Get(r.Context(), app); err == nil && stored != nil {
		b = stored
	}
	httputil.WriteJSON(w, http.StatusOK, toBrandingView(b))
}

// DeleteEmailBranding handles DELETE /admin/email-branding/{app}.
func (h *Handler) DeleteEmailBranding(w http.ResponseWriter, r *http.Request) {
	if h.emailBranding == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "email_config_unavailable")
		return
	}
	app := r.PathValue("app")
	if !email.ValidApp(app) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_app")
		return
	}
	if err := h.emailBranding.Delete(r.Context(), app); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "admin:email_branding_delete", h.actor(r), "", r.RemoteAddr, r.UserAgent(), "", "", // #nosec G104 -- audit is best-effort
			map[string]any{"app": app})
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// ===================== Email templates =====================

type emailTemplateView struct {
	App          string    `json:"app"`
	TemplateName string    `json:"template_name"`
	Subject      string    `json:"subject"`
	HTMLContent  string    `json:"html_content"`
	TextContent  string    `json:"text_content,omitempty"`
	Enabled      bool      `json:"enabled"`
	UpdatedAt    time.Time `json:"updated_at"`
	UpdatedBy    string    `json:"updated_by,omitempty"`
}

func toTemplateView(t *model.EmailTemplate) emailTemplateView {
	return emailTemplateView{
		App: t.App, TemplateName: t.TemplateName, Subject: t.Subject, HTMLContent: t.HTMLContent,
		TextContent: t.TextContent, Enabled: t.Enabled, UpdatedAt: t.UpdatedAt, UpdatedBy: t.UpdatedBy,
	}
}

// ListEmailTemplates handles GET /admin/email-templates (optional ?app= filter).
func (h *Handler) ListEmailTemplates(w http.ResponseWriter, r *http.Request) {
	if h.emailTemplates == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "email_config_unavailable")
		return
	}
	var (
		items []*model.EmailTemplate
		err   error
	)
	if app := r.URL.Query().Get("app"); app != "" {
		if !email.ValidApp(app) {
			httputil.WriteError(w, http.StatusBadRequest, "invalid_app")
			return
		}
		items, err = h.emailTemplates.ListByApp(r.Context(), app)
	} else {
		items, err = h.emailTemplates.List(r.Context())
	}
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	views := make([]emailTemplateView, 0, len(items))
	for _, t := range items {
		views = append(views, toTemplateView(t))
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"templates": views})
}

// GetEmailTemplate handles GET /admin/email-templates/{app}/{name}.
func (h *Handler) GetEmailTemplate(w http.ResponseWriter, r *http.Request) {
	if h.emailTemplates == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "email_config_unavailable")
		return
	}
	app, name := r.PathValue("app"), r.PathValue("name")
	if !email.ValidApp(app) || !email.ValidTemplateName(name) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	t, err := h.emailTemplates.Get(r.Context(), app, name)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if t == nil {
		httputil.WriteError(w, http.StatusNotFound, "not_found")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, toTemplateView(t))
}

// PutEmailTemplate handles PUT /admin/email-templates/{app}/{name}.
func (h *Handler) PutEmailTemplate(w http.ResponseWriter, r *http.Request) {
	if h.emailTemplates == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "email_config_unavailable")
		return
	}
	app, name := r.PathValue("app"), r.PathValue("name")
	if !email.ValidApp(app) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_app")
		return
	}
	if !email.ValidTemplateName(name) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_template_name")
		return
	}
	var req struct {
		Subject     string `json:"subject"`
		HTMLContent string `json:"html_content"`
		TextContent string `json:"text_content"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(req.Subject) > maxSubjectLen {
		httputil.WriteError(w, http.StatusBadRequest, "subject_too_long")
		return
	}
	if h.maxTemplateSize > 0 && len(req.HTMLContent)+len(req.TextContent) > h.maxTemplateSize {
		httputil.WriteError(w, http.StatusBadRequest, "template_too_large")
		return
	}
	if err := email.ValidateTemplateContent(req.Subject, req.HTMLContent); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_template")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	actor := h.actor(r)
	t := &model.EmailTemplate{
		ID: id, App: app, TemplateName: name, Subject: req.Subject, HTMLContent: req.HTMLContent,
		TextContent: req.TextContent, Enabled: enabled, CreatedBy: actor, UpdatedBy: actor,
	}
	if err := h.emailTemplates.Upsert(r.Context(), t); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "admin:email_template_set", h.actor(r), "", r.RemoteAddr, r.UserAgent(), "", "", // #nosec G104 -- audit is best-effort
			map[string]any{"app": app, "template": name, "enabled": enabled})
	}
	if stored, err := h.emailTemplates.Get(r.Context(), app, name); err == nil && stored != nil {
		t = stored
	}
	httputil.WriteJSON(w, http.StatusOK, toTemplateView(t))
}

// DeleteEmailTemplate handles DELETE /admin/email-templates/{app}/{name}.
func (h *Handler) DeleteEmailTemplate(w http.ResponseWriter, r *http.Request) {
	if h.emailTemplates == nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, "email_config_unavailable")
		return
	}
	app, name := r.PathValue("app"), r.PathValue("name")
	if !email.ValidApp(app) || !email.ValidTemplateName(name) {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.emailTemplates.Delete(r.Context(), app, name); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), "admin:email_template_delete", h.actor(r), "", r.RemoteAddr, r.UserAgent(), "", "", // #nosec G104 -- audit is best-effort
			map[string]any{"app": app, "template": name})
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// PreviewEmailTemplate handles POST /admin/email-templates/preview — render a
// candidate template against sample data without saving or sending. Always
// returns 200 with a structured result so the admin UI can show either the
// rendered output or the validation error.
func (h *Handler) PreviewEmailTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject     string `json:"subject"`
		HTMLContent string `json:"html_content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	subject, html, text, err := email.RenderPreview(req.Subject, req.HTMLContent, email.SampleData())
	if err != nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"valid": true, "subject": subject, "html": html, "text": text,
	})
}
