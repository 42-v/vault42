package service

import (
	"context"
	"log"

	vaultemail "github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/repository"
)

// EmailOverrideStore adapts the branding + template repositories to the
// email.OverrideStore interface consumed by the Mailer on the send path.
// Lookups degrade to "no override" on error (the global template renders) — a
// branding query must never block an auth email.
type EmailOverrideStore struct {
	branding  repository.EmailBrandingRepository
	templates repository.EmailTemplateRepository
}

// NewEmailOverrideStore wires the per-app branding + template repositories into
// an email.OverrideStore.
func NewEmailOverrideStore(b repository.EmailBrandingRepository, t repository.EmailTemplateRepository) *EmailOverrideStore {
	return &EmailOverrideStore{branding: b, templates: t}
}

// Branding returns the per-app branding, or ok=false when there is none.
func (s *EmailOverrideStore) Branding(ctx context.Context, app string) (vaultemail.Branding, bool) {
	if s == nil || s.branding == nil {
		return vaultemail.Branding{}, false
	}
	b, err := s.branding.Get(ctx, app)
	if err != nil {
		log.Printf("email: branding lookup for %q failed: %v", app, err)
		return vaultemail.Branding{}, false
	}
	if b == nil {
		return vaultemail.Branding{}, false
	}
	return vaultemail.Branding{
		AppName:      b.AppName,
		LogoURL:      b.LogoURL,
		PrimaryColor: b.PrimaryColor,
		FromName:     b.FromName,
		FromAddress:  b.FromAddress,
	}, true
}

// Template returns the per-app override for an email type, or ok=false when none
// exists or it is disabled.
func (s *EmailOverrideStore) Template(ctx context.Context, app, name string) (vaultemail.TemplateOverride, bool) {
	if s == nil || s.templates == nil {
		return vaultemail.TemplateOverride{}, false
	}
	t, err := s.templates.Get(ctx, app, name)
	if err != nil {
		log.Printf("email: template lookup for %q/%q failed: %v", app, name, err)
		return vaultemail.TemplateOverride{}, false
	}
	if t == nil || !t.Enabled {
		return vaultemail.TemplateOverride{}, false
	}
	return vaultemail.TemplateOverride{
		Subject:     t.Subject,
		HTMLContent: t.HTMLContent,
		TextContent: t.TextContent,
	}, true
}

var _ vaultemail.OverrideStore = (*EmailOverrideStore)(nil)
