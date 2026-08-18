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

// Template returns the per-app override for an email type, compiled and ready
// to execute, or ok=false when none exists, it is disabled, or it does not pass
// validation.
//
// This is where a stored row becomes an executable template, so this is where
// the admin write path's validation runs a second time. The admin API is not
// the only way a row reaches email_templates — a restored backup, a direct
// write by the vault_app role, or a row written before the validation existed
// all land in the same table — and the send path used to compile whatever it
// found there (ASVS V1.3.7).
func (s *EmailOverrideStore) Template(ctx context.Context, app, name string) (*vaultemail.CompiledOverride, bool) {
	if s == nil || s.templates == nil {
		return nil, false
	}
	t, err := s.templates.Get(ctx, app, name)
	if err != nil {
		log.Printf("email: template lookup for %q/%q failed: %v", app, name, err)
		return nil, false
	}
	if t == nil || !t.Enabled {
		return nil, false
	}
	compiled, err := vaultemail.CompileOverride(vaultemail.TemplateOverride{
		Subject:     t.Subject,
		HTMLContent: t.HTMLContent,
		TextContent: t.TextContent,
	})
	if err != nil {
		log.Printf("email: stored template %q/%q refused at load: %v", app, name, err)
		return nil, false
	}
	return compiled, true
}

var _ vaultemail.OverrideStore = (*EmailOverrideStore)(nil)
