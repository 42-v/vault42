package service

import (
	"context"
	"errors"
	"testing"

	vaultemail "github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/model"
)

// fakeBrandingRepo / fakeTemplateRepo are in-memory repositories for the
// EmailOverrideStore send-path adapter. A non-nil err forces failure.
type fakeBrandingRepo struct {
	b   *model.EmailBranding
	err error
}

func (f *fakeBrandingRepo) Get(context.Context, string) (*model.EmailBranding, error) {
	return f.b, f.err
}

func (f *fakeBrandingRepo) List(context.Context) ([]*model.EmailBranding, error) { return nil, f.err }
func (f *fakeBrandingRepo) Upsert(context.Context, *model.EmailBranding) error   { return f.err }
func (f *fakeBrandingRepo) Delete(context.Context, string) error                 { return f.err }

type fakeTemplateRepo struct {
	t   *model.EmailTemplate
	err error
}

func (f *fakeTemplateRepo) Get(context.Context, string, string) (*model.EmailTemplate, error) {
	return f.t, f.err
}

func (f *fakeTemplateRepo) ListByApp(context.Context, string) ([]*model.EmailTemplate, error) {
	return nil, f.err
}

func (f *fakeTemplateRepo) List(context.Context) ([]*model.EmailTemplate, error) { return nil, f.err }
func (f *fakeTemplateRepo) Upsert(context.Context, *model.EmailTemplate) error   { return f.err }
func (f *fakeTemplateRepo) Delete(context.Context, string, string) error         { return f.err }

func TestEmailOverrideStore_Branding(t *testing.T) {
	ctx := context.Background()

	t.Run("nil store and nil repo return no override", func(t *testing.T) {
		var s *EmailOverrideStore
		if _, ok := s.Branding(ctx, "acme"); ok {
			t.Error("nil store should report no branding")
		}
		if _, ok := NewEmailOverrideStore(nil, nil).Branding(ctx, "acme"); ok {
			t.Error("nil branding repo should report no branding")
		}
	})

	t.Run("found maps all fields", func(t *testing.T) {
		s := NewEmailOverrideStore(&fakeBrandingRepo{b: &model.EmailBranding{
			App: "acme", AppName: "Acme", LogoURL: "https://acme.test/l.png",
			PrimaryColor: "#00FF42", FromName: "Acme", FromAddress: "no-reply@acme.test",
		}}, nil)
		got, ok := s.Branding(ctx, "acme")
		if !ok {
			t.Fatal("expected branding")
		}
		want := vaultemail.Branding{AppName: "Acme", LogoURL: "https://acme.test/l.png", PrimaryColor: "#00FF42", FromName: "Acme", FromAddress: "no-reply@acme.test"}
		if got != want {
			t.Errorf("Branding = %+v, want %+v", got, want)
		}
	})

	t.Run("absent returns no override", func(t *testing.T) {
		s := NewEmailOverrideStore(&fakeBrandingRepo{b: nil}, nil)
		if _, ok := s.Branding(ctx, "ghost"); ok {
			t.Error("absent branding should report ok=false")
		}
	})

	t.Run("repo error degrades to no override", func(t *testing.T) {
		s := NewEmailOverrideStore(&fakeBrandingRepo{err: errors.New("db down")}, nil)
		if _, ok := s.Branding(ctx, "acme"); ok {
			t.Error("a branding lookup error must never block an auth email")
		}
	})
}

func TestEmailOverrideStore_Template(t *testing.T) {
	ctx := context.Background()

	t.Run("nil store and nil repo return no override", func(t *testing.T) {
		var s *EmailOverrideStore
		if _, ok := s.Template(ctx, "acme", "verification"); ok {
			t.Error("nil store should report no template")
		}
		if _, ok := NewEmailOverrideStore(nil, nil).Template(ctx, "acme", "verification"); ok {
			t.Error("nil template repo should report no template")
		}
	})

	t.Run("enabled template maps fields", func(t *testing.T) {
		s := NewEmailOverrideStore(nil, &fakeTemplateRepo{t: &model.EmailTemplate{
			App: "acme", TemplateName: "verification", Subject: "Verify",
			HTMLContent: "<p>hi</p>", TextContent: "hi", Enabled: true,
		}})
		got, ok := s.Template(ctx, "acme", "verification")
		if !ok {
			t.Fatal("expected template")
		}
		if got == nil {
			t.Fatal("Template returned ok with a nil compiled override")
		}
	})

	t.Run("disabled template is not applied", func(t *testing.T) {
		s := NewEmailOverrideStore(nil, &fakeTemplateRepo{t: &model.EmailTemplate{App: "acme", TemplateName: "verification", Enabled: false}})
		if _, ok := s.Template(ctx, "acme", "verification"); ok {
			t.Error("a disabled template must report ok=false")
		}
	})

	t.Run("absent and error degrade to no override", func(t *testing.T) {
		if _, ok := NewEmailOverrideStore(nil, &fakeTemplateRepo{t: nil}).Template(ctx, "acme", "verification"); ok {
			t.Error("absent template should report ok=false")
		}
		if _, ok := NewEmailOverrideStore(nil, &fakeTemplateRepo{err: errors.New("db down")}).Template(ctx, "acme", "verification"); ok {
			t.Error("a template lookup error must never block an auth email")
		}
	})
}
