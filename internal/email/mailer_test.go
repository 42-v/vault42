package email

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// captureSender records the last message the Mailer handed to the transport.
type captureSender struct {
	from    Address
	to      string
	subject string
	html    string
	text    string
	calls   int
}

func (c *captureSender) Send(_ context.Context, from Address, to, subject, html, text string) error {
	c.from, c.to, c.subject, c.html, c.text = from, to, subject, html, text
	c.calls++
	return nil
}

// staticStore serves one app's branding + template override.
type staticStore struct {
	app      string
	branding Branding
	brandOK  bool
	tmpl     TemplateOverride
	tmplOK   bool
	brandHit int
	tmplHit  int
}

func (s *staticStore) Branding(_ context.Context, app string) (Branding, bool) {
	s.brandHit++
	if app == s.app && s.brandOK {
		return s.branding, true
	}
	return Branding{}, false
}

// Template compiles through the same constructor the real store uses, so a
// fake cannot hand the mailer a template the production path would refuse.
func (s *staticStore) Template(_ context.Context, app, _ string) (*CompiledOverride, bool) {
	s.tmplHit++
	if app == s.app && s.tmplOK {
		c, err := CompileOverride(s.tmpl)
		if err != nil {
			return nil, false
		}
		return c, true
	}
	return nil, false
}

func testMailer(t *testing.T, sender Sender, store OverrideStore, defaults Branding, allowed []string) *Mailer {
	t.Helper()
	r, err := NewTemplateRenderer("")
	if err != nil {
		t.Fatalf("NewTemplateRenderer: %v", err)
	}
	return NewMailer(r, sender, store, defaults, allowed)
}

func TestMailer_SendGlobalBranding(t *testing.T) {
	cap := &captureSender{}
	m := testMailer(t, cap, nil, Branding{AppName: "Vault", FromName: "Vault"}, nil)

	if err := m.Send(context.Background(), "", TemplateVerification, "u@test.com", TemplateData{URL: "https://vault.test/v"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if cap.calls != 1 || cap.to != "u@test.com" {
		t.Fatalf("sender not invoked correctly: %+v", cap)
	}
	if cap.subject == "" || cap.html == "" {
		t.Error("global template produced empty subject/html")
	}
	if cap.from.Name != "Vault" {
		t.Errorf("From name = %q, want the default Vault", cap.from.Name)
	}
}

func TestMailer_SendPerAppOverride(t *testing.T) {
	cap := &captureSender{}
	store := &staticStore{
		app:      "acme",
		branding: Branding{AppName: "Acme", FromName: "Acme Support", FromAddress: "no-reply@acme.test"},
		brandOK:  true,
		tmpl:     TemplateOverride{Subject: "Acme: {{.AppName}} verify", HTMLContent: "<p>Code {{.Code}}</p>"},
		tmplOK:   true,
	}
	m := testMailer(t, cap, store, Branding{AppName: "Vault"}, []string{"acme.test"})

	err := m.Send(context.Background(), "acme", TemplateVerification, "u@acme.test", TemplateData{Code: "123456"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if cap.subject != "Acme: Acme verify" {
		t.Errorf("subject = %q, want the rendered override", cap.subject)
	}
	if !contains(cap.html, "123456") {
		t.Errorf("html = %q, want it to contain the rendered code 123456", cap.html)
	}
	// From address is on the allowlist, so it is honored.
	if cap.from.Email != "no-reply@acme.test" || cap.from.Name != "Acme Support" {
		t.Errorf("From = %+v, want the allowlisted acme address", cap.from)
	}

	// Second send for the same app is served from the cache (no new store hits).
	brandBefore, tmplBefore := store.brandHit, store.tmplHit
	if err := m.Send(context.Background(), "acme", TemplateVerification, "u2@acme.test", TemplateData{Code: "999"}); err != nil {
		t.Fatalf("Send (cached): %v", err)
	}
	if store.brandHit != brandBefore || store.tmplHit != tmplBefore {
		t.Errorf("cache miss on second send: branding %d->%d, template %d->%d",
			brandBefore, store.brandHit, tmplBefore, store.tmplHit)
	}
}

func TestMailer_BadOverrideFallsBackToGlobal(t *testing.T) {
	tests := []struct {
		name string
		tmpl TemplateOverride
	}{
		{"subject execute error", TemplateOverride{Subject: "{{.Missing}}", HTMLContent: "<p>x</p>"}},
		{"html execute error", TemplateOverride{Subject: "S", HTMLContent: "{{.Missing}}"}},
		{"subject parse error", TemplateOverride{Subject: "{{if}}", HTMLContent: "<p>x</p>"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cap := &captureSender{}
			store := &staticStore{app: "acme", tmpl: tt.tmpl, tmplOK: true}
			m := testMailer(t, cap, store, Branding{AppName: "Vault"}, nil)

			if err := m.Send(context.Background(), "acme", TemplateVerification, "u@test.com", TemplateData{URL: "https://vault.test/v"}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			wantSubject, wantHTML, _ := m.renderer.Render(TemplateVerification, TemplateData{AppName: "Vault", URL: "https://vault.test/v"})
			if cap.subject != wantSubject {
				t.Errorf("subject = %q, want the global %q", cap.subject, wantSubject)
			}
			if cap.html != wantHTML {
				t.Error("html did not fall back to the global render")
			}
		})
	}
}

func TestMailer_BrandingLogoAndColorOverlay(t *testing.T) {
	cap := &captureSender{}
	store := &staticStore{
		app:      "acme",
		branding: Branding{AppName: "Acme", LogoURL: "https://cdn.acme.test/logo.png", PrimaryColor: "#123456"},
		brandOK:  true,
	}
	m := testMailer(t, cap, store, Branding{AppName: "Vault"}, nil)

	if err := m.Send(context.Background(), "acme", TemplateVerification, "u@test.com", TemplateData{URL: "https://vault.test/v"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !contains(cap.html, "https://cdn.acme.test/logo.png") {
		t.Error("html missing the per-app logo URL")
	}
	if !contains(cap.html, "#123456") {
		t.Error("html missing the per-app primary color")
	}
}

func TestOverrideCache_ResetOnMaxEntries(t *testing.T) {
	c := newOverrideCache()
	exp := time.Now().Add(time.Hour)

	for i := 0; i < maxCacheEntries; i++ {
		c.putBranding(fmt.Sprintf("app-%d", i), Branding{}, exp)
	}
	if len(c.branding) != maxCacheEntries {
		t.Fatalf("branding entries = %d, want %d", len(c.branding), maxCacheEntries)
	}
	c.putBranding("overflow", Branding{AppName: "Over"}, exp)
	if len(c.branding) != 1 {
		t.Errorf("branding entries after overflow = %d, want 1 (map reset)", len(c.branding))
	}
	if b, ok := c.getBranding("overflow"); !ok || b.AppName != "Over" {
		t.Errorf("overflow branding entry = %+v (ok=%v), want it stored after the reset", b, ok)
	}

	for i := 0; i < maxCacheEntries; i++ {
		c.putTemplate(fmt.Sprintf("app-%d", i), TemplateVerification, cachedTemplate{exp: exp})
	}
	if len(c.templates) != maxCacheEntries {
		t.Fatalf("template entries = %d, want %d", len(c.templates), maxCacheEntries)
	}
	compiled, err := CompileOverride(TemplateOverride{Subject: "S", HTMLContent: "<p>b</p>"})
	if err != nil {
		t.Fatalf("CompileOverride: %v", err)
	}
	c.putTemplate("overflow", TemplateVerification, cachedTemplate{compiled: compiled, exp: exp})
	if len(c.templates) != 1 {
		t.Errorf("template entries after overflow = %d, want 1 (map reset)", len(c.templates))
	}
	if e, ok := c.getTemplate("overflow", TemplateVerification); !ok || e.compiled == nil {
		t.Errorf("overflow template entry = %+v (ok=%v), want it stored after the reset", e, ok)
	}
}

func TestMailer_FromAddressDomainNotAllowed(t *testing.T) {
	cap := &captureSender{}
	store := &staticStore{
		app:      "acme",
		branding: Branding{AppName: "Acme", FromName: "Acme", FromAddress: "no-reply@evil.test"},
		brandOK:  true,
	}
	// Allowlist does not include evil.test, so the address override is dropped
	// but the display name still applies.
	m := testMailer(t, cap, store, Branding{AppName: "Vault"}, []string{"acme.test"})

	if err := m.Send(context.Background(), "acme", TemplateVerification, "u@test.com", TemplateData{URL: "https://x/y"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if cap.from.Email == "no-reply@evil.test" {
		t.Error("off-allowlist From address was honored")
	}
	if cap.from.Name != "Acme" {
		t.Errorf("From name = %q, want the display name to still apply", cap.from.Name)
	}
}

func TestMailer_DisabledReturnsErrNoSender(t *testing.T) {
	m := testMailer(t, nil, nil, Branding{}, nil)
	if err := m.Send(context.Background(), "", TemplateVerification, "u@test.com", TemplateData{}); err != ErrNoSender {
		t.Errorf("Send without sender = %v, want ErrNoSender", err)
	}
	if m.Enabled() {
		t.Error("Enabled() true with nil sender")
	}
}

func TestMailer_WithStoreUpgrade(t *testing.T) {
	cap := &captureSender{}
	base := testMailer(t, cap, nil, Branding{AppName: "Vault"}, nil)
	store := &staticStore{app: "acme", branding: Branding{AppName: "Acme"}, brandOK: true}

	upgraded := base.WithStore(store, Branding{AppName: "Vault"}, []string{"acme.test"})
	if err := upgraded.Send(context.Background(), "acme", TemplateVerification, "u@acme.test", TemplateData{URL: "https://x/y"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if store.brandHit == 0 {
		t.Error("WithStore-upgraded mailer did not consult the store")
	}
}
