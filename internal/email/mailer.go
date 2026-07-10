package email

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"net/mail"
	"strings"
	"sync"
	"time"
)

// defaultOverrideTTL bounds how long a resolved per-app branding/template is
// cached on the send path. It also bounds how long an admin edit on one replica
// takes to become visible on the others (no cross-replica invalidation needed).
const defaultOverrideTTL = 60 * time.Second

// maxCacheEntries caps each send-path cache map. An attacker who can vary the
// X-Vault-App slug must not be able to grow these unbounded; on overflow the map
// is reset (a cheap, correct eviction — entries simply re-resolve on next use).
const maxCacheEntries = 1024

// ErrNoSender is returned by Send when the mailer has no delivery transport.
var ErrNoSender = errors.New("email: mailer has no sender configured")

// Mailer applies the per-app white-label layer on top of the global templates
// and a [Sender]. It resolves each tenant's branding, renders either a custom
// override or the global template, picks an allowlisted From line, and sends.
// A zero/absent app slug reproduces the pre-white-label global behaviour.
type Mailer struct {
	renderer           *TemplateRenderer
	sender             Sender
	store              OverrideStore // nil => no per-app overrides
	defaults           Branding
	allowedFromDomains map[string]bool
	ttl                time.Duration
	cache              *overrideCache
}

// NewMailer builds a Mailer. A nil renderer uses the package default renderer
// (set via [SetRenderer] at startup). A nil store disables per-app overrides,
// leaving global branding only. allowedFromDomains gates per-app From-address
// overrides: an empty list disables address overrides entirely (display-name
// overrides still apply, on the default address).
func NewMailer(renderer *TemplateRenderer, sender Sender, store OverrideStore, defaults Branding, allowedFromDomains []string) *Mailer {
	if renderer == nil {
		renderer = defaultRenderer
	}
	allowed := make(map[string]bool, len(allowedFromDomains))
	for _, d := range allowedFromDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			allowed[d] = true
		}
	}
	return &Mailer{
		renderer:           renderer,
		sender:             sender,
		store:              store,
		defaults:           defaults,
		allowedFromDomains: allowed,
		ttl:                defaultOverrideTTL,
		cache:              newOverrideCache(),
	}
}

// Enabled reports whether the mailer can actually deliver (a sender is wired).
func (m *Mailer) Enabled() bool { return m != nil && m.sender != nil }

// WithStore returns a copy of the mailer that resolves per-app overrides through
// store and applies the given defaults/allowlist, keeping the same sender and
// renderer. Used to upgrade a constructor-built default mailer at wiring time.
func (m *Mailer) WithStore(store OverrideStore, defaults Branding, allowedFromDomains []string) *Mailer {
	upgraded := NewMailer(m.renderer, m.sender, store, defaults, allowedFromDomains)
	return upgraded
}

// Send renders the named template for app (falling back to global branding when
// app is empty or unknown) and delivers it to the recipient.
func (m *Mailer) Send(ctx context.Context, app, templateName, to string, data TemplateData) error {
	if !m.Enabled() {
		return ErrNoSender
	}
	b := m.resolveBranding(ctx, app)
	if data.AppName == "" {
		data.AppName = b.AppName
	}
	if data.LogoURL == "" {
		data.LogoURL = b.LogoURL
	}
	if data.PrimaryColor == "" {
		data.PrimaryColor = b.PrimaryColor
	}

	subject, html, text, ok := m.renderOverride(ctx, app, templateName, data)
	if !ok {
		subject, html, text = m.renderer.Render(templateName, data)
	}

	return m.sender.Send(ctx, m.resolveFrom(b), to, subject, html, text)
}

// resolveBranding overlays the per-app branding (if any) on the global defaults.
func (m *Mailer) resolveBranding(ctx context.Context, app string) Branding {
	if app == "" || m.store == nil {
		return m.defaults
	}
	if b, ok := m.cache.getBranding(app); ok {
		return b
	}
	b := m.defaults
	if sb, ok := m.store.Branding(ctx, app); ok {
		if sb.AppName != "" {
			b.AppName = sb.AppName
		}
		if sb.LogoURL != "" {
			b.LogoURL = sb.LogoURL
		}
		if sb.PrimaryColor != "" {
			b.PrimaryColor = sb.PrimaryColor
		}
		if sb.FromName != "" {
			b.FromName = sb.FromName
		}
		if sb.FromAddress != "" {
			b.FromAddress = sb.FromAddress
		}
	}
	m.cache.putBranding(app, b, time.Now().Add(m.ttl))
	return b
}

// renderOverride renders a per-app custom template if one exists and is enabled.
// ok is false when there is no override and the caller should use the global one.
func (m *Mailer) renderOverride(ctx context.Context, app, templateName string, data TemplateData) (subject, html, text string, ok bool) {
	if app == "" || m.store == nil {
		return "", "", "", false
	}
	c, found := m.cache.getTemplate(app, templateName)
	if !found {
		c = cachedTemplate{exp: time.Now().Add(m.ttl)}
		if ov, has := m.store.Template(ctx, app, templateName); has {
			if st, ht, err := compileOverride(ov.Subject, ov.HTMLContent); err == nil {
				c.subj, c.htmlTmpl, c.text, c.ok = st, ht, ov.TextContent, true
			}
		}
		m.cache.putTemplate(app, templateName, c)
	}
	if !c.ok {
		return "", "", "", false
	}

	var subBuf, htmlBuf bytes.Buffer
	if err := c.subj.Execute(&subBuf, data); err != nil {
		return "", "", "", false
	}
	subject = strings.TrimSpace(subBuf.String())
	data.Subject = subject
	if err := c.htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return "", "", "", false
	}
	html = htmlBuf.String()
	text = c.text
	if strings.TrimSpace(text) == "" {
		text = stripHTML(html)
	}
	return subject, html, text, true
}

// resolveFrom picks the From identity. The display name always applies; the
// address override applies only when its domain is on the allowlist (otherwise
// the sender's verified default address is used).
func (m *Mailer) resolveFrom(b Branding) Address {
	from := Address{Name: b.FromName}
	if b.FromAddress != "" && m.fromDomainAllowed(b.FromAddress) {
		from.Email = b.FromAddress
	}
	return from
}

func (m *Mailer) fromDomainAllowed(addr string) bool {
	if len(m.allowedFromDomains) == 0 {
		return false
	}
	// Parse to the canonical address first so a display-name wrapper or quoted
	// local part can't smuggle a different domain past the gate.
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return false
	}
	at := strings.LastIndex(parsed.Address, "@")
	if at < 0 || at == len(parsed.Address)-1 {
		return false
	}
	return m.allowedFromDomains[strings.ToLower(parsed.Address[at+1:])]
}

// compileOverride parses a custom subject + HTML body into executable templates,
// using the same safe function map (and therefore the same safeURL guard) as the
// global templates.
func compileOverride(subject, htmlContent string) (*template.Template, *template.Template, error) {
	st, err := template.New("subject").Funcs(safeFuncMap()).Parse(subject)
	if err != nil {
		return nil, nil, err
	}
	ht, err := template.New("html").Funcs(safeFuncMap()).Parse(htmlContent)
	if err != nil {
		return nil, nil, err
	}
	return st, ht, nil
}

// --- send-path cache -------------------------------------------------------

type cachedBranding struct {
	b   Branding
	exp time.Time
}

type cachedTemplate struct {
	subj     *template.Template
	htmlTmpl *template.Template
	text     string
	ok       bool
	exp      time.Time
}

type overrideCache struct {
	mu        sync.RWMutex
	branding  map[string]cachedBranding
	templates map[string]cachedTemplate
}

func newOverrideCache() *overrideCache {
	return &overrideCache{
		branding:  make(map[string]cachedBranding),
		templates: make(map[string]cachedTemplate),
	}
}

func (c *overrideCache) getBranding(app string) (Branding, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.branding[app]
	if !ok || time.Now().After(e.exp) {
		return Branding{}, false
	}
	return e.b, true
}

func (c *overrideCache) putBranding(app string, b Branding, exp time.Time) {
	c.mu.Lock()
	if len(c.branding) >= maxCacheEntries {
		c.branding = make(map[string]cachedBranding)
	}
	c.branding[app] = cachedBranding{b: b, exp: exp}
	c.mu.Unlock()
}

func (c *overrideCache) getTemplate(app, name string) (cachedTemplate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.templates[app+"\x00"+name]
	if !ok || time.Now().After(e.exp) {
		return cachedTemplate{}, false
	}
	return e, true
}

func (c *overrideCache) putTemplate(app, name string, e cachedTemplate) {
	c.mu.Lock()
	if len(c.templates) >= maxCacheEntries {
		c.templates = make(map[string]cachedTemplate)
	}
	c.templates[app+"\x00"+name] = e
	c.mu.Unlock()
}
