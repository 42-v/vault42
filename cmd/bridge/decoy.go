package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"strings"
)

//go:embed decoys/*.html
var decoyFS embed.FS

// DecoyHandler serves fake login pages and flags IPs that interact with them.
type DecoyHandler struct {
	flags     *FlagStore
	templates map[string]*template.Template
	webhook   *WebhookSender
}

// NewDecoyHandler creates a decoy page handler.
func NewDecoyHandler(flags *FlagStore, webhook *WebhookSender) *DecoyHandler {
	dh := &DecoyHandler{
		flags:     flags,
		templates: make(map[string]*template.Template),
		webhook:   webhook,
	}

	for _, name := range []string{"wp-login.html", "phpmyadmin.html", "cpanel.html", "admin.html"} {
		tmpl, err := template.ParseFS(decoyFS, "decoys/"+name)
		if err != nil {
			log.Printf("bridge: failed to parse decoy template %s: %v", name, err)
			continue
		}
		dh.templates[name] = tmpl
	}

	return dh
}

// decoyPaths maps URL path prefixes to their decoy template.
//
// Every prefix here must be one vault42 does not itself serve. A decoy is not a
// passive 404: hitting one flags the caller for BRIDGE_FLAG_TTL, and for that
// whole window every request from them is answered with fabricated key, user,
// session and audit data, with nothing to indicate the switch. Aiming that at a
// real route aims it at whoever legitimately uses the route.
//
// `/admin` used to be in this list and did exactly that. vault42 serves its
// admin SPA and roughly thirty documented API routes under `/admin/`, and
// IsDecoyPath matches by prefix, so an operator opening the admin console
// through a bridge was flagged for twenty-four hours and then shown a fabricated
// console. `POST /admin/auth/login` is the first request they make.
// `/administrator` stays: it is Joomla's, not ours, and nothing under it is
// registered.
//
// tests/spec/decoy_paths_test.go holds this property down against the real
// route registrations rather than against this comment.
var decoyPaths = map[string]string{
	"/wp-admin":      "wp-login.html",
	"/wp-login.php":  "wp-login.html",
	"/phpmyadmin":    "phpmyadmin.html",
	"/pma":           "phpmyadmin.html",
	"/cpanel":        "cpanel.html",
	"/webmail":       "cpanel.html",
	"/administrator": "admin.html",
}

// IsDecoyPath checks if the request path matches a known decoy path.
func IsDecoyPath(path string) (string, bool) {
	lower := strings.ToLower(path)
	for prefix, tmpl := range decoyPaths {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") || strings.HasPrefix(lower, prefix+"?") {
			return tmpl, true
		}
	}
	return "", false
}

// maxReasonPathLen caps how much of a caller-chosen path is kept.
//
// IsDecoyPath matches by prefix, so everything after it is the caller's. The
// full path went into the flag reason, which is held in memory AND in Redis for
// FlagTTL (24h), and into the webhook body. MaxHeaderBytes is 1 MiB, so one
// request produced a ~1 MB reason held for a day and a ~1 MB webhook POST; the
// bridge's memory limit is 64Mi, so about sixty-four addresses pinned it, and
// with a briefly slow webhook receiver the 1024-deep queue did it from one.
const maxReasonPathLen = 256

// truncatePath bounds a caller-chosen path before it is stored or forwarded.
func truncatePath(path string) string {
	if len(path) <= maxReasonPathLen {
		return path
	}
	return path[:maxReasonPathLen] + "..."
}

// ServeDecoy serves a fake login page and flags the IP.
//
// coerced is true when fetch metadata says the browser was made to issue this
// request by a page the visitor did not choose to talk to us. The decoy is
// still served — an attacker learns nothing from the response either way — but
// no flag is raised, because the flagged party would be the victim whose
// browser was borrowed, and their whole NAT egress with them.
func (dh *DecoyHandler) ServeDecoy(w http.ResponseWriter, r *http.Request, ip string, tmplName string, coerced bool) {
	// Flag IP immediately — decoy hit = instant flag
	path := truncatePath(r.URL.Path)
	reason := "decoy:" + path
	if !coerced {
		dh.flags.Flag(ip, reason, 100)
	}
	// Quoted, not interpolated. IsDecoyPath matches by prefix, so everything
	// after the prefix is chosen by the caller: /wp-admin/<anything> is a hit.
	// %q escapes control bytes, which stops an escape sequence clearing the
	// terminal of whoever is reading these logs during the scan that wrote them,
	// and stops a newline forging a whole record.
	log.Printf("bridge: decoy hit from %s path=%q coerced=%t", obfuscatedIP(ip), path, coerced) // #nosec G706 -- masked network, path quoted and truncated

	if dh.webhook != nil && !coerced {
		dh.webhook.Send(map[string]interface{}{
			"event":      "decoy_hit",
			"ip":         ip,
			"path":       path,
			"user_agent": truncatePath(r.UserAgent()),
			"method":     r.Method,
		})
	}

	if r.Method == http.MethodPost {
		// POST to decoy form — return fake "invalid credentials"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_credentials","message":"Invalid username or password"}`)) // #nosec G104 -- best-effort response
		return
	}

	tmpl, ok := dh.templates[tmplName]
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("bridge: decoy template error: %v", err)
	}
}
