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
var decoyPaths = map[string]string{
	"/wp-admin":      "wp-login.html",
	"/wp-login.php":  "wp-login.html",
	"/phpmyadmin":    "phpmyadmin.html",
	"/pma":           "phpmyadmin.html",
	"/cpanel":        "cpanel.html",
	"/webmail":       "cpanel.html",
	"/admin":         "admin.html",
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

// ServeDecoy serves a fake login page and flags the IP.
func (dh *DecoyHandler) ServeDecoy(w http.ResponseWriter, r *http.Request, ip string, tmplName string) {
	// Flag IP immediately — decoy hit = instant flag
	reason := "decoy:" + r.URL.Path
	dh.flags.Flag(ip, reason, 100)
	log.Printf("bridge: decoy hit from %s path=%s", ip, r.URL.Path) // #nosec G706 -- IP from RemoteAddr, path from known decoy set

	if dh.webhook != nil {
		dh.webhook.Send(map[string]interface{}{
			"event":      "decoy_hit",
			"ip":         ip,
			"path":       r.URL.Path,
			"user_agent": r.UserAgent(),
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
