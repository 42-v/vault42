package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsDecoyPath(t *testing.T) {
	tests := []struct {
		path    string
		isDecoy bool
		tmpl    string
	}{
		{"/wp-admin", true, "wp-login.html"},
		{"/wp-admin/", true, "wp-login.html"},
		{"/wp-login.php", true, "wp-login.html"},
		{"/phpmyadmin", true, "phpmyadmin.html"},
		{"/pma", true, "phpmyadmin.html"},
		{"/cpanel", true, "cpanel.html"},
		{"/webmail", true, "cpanel.html"},
		{"/admin", true, "admin.html"},
		{"/administrator", true, "admin.html"},
		{"/auth/login", false, ""},
		{"/healthz", false, ""},
		{"/", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			tmpl, ok := IsDecoyPath(tt.path)
			if ok != tt.isDecoy {
				t.Errorf("IsDecoyPath(%q) = %v, want %v", tt.path, ok, tt.isDecoy)
			}
			if tmpl != tt.tmpl {
				t.Errorf("IsDecoyPath(%q) template = %q, want %q", tt.path, tmpl, tt.tmpl)
			}
		})
	}
}

func TestDecoyServesHTMLOnGET(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	dh.ServeDecoy(w, req, "10.0.0.1", "wp-login.html")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !fs.IsFlagged("10.0.0.1") {
		t.Error("IP should be flagged after decoy hit")
	}
}

func TestDecoyReturnsFakeCredentialsOnPOST(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	req := httptest.NewRequest(http.MethodPost, "/wp-login.php", nil)
	w := httptest.NewRecorder()

	dh.ServeDecoy(w, req, "10.0.0.2", "wp-login.html")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !fs.IsFlagged("10.0.0.2") {
		t.Error("IP should be flagged after decoy POST")
	}
}
