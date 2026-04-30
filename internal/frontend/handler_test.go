package frontend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesIndexHTML(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "The Vault") {
		t.Error("GET / should return index.html containing 'The Vault'")
	}
}

func TestHandlerSPAFallback(t *testing.T) {
	h := Handler()
	// Non-existent path should fall back to index.html (SPA routing)
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /login status = %d, want 200 (SPA fallback)", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "The Vault") {
		t.Error("SPA fallback should return index.html")
	}
}

func TestHandlerServesIndexHTMLRedirect(t *testing.T) {
	h := Handler()
	// Go's FileServer redirects /index.html to / (clean URL)
	req := httptest.NewRequest("GET", "/index.html", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Errorf("GET /index.html status = %d, want 301 (redirect to /)", w.Code)
	}
}

func TestHandlerDeepSPARoute(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest("GET", "/settings/security/2fa", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /settings/security/2fa status = %d, want 200 (SPA fallback)", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "The Vault") {
		t.Error("deep SPA route should return index.html")
	}
}
