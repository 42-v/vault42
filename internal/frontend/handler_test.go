package frontend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// servedIndex drives the handler and returns the body it produced for path.
//
// These tests used to assert the body contained the brand string "The Vault".
// That coupled them to the wording of a page rather than to the behavior of the
// handler, and it broke the moment the embedded placeholder was rewritten to
// explain itself instead of impersonating a real build. What the handler
// actually promises is that every non-asset path is answered with the SAME
// embedded document, which is what makes client-side routing work, so that is
// what is asserted now.
func servedIndex(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", path, w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") || !strings.Contains(body, "</html>") {
		t.Fatalf("GET %s did not return an HTML document: %.120q", path, body)
	}
	return body
}

func TestHandlerServesIndexHTML(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Error("GET / should return the embedded index.html")
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
	if !strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Error("SPA fallback should return the embedded index.html")
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
	if !strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Error("deep SPA route should return the embedded index.html")
	}
}

// The SPA fallback is only useful if every client-side route receives byte for
// byte the same document. A handler that answered "/" from the embedded file and
// a deep route from somewhere else would pass each test above individually and
// still break routing.
func TestHandlerServesTheSameDocumentForEveryClientRoute(t *testing.T) {
	h := Handler()
	root := servedIndex(t, h, "/")
	for _, path := range []string{"/login", "/settings/security/2fa", "/a/b/c/d"} {
		if got := servedIndex(t, h, path); got != root {
			t.Errorf("GET %s returned a different document from GET /; client-side "+
				"routing needs one entry point", path)
		}
	}
}

// The placeholder that ships when the SPA has not been built must not reference
// asset files that are not embedded alongside it.
//
// The previous placeholder was a copy of a real build's index.html, so it
// pointed at /assets/index-<hash>.js and /assets/index-<hash>.css. Those files
// are gitignored, so every go install and every release archive served a page
// that 404ed on its own script and stylesheet: a blank screen with two console
// errors and nothing explaining why. A placeholder has to be self-contained.
func TestPlaceholderReferencesNoUnembeddedAssets(t *testing.T) {
	body := servedIndex(t, Handler(), "/")
	if !strings.Contains(body, "dashboard is not in this binary") {
		t.Skip("a real SPA build is embedded; this test guards the placeholder only")
	}
	for _, ref := range []string{"/assets/", "src=\"/", "href=\"/assets"} {
		if strings.Contains(body, ref) {
			t.Errorf("the placeholder references %q, which is not embedded with it; "+
				"it must be self-contained", ref)
		}
	}
}
