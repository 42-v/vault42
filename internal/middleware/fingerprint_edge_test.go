package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

func TestFingerprint_MissingUserAgent(t *testing.T) {
	ip := "10.0.0.1"
	lang := "en-US"

	// Compute fingerprint without User-Agent
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             ip,
		UserAgent:      "",
		AcceptLanguage: lang,
	})

	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = ip + ":12345"
	// No User-Agent header set
	req.Header.Set("Accept-Language", lang)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("matches when both have empty User-Agent", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !called {
			t.Error("handler should be called")
		}
	})
}

func TestFingerprint_MissingAcceptLanguage(t *testing.T) {
	ip := "10.0.0.2"
	ua := "TestBrowser/1.0"

	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             ip,
		UserAgent:      ua,
		AcceptLanguage: "",
	})

	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = ip + ":12345"
	req.Header.Set("User-Agent", ua)
	// No Accept-Language header set
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("matches when both have empty Accept-Language", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !called {
			t.Error("handler should be called")
		}
	})
}

func TestFingerprint_AllHeadersMissing(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "",
		UserAgent:      "",
		AcceptLanguage: "",
	})

	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "" // Empty remote addr
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("matches when all inputs are empty", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !called {
			t.Error("handler should be called")
		}
	})
}

func TestFingerprint_IPChangeMismatch(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "192.168.1.100",
		UserAgent:      "Chrome/120",
		AcceptLanguage: "en-US",
	})

	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "10.0.0.50:12345" // Different IP
	req.Header.Set("User-Agent", "Chrome/120")
	req.Header.Set("Accept-Language", "en-US")
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects on IP change in strict mode", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestFingerprint_IPChangeSoftMode(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "192.168.1.100",
		UserAgent:      "Chrome/120",
		AcceptLanguage: "en-US",
	})

	var called bool
	handler := Fingerprint(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "10.0.0.50:12345" // Different IP
	req.Header.Set("User-Agent", "Chrome/120")
	req.Header.Set("Accept-Language", "en-US")
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("allows IP change in soft mode", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !called {
			t.Error("handler should be called in soft mode")
		}
	})
}

func TestFingerprint_UserAgentChange(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Firefox/119",
		AcceptLanguage: "en-GB",
	})

	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Chrome/120") // Different UA
	req.Header.Set("Accept-Language", "en-GB")
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects user-agent change", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestFingerprint_LanguageChange(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "Chrome/120",
		AcceptLanguage: "en-US",
	})

	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Chrome/120")
	req.Header.Set("Accept-Language", "de-DE") // Different language
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects Accept-Language change", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestFingerprint_IPv6Address(t *testing.T) {
	ip := "::1"
	ua := "TestAgent/2.0"
	lang := "fr-FR"

	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             ip,
		UserAgent:      ua,
		AcceptLanguage: lang,
	})

	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "[::1]:12345"
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Language", lang)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("handles IPv6 address", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !called {
			t.Error("handler should be called for IPv6 match")
		}
	})
}

func TestFingerprint_LongUserAgent(t *testing.T) {
	ip := "5.6.7.8"
	longUA := ""
	for i := 0; i < 500; i++ {
		longUA += "A"
	}
	lang := "en-US"

	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             ip,
		UserAgent:      longUA,
		AcceptLanguage: lang,
	})

	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = ip + ":12345"
	req.Header.Set("User-Agent", longUA)
	req.Header.Set("Accept-Language", lang)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("handles long user agent", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !called {
			t.Error("handler should be called")
		}
	})
}

func TestFingerprint_SoftModeMismatchStillContinues(t *testing.T) {
	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "1.1.1.1",
		UserAgent:      "Agent1",
		AcceptLanguage: "en",
	})

	// Test multiple different mismatches in soft mode
	mismatches := []struct {
		name string
		ip   string
		ua   string
		lang string
	}{
		{"different IP", "2.2.2.2", "Agent1", "en"},
		{"different UA", "1.1.1.1", "Agent2", "en"},
		{"different lang", "1.1.1.1", "Agent1", "de"},
		{"all different", "9.9.9.9", "OtherAgent", "ja"},
	}

	for _, mm := range mismatches {
		t.Run(mm.name, func(t *testing.T) {
			var called bool
			handler := Fingerprint(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))

			claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			req.RemoteAddr = mm.ip + ":12345"
			req.Header.Set("User-Agent", mm.ua)
			req.Header.Set("Accept-Language", mm.lang)
			ctx := context.WithValue(req.Context(), ClaimsKey, claims)
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 (soft mode)", rec.Code)
			}
			if !called {
				t.Error("handler should be called in soft mode")
			}
		})
	}
}

func TestFingerprint_InvalidFingerprintInClaim(t *testing.T) {
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: "not-a-valid-hex-fingerprint"}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "TestAgent")
	req.Header.Set("Accept-Language", "en-US")
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("rejects invalid fingerprint claim", func(t *testing.T) {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (fingerprint mismatch)", rec.Code)
		}
	})
}

func TestFingerprint_UnicodeHeaders(t *testing.T) {
	ip := "1.2.3.4"
	ua := "Mozilla/5.0 (compatible; UnicodeTest/1.0 \u00e4\u00f6\u00fc)"
	lang := "de-DE,de;q=0.9"

	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             ip,
		UserAgent:      ua,
		AcceptLanguage: lang,
	})

	var called bool
	handler := Fingerprint(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	claims := &vaultcrypto.VaultClaims{Fingerprint: fp}
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.RemoteAddr = ip + ":12345"
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Language", lang)
	ctx := context.WithValue(req.Context(), ClaimsKey, claims)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	t.Run("handles unicode in headers", func(t *testing.T) {
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !called {
			t.Error("handler should be called")
		}
	})
}
