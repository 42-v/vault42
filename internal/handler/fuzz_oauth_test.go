package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/service"
)

// FuzzIsSafeAuthorizeRedirect is the open-redirect gate on the URL a
// configured provider produces. The authorize URL is server-built, but the
// check is what sanitizes the value that flows into http.Redirect.
func FuzzIsSafeAuthorizeRedirect(f *testing.F) {
	f.Add("https://github.com/login/oauth/authorize?client_id=x")
	f.Add("https://www.facebook.com/v19.0/dialog/oauth?state=y")
	f.Add("http://github.com/login/oauth/authorize")
	f.Add("/auth/evil")
	f.Add("//evil.example.com/x")
	f.Add("javascript:alert(1)")
	f.Add("")
	f.Add("://nope")
	f.Add("https://")
	f.Add("https:evil.com")
	f.Add("HTTPS://github.com/login/oauth/authorize")

	f.Fuzz(func(t *testing.T, raw string) {
		ok := isSafeAuthorizeRedirect(raw)
		if !ok {
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("accepted %q but url.Parse rejected it: %v", raw, err)
		}
		if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
			t.Fatalf("accepted a URL that is not absolute https: %q (scheme=%q host=%q)", raw, u.Scheme, u.Host)
		}
	})
}

// FuzzMintRequestJSON is the POST /mint body decoder: strict JSON with
// unknown fields rejected, then the subject / TTL validators the handler
// runs on whatever survived.
func FuzzMintRequestJSON(f *testing.F) {
	f.Add([]byte(`{"subject":"user-1"}`))
	f.Add([]byte(`{"subject":"alice@example.com","roles":["reader"],"scopes":["read"],"ttl_seconds":60}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`{"subject":"u","extra":true}`))
	f.Add([]byte(`{"suBjeCt":"user-1"}`))
	f.Add([]byte(`{"SUBJECT":"user-1"}`))
	f.Add([]byte(`{"subject":1}`))
	f.Add([]byte(`{"ttl_seconds":-1}`))
	f.Add([]byte(`{"ttl_seconds":999999999}`))
	f.Add([]byte(`{"subject":"` + strings.Repeat("a", 200) + `"}`))
	f.Add([]byte("\xff\xfe"))

	f.Fuzz(func(t *testing.T, body []byte) {
		req := httptest.NewRequest(http.MethodPost, "/mint", bytes.NewReader(body))
		var parsed MintRequestBody
		err := decodeJSON(req, &parsed)

		var probe map[string]json.RawMessage
		probeErr := json.Unmarshal(body, &probe)
		if probeErr == nil {
			// encoding/json matches struct tags case-insensitively
			// (EqualFold). DisallowUnknownFields therefore accepts
			// "suBjeCt" as "subject"; a case-sensitive allow-list
			// treats that as an unknown key and fails on first
			// execution. The contract is fold-equal, not exact.
			for k := range probe {
				if !mintRequestJSONField(k) && err == nil {
					t.Fatalf("unknown field %q was accepted in %q", k, body)
				}
			}
		}
		if err != nil {
			return
		}

		// The handler always converts TTL then calls Mint, which
		// re-validates the subject. A decoded subject the validator
		// would reject is a 400, not a signed token. The result is
		// checked: discarding it would let a broken validator (always
		// nil, or a non-ErrMintSubjectInvalid error) look like success.
		subErr := service.ValidateMintSubject(parsed.Subject)
		if subErr != nil {
			if !errors.Is(subErr, service.ErrMintSubjectInvalid) {
				t.Fatalf("ValidateMintSubject(%q) = %v, want ErrMintSubjectInvalid", parsed.Subject, subErr)
			}
		} else {
			s := parsed.Subject
			if s == "" || len(s) > 128 {
				t.Fatalf("ValidateMintSubject accepted empty or over-long %q", s)
			}
			if s[0] < '0' || (s[0] > '9' && s[0] < 'A') || (s[0] > 'Z' && s[0] < 'a') || s[0] > 'z' {
				t.Fatalf("ValidateMintSubject accepted a subject that does not start with alphanumeric: %q", s)
			}
			for i := 1; i < len(s); i++ {
				c := s[i]
				ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
					c == '.' || c == '_' || c == '@' || c == '-'
				if !ok {
					t.Fatalf("ValidateMintSubject accepted a forbidden byte %q at %d in %q", c, i, s)
				}
			}
		}

		d, ttlErr := service.MintTTLFromSeconds(parsed.TTLSeconds)
		if parsed.TTLSeconds < 0 || parsed.TTLSeconds > 900 {
			if ttlErr == nil {
				t.Fatalf("MintTTLFromSeconds(%d) = %v, want error", parsed.TTLSeconds, d)
			}
		} else if ttlErr != nil {
			t.Fatalf("MintTTLFromSeconds(%d) rejected an in-range value: %v", parsed.TTLSeconds, ttlErr)
		} else if parsed.TTLSeconds != 0 && int(d.Seconds()) != parsed.TTLSeconds {
			t.Fatalf("MintTTLFromSeconds(%d) = %v, seconds do not round-trip", parsed.TTLSeconds, d)
		}
	})
}

// mintRequestJSONField reports whether k is a MintRequestBody field name
// under encoding/json's case-insensitive match.
func mintRequestJSONField(k string) bool {
	switch {
	case strings.EqualFold(k, "subject"),
		strings.EqualFold(k, "roles"),
		strings.EqualFold(k, "scopes"),
		strings.EqualFold(k, "ttl_seconds"),
		strings.EqualFold(k, "email"):
		return true
	default:
		return false
	}
}
