package attack

import (
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/honeypot"
)

// TestHoneypotTrapUserCaseInsensitive verifies that trap user detection
// is case-insensitive — attackers can't bypass by changing capitalization.
func TestHoneypotTrapUserCaseInsensitive(t *testing.T) {
	alerter := honeypot.NewAlerter("https://webhook.test", []string{
		"admin@example.com",
		"root@test.com",
	}, nil)

	cases := []struct {
		email string
		want  bool
	}{
		{"admin@example.com", true},
		{"ADMIN@EXAMPLE.COM", true},
		{"Admin@Example.Com", true},
		{"aDmIn@eXaMpLe.cOm", true},
		{"root@test.com", true},
		{"ROOT@TEST.COM", true},
		{"random@other.com", false},
		{"", false},
		{"admin@other.com", false},
		{"notadmin@example.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.email, func(t *testing.T) {
			got := alerter.IsTrapUser(tc.email)
			if got != tc.want {
				t.Fatalf("IsTrapUser(%q) = %v, want %v", tc.email, got, tc.want)
			}
		})
	}
}

// TestHoneypotFakeTokenFormat verifies that fake JWT tokens generated
// by the honeypot look like real JWTs (3 dot-separated base64 segments)
// but have an invalid signature that can't be verified.
func TestHoneypotFakeTokenFormat(t *testing.T) {
	d := hpService(t, false)
	token := hpTrapAccessToken(t, d)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("fake JWT should have 3 parts, got %d", len(parts))
	}

	// Header should be non-empty base64
	if len(parts[0]) < 10 {
		t.Fatal("JWT header too short")
	}

	// Payload should be non-empty base64
	if len(parts[1]) < 10 {
		t.Fatal("JWT payload too short")
	}

	// Signature should be non-empty (fake but present)
	if len(parts[2]) < 10 {
		t.Fatal("JWT signature too short — would be obvious it's fake")
	}

	// Each token should be unique (random nonce)
	token2 := hpTrapAccessToken(t, d)
	if token == token2 {
		t.Fatal("Two consecutive fake JWTs are identical — insufficient randomness")
	}
}

// TestHoneypotFakeRefreshTokenUniqueness verifies that fake refresh tokens
// are unique and look like real refresh tokens (64 hex chars).
func TestHoneypotFakeRefreshTokenUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		rt, err := honeypot.GenerateFakeRefresh()
		if err != nil {
			t.Fatalf("GenerateFakeRefresh: %v", err)
		}
		if len(rt) != 64 {
			t.Fatalf("expected 64 hex chars, got %d", len(rt))
		}
		if seen[rt] {
			t.Fatalf("duplicate refresh token at iteration %d", i)
		}
		seen[rt] = true
	}
}

// TestHoneypotRedactBody verifies that the body redactor properly masks
// password-like fields while preserving the rest of the body.
func TestHoneypotRedactBody(t *testing.T) {
	body := `{"email":"admin@test.com","password":"secret123","remember":true}`
	redacted := honeypot.RedactBody(body)

	if strings.Contains(redacted, "secret123") {
		t.Fatal("password was not redacted from body")
	}
	if !strings.Contains(redacted, "admin@test.com") {
		t.Fatal("non-sensitive data was incorrectly redacted")
	}
}

// TestHoneypotAutomationUserAgentDetection verifies detection of common
// automation tool User-Agent strings.
func TestHoneypotAutomationUserAgentDetection(t *testing.T) {
	automationUAs := []string{
		"python-requests/2.28.1",
		"curl/7.68.0",
		"Go-http-client/1.1",
		"Java/11.0.11",
		"libwww-perl/6.05",
		"Wget/1.21.1",
		"httpie/3.2.1",
		"python-urllib3/1.26.7",
		"Scrapy/2.7.0",
		"sqlmap/1.7",
		"Nikto/2.1.5",
	}

	for _, ua := range automationUAs {
		t.Run(ua, func(t *testing.T) {
			if !honeypot.IsAutomationUA(ua) {
				t.Fatalf("failed to detect automation UA: %q", ua)
			}
		})
	}

	// Real browser UAs should NOT be flagged
	realUAs := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	}

	for _, ua := range realUAs {
		t.Run("browser:"+ua[:20], func(t *testing.T) {
			if honeypot.IsAutomationUA(ua) {
				t.Fatalf("real browser UA incorrectly flagged as automation: %q", ua)
			}
		})
	}
}
