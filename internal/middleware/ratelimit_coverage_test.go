package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// ---------------------------------------------------------------------------
// LoginRateLimitKey tests
// ---------------------------------------------------------------------------

func TestLoginRateLimitKeyBasicIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "192.168.1.100:5000"
	SetTrustedProxies(nil)

	key := LoginRateLimitKey(req)
	if key != "login:192.168.1.100" {
		t.Errorf("LoginRateLimitKey = %q, want %q", key, "login:192.168.1.100")
	}
}

func TestLoginRateLimitKeyIPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "[2001:db8::1]:5000"
	SetTrustedProxies(nil)

	key := LoginRateLimitKey(req)
	if key != "login:2001:db8::1" {
		t.Errorf("LoginRateLimitKey = %q, want %q", key, "login:2001:db8::1")
	}
}

func TestLoginRateLimitKeyNoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "10.0.0.1"
	SetTrustedProxies(nil)

	key := LoginRateLimitKey(req)
	if key != "login:10.0.0.1" {
		t.Errorf("LoginRateLimitKey = %q, want %q", key, "login:10.0.0.1")
	}
}

func TestLoginRateLimitKeyDifferentIPsDifferentKeys(t *testing.T) {
	SetTrustedProxies(nil)

	req1 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req1.RemoteAddr = "1.1.1.1:1234"

	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req2.RemoteAddr = "2.2.2.2:1234"

	key1 := LoginRateLimitKey(req1)
	key2 := LoginRateLimitKey(req2)

	if key1 == key2 {
		t.Errorf("different IPs should produce different keys: %q == %q", key1, key2)
	}
}

func TestLoginRateLimitKeySameIPSameKey(t *testing.T) {
	SetTrustedProxies(nil)

	req1 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req1.RemoteAddr = "10.10.10.10:1111"

	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req2.RemoteAddr = "10.10.10.10:2222"

	key1 := LoginRateLimitKey(req1)
	key2 := LoginRateLimitKey(req2)

	if key1 != key2 {
		t.Errorf("same IP different port should produce same key: %q != %q", key1, key2)
	}
}

func TestLoginRateLimitKeyHasPrefix(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "5.5.5.5:9090"
	SetTrustedProxies(nil)

	key := LoginRateLimitKey(req)
	if !strings.HasPrefix(key, "login:") {
		t.Errorf("LoginRateLimitKey should have 'login:' prefix, got %q", key)
	}
}

// ---------------------------------------------------------------------------
// GeneralRateLimitKey tests
// ---------------------------------------------------------------------------

func TestGeneralRateLimitKeyWithClaims(t *testing.T) {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user-uuid-1234",
		},
	}
	ctx := context.WithValue(context.Background(), ClaimsKey, claims)
	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req = req.WithContext(ctx)

	key := GeneralRateLimitKey(req)
	if key != "user:user-uuid-1234" {
		t.Errorf("GeneralRateLimitKey = %q, want %q", key, "user:user-uuid-1234")
	}
}

func TestGeneralRateLimitKeyWithoutClaims(t *testing.T) {
	SetTrustedProxies(nil)
	req := httptest.NewRequest(http.MethodGet, "/public/resource", nil)
	req.RemoteAddr = "203.0.113.50:4321"

	key := GeneralRateLimitKey(req)
	if key != "anon:203.0.113.50" {
		t.Errorf("GeneralRateLimitKey = %q, want %q", key, "anon:203.0.113.50")
	}
}

func TestGeneralRateLimitKeyAnonPrefix(t *testing.T) {
	SetTrustedProxies(nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:5678"

	key := GeneralRateLimitKey(req)
	if !strings.HasPrefix(key, "anon:") {
		t.Errorf("unauthenticated GeneralRateLimitKey should have 'anon:' prefix, got %q", key)
	}
}

func TestGeneralRateLimitKeyUserPrefix(t *testing.T) {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "some-user-id",
		},
	}
	ctx := context.WithValue(context.Background(), ClaimsKey, claims)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	key := GeneralRateLimitKey(req)
	if !strings.HasPrefix(key, "user:") {
		t.Errorf("authenticated GeneralRateLimitKey should have 'user:' prefix, got %q", key)
	}
}

func TestGeneralRateLimitKeyNilClaimsInContext(t *testing.T) {
	// Put a non-claims value in the ClaimsKey
	ctx := context.WithValue(context.Background(), ClaimsKey, "not-a-claims-pointer")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)
	req.RemoteAddr = "10.0.0.5:1234"
	SetTrustedProxies(nil)

	key := GeneralRateLimitKey(req)
	if !strings.HasPrefix(key, "anon:") {
		t.Errorf("wrong type in context should fall back to anon, got %q", key)
	}
}

func TestGeneralRateLimitKeyDifferentUsersDifferentKeys(t *testing.T) {
	makeClaims := func(sub string) context.Context {
		c := &vaultcrypto.VaultClaims{
			RegisteredClaims: vjwt.RegisteredClaims{Subject: sub},
		}
		return context.WithValue(context.Background(), ClaimsKey, c)
	}

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1 = req1.WithContext(makeClaims("user-a"))

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2 = req2.WithContext(makeClaims("user-b"))

	key1 := GeneralRateLimitKey(req1)
	key2 := GeneralRateLimitKey(req2)

	if key1 == key2 {
		t.Errorf("different users should produce different keys: %q == %q", key1, key2)
	}
}

// ---------------------------------------------------------------------------
// IPRateLimitKey tests
// ---------------------------------------------------------------------------

func TestIPRateLimitKeyBasic(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:8080"
	SetTrustedProxies(nil)

	key := IPRateLimitKey(req)
	if key != "ip:172.16.0.1" {
		t.Errorf("IPRateLimitKey = %q, want %q", key, "ip:172.16.0.1")
	}
}

func TestIPRateLimitKeyIPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:8080"
	SetTrustedProxies(nil)

	key := IPRateLimitKey(req)
	if key != "ip:::1" {
		t.Errorf("IPRateLimitKey = %q, want %q", key, "ip:::1")
	}
}

// ---------------------------------------------------------------------------
// ClientIP edge case tests
// ---------------------------------------------------------------------------

func TestClientIPXFFSingleIP(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")

	ip := ClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("ClientIP with single XFF = %q, want %q", ip, "203.0.113.50")
	}
}

func TestClientIPXFFMultipleIPsTakesRightmostUntrusted(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 203.0.113.20, 10.0.0.5")

	ip := ClientIP(req)
	// 10.0.0.5 is trusted, so skip. 203.0.113.20 is first non-trusted from the right.
	if ip != "203.0.113.20" {
		t.Errorf("ClientIP with multi XFF = %q, want %q", ip, "203.0.113.20")
	}
}

func TestClientIPXFFAllTrustedReturnsLeftmost(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.10, 10.0.0.20, 10.0.0.30")

	ip := ClientIP(req)
	// All trusted — falls back to leftmost
	if ip != "10.0.0.10" {
		t.Errorf("ClientIP all-trusted XFF = %q, want %q", ip, "10.0.0.10")
	}
}

func TestClientIPXRealIPNotUsed(t *testing.T) {
	// ClientIP doesn't use X-Real-IP — only XFF. Verify RemoteAddr is used.
	SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("X-Real-Ip", "10.0.0.1")

	ip := ClientIP(req)
	if ip != "192.168.1.1" {
		t.Errorf("ClientIP should ignore X-Real-Ip without trusted proxies, got %q", ip)
	}
}

func TestClientIPRemoteAddrFallback(t *testing.T) {
	SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "100.64.0.1:9999"

	ip := ClientIP(req)
	if ip != "100.64.0.1" {
		t.Errorf("ClientIP fallback = %q, want %q", ip, "100.64.0.1")
	}
}

func TestClientIPEmptyXFF(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "")

	ip := ClientIP(req)
	// Empty XFF with trusted remote → return remoteIP
	if ip != "10.0.0.1" {
		t.Errorf("ClientIP empty XFF = %q, want %q", ip, "10.0.0.1")
	}
}

func TestClientIPIPv6RemoteAddrWithTrustedProxy(t *testing.T) {
	SetTrustedProxies([]string{"::1/128"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:8080"
	req.Header.Set("X-Forwarded-For", "2001:db8::1")

	ip := ClientIP(req)
	if ip != "2001:db8::1" {
		t.Errorf("ClientIP IPv6 trusted proxy = %q, want %q", ip, "2001:db8::1")
	}
}

func TestClientIPIPv6InXFF(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "2001:db8::cafe")

	ip := ClientIP(req)
	if ip != "2001:db8::cafe" {
		t.Errorf("ClientIP IPv6 in XFF = %q, want %q", ip, "2001:db8::cafe")
	}
}

func TestClientIPPortStrippedFromRemoteAddr(t *testing.T) {
	SetTrustedProxies(nil)

	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"IPv4 with port", "1.2.3.4:8080", "1.2.3.4"},
		{"IPv6 with port", "[::1]:8080", "::1"},
		{"IPv4 without port", "1.2.3.4", "1.2.3.4"},
		{"IPv6 without port", "::1", "::1"},
		{"IPv6 full with port", "[2001:db8::1]:443", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			ip := ClientIP(req)
			if ip != tt.want {
				t.Errorf("ClientIP(%q) = %q, want %q", tt.remoteAddr, ip, tt.want)
			}
		})
	}
}

func TestClientIPXFFWithSpaces(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "  203.0.113.50  ,  10.0.0.5  ")

	ip := ClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("ClientIP with spaces in XFF = %q, want %q", ip, "203.0.113.50")
	}
}

func TestClientIPMultipleTrustedProxyCIDRs(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 172.16.0.5, 10.0.0.3")

	ip := ClientIP(req)
	// Walk right-to-left: 10.0.0.3 trusted, 172.16.0.5 trusted, 8.8.8.8 not trusted
	if ip != "8.8.8.8" {
		t.Errorf("ClientIP multi-CIDR = %q, want %q", ip, "8.8.8.8")
	}
}

func TestClientIPTrustedProxySingleBareIP(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.1"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	ip := ClientIP(req)
	if ip != "1.2.3.4" {
		t.Errorf("ClientIP bare IP proxy = %q, want %q", ip, "1.2.3.4")
	}
}

func TestClientIPXFFEmptyEntries(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", ",, 203.0.113.50,,")

	ip := ClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("ClientIP with empty XFF entries = %q, want %q", ip, "203.0.113.50")
	}
}

func TestSetTrustedProxiesOverwrites(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	if len(loadTrustedProxyCIDRs()) != 1 {
		t.Fatalf("expected 1 CIDR, got %d", len(loadTrustedProxyCIDRs()))
	}

	SetTrustedProxies([]string{"192.168.0.0/16", "172.16.0.0/12"})
	if len(loadTrustedProxyCIDRs()) != 2 {
		t.Errorf("expected 2 CIDRs after overwrite, got %d", len(loadTrustedProxyCIDRs()))
	}

	// Verify old CIDR is gone
	if isTrustedProxy("10.0.0.1") {
		t.Error("10.0.0.1 should no longer be trusted after overwrite")
	}

	SetTrustedProxies(nil)
}

func TestSetTrustedProxiesEmpty(t *testing.T) {
	SetTrustedProxies([]string{})
	if len(loadTrustedProxyCIDRs()) != 0 {
		t.Errorf("empty proxies should yield 0 CIDRs, got %d", len(loadTrustedProxyCIDRs()))
	}
}

func TestIsTrustedProxyInvalidIP(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	if isTrustedProxy("not-an-ip") {
		t.Error("invalid IP should not be trusted")
	}
}

func TestIsTrustedProxyEmptyString(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	if isTrustedProxy("") {
		t.Error("empty string should not be trusted")
	}
}

func TestLoginRateLimitKeyWithTrustedProxy(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	key := LoginRateLimitKey(req)
	if key != "login:203.0.113.99" {
		t.Errorf("LoginRateLimitKey via proxy = %q, want %q", key, "login:203.0.113.99")
	}
}

func TestIPRateLimitKeyHasPrefix(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:53"
	SetTrustedProxies(nil)

	key := IPRateLimitKey(req)
	if !strings.HasPrefix(key, "ip:") {
		t.Errorf("IPRateLimitKey should have 'ip:' prefix, got %q", key)
	}
}

func TestGeneralRateLimitKeyEmptySubject(t *testing.T) {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "",
		},
	}
	ctx := context.WithValue(context.Background(), ClaimsKey, claims)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	key := GeneralRateLimitKey(req)
	// Claims exist but subject is empty — still uses "user:" prefix
	if key != "user:" {
		t.Errorf("GeneralRateLimitKey with empty subject = %q, want %q", key, "user:")
	}
}

func TestClientIPNoXFFWhenTrusted(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	// No XFF header at all

	ip := ClientIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("ClientIP trusted but no XFF = %q, want %q", ip, "10.0.0.1")
	}
}
