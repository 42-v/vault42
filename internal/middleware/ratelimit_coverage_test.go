package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// ---------------------------------------------------------------------------
// LoginRateLimitKey tests
// ---------------------------------------------------------------------------

func TestLoginRateLimitKey(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		xff        string
		want       string
	}{
		{name: "IPv4 peer with a port", remoteAddr: "192.168.1.100:5000", want: "login:192.168.1.100"},
		{name: "IPv6 peer with a port", remoteAddr: "[2001:db8::1]:5000", want: "login:2001:db8::1"},
		{name: "peer without a port", remoteAddr: "10.0.0.1", want: "login:10.0.0.1"},
		{
			name:       "behind a trusted proxy the key is the forwarded client",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.99",
			want:       "login:203.0.113.99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxies(tt.trusted)
			t.Cleanup(func() { SetTrustedProxies(nil) })

			req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			if got := LoginRateLimitKey(req); got != tt.want {
				t.Errorf("LoginRateLimitKey(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
			}
		})
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

// ---------------------------------------------------------------------------
// GeneralRateLimitKey tests
// ---------------------------------------------------------------------------

// A caller with valid claims is bucketed by subject; everyone else is bucketed
// by address. Getting the fallback wrong in either direction is a real fault:
// "user:" for an unauthenticated caller lets anyone pick their own bucket, and
// "anon:" for an authenticated one shares a bucket across every user behind one
// NAT.
func TestGeneralRateLimitKey(t *testing.T) {
	claimsFor := func(sub string) any {
		return &vaultcrypto.VaultClaims{
			RegisteredClaims: vjwt.RegisteredClaims{Subject: sub},
		}
	}

	tests := []struct {
		name string
		// ctxValue is stored under ClaimsKey when non-nil.
		ctxValue   any
		remoteAddr string
		want       string
	}{
		{name: "claims present", ctxValue: claimsFor("user-uuid-1234"), want: "user:user-uuid-1234"},
		{name: "no claims falls back to the address", remoteAddr: "203.0.113.50:4321", want: "anon:203.0.113.50"},
		{
			name:       "a wrongly typed context value falls back to the address",
			ctxValue:   "not-a-claims-pointer",
			remoteAddr: "10.0.0.5:1234",
			want:       "anon:10.0.0.5",
		},
		{
			// Claims with no subject still bucket as a user: the prefix follows the
			// presence of claims, not the content of the subject.
			name:     "claims with an empty subject",
			ctxValue: claimsFor(""),
			want:     "user:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxies(nil)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			if tt.ctxValue != nil {
				req = req.WithContext(context.WithValue(req.Context(), ClaimsKey, tt.ctxValue))
			}

			if got := GeneralRateLimitKey(req); got != tt.want {
				t.Errorf("GeneralRateLimitKey = %q, want %q", got, tt.want)
			}
		})
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

func TestIPRateLimitKey(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{name: "IPv4 peer", remoteAddr: "172.16.0.1:8080", want: "ip:172.16.0.1"},
		{name: "IPv6 peer", remoteAddr: "[::1]:8080", want: "ip:::1"},
		{name: "public IPv4 peer", remoteAddr: "8.8.8.8:53", want: "ip:8.8.8.8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxies(nil)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr

			if got := IPRateLimitKey(req); got != tt.want {
				t.Errorf("IPRateLimitKey(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ClientIP
// ---------------------------------------------------------------------------

// TestClientIP is the one place the address resolution is pinned, because the
// answer becomes the rate-limit bucket key, the account-lockout source and the
// audit ip column. Every row is a distinct header shape rather than a repeat of
// one: the header is attacker-supplied, so "which entry wins" has to be decided
// per shape and not inferred from a couple of happy cases.
//
// The cases used to be twenty-one separate functions spread over three files,
// several of which were the same input written twice.
func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		// headers is a list rather than a map so that "the header is absent" and
		// "the header is present and empty" stay tellable apart.
		headers [][2]string
		want    string
	}{
		{
			name:       "no trusted proxies means XFF is not read at all",
			remoteAddr: "1.2.3.4:1234",
			headers:    [][2]string{{"X-Forwarded-For", "10.0.0.1, 192.168.1.1"}},
			want:       "1.2.3.4",
		},
		{
			name:       "no trusted proxies means X-Real-Ip is not read either",
			remoteAddr: "192.168.1.1:1234",
			headers:    [][2]string{{"X-Real-Ip", "10.0.0.1"}},
			want:       "192.168.1.1",
		},
		{
			name:       "no trusted proxies and no headers falls back to the peer",
			remoteAddr: "100.64.0.1:9999",
			want:       "100.64.0.1",
		},
		{
			name:       "an untrusted peer cannot forge a single hop",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "203.0.113.50:1234",
			headers:    [][2]string{{"X-Forwarded-For", "10.0.0.1"}},
			want:       "203.0.113.50",
		},
		{
			name:       "an untrusted peer cannot forge a whole chain",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "203.0.113.50:1234",
			headers:    [][2]string{{"X-Forwarded-For", "192.168.1.1, 10.0.0.1"}},
			want:       "203.0.113.50",
		},
		{
			name:       "a trusted peer with one XFF entry",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "203.0.113.50"}},
			want:       "203.0.113.50",
		},
		{
			name:       "the rightmost untrusted entry wins, not the leftmost",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "203.0.113.10, 203.0.113.20, 10.0.0.5"}},
			want:       "203.0.113.20",
		},
		{
			name:       "a trailing trusted hop is walked past",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "203.0.113.50, 10.0.0.2"}},
			want:       "203.0.113.50",
		},
		{
			name:       "an all-trusted chain falls back to the leftmost entry",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "10.0.0.10, 10.0.0.20, 10.0.0.30"}},
			want:       "10.0.0.10",
		},
		{
			name:       "a trusted peer sending an empty XFF falls back to the peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", ""}},
			want:       "10.0.0.1",
		},
		{
			name:       "a trusted peer sending no XFF falls back to the peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			want:       "10.0.0.1",
		},
		{
			name:       "an XFF entry that is not an IP is discarded, not returned",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "not-a-valid-ip"}},
			want:       "10.0.0.1",
		},
		{
			name:       "XFF entries padded with spaces are trimmed",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "  203.0.113.50  ,  10.0.0.5  "}},
			want:       "203.0.113.50",
		},
		{
			name:       "empty XFF entries are skipped",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", ",, 203.0.113.50,,"}},
			want:       "203.0.113.50",
		},
		{
			name:       "an IPv6 address in XFF",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "2001:db8::cafe"}},
			want:       "2001:db8::cafe",
		},
		{
			name:       "an IPv6 trusted peer forwarding an IPv6 client",
			trusted:    []string{"::1/128"},
			remoteAddr: "[::1]:8080",
			headers:    [][2]string{{"X-Forwarded-For", "2001:db8::1"}},
			want:       "2001:db8::1",
		},
		{
			name:       "the walk passes over hops from several trusted CIDRs",
			trusted:    []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			remoteAddr: "192.168.1.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "8.8.8.8, 172.16.0.5, 10.0.0.3"}},
			want:       "8.8.8.8",
		},
		{
			name:       "a trusted proxy configured as a bare IP is still trusted",
			trusted:    []string{"10.0.0.1"},
			remoteAddr: "10.0.0.1:1234",
			headers:    [][2]string{{"X-Forwarded-For", "1.2.3.4"}},
			want:       "1.2.3.4",
		},
		{name: "IPv4 peer with a port", remoteAddr: "1.2.3.4:8080", want: "1.2.3.4"},
		{name: "IPv6 peer with a port", remoteAddr: "[::1]:8080", want: "::1"},
		{name: "IPv4 peer without a port", remoteAddr: "1.2.3.4", want: "1.2.3.4"},
		{name: "IPv6 peer without a port", remoteAddr: "::1", want: "::1"},
		{name: "full IPv6 peer with a port", remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "an empty RemoteAddr resolves to nothing", remoteAddr: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxies(tt.trusted)
			t.Cleanup(func() { SetTrustedProxies(nil) })

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for _, h := range tt.headers {
				req.Header.Set(h[0], h[1])
			}

			if got := ClientIP(req); got != tt.want {
				t.Errorf("ClientIP(RemoteAddr=%q, headers=%v) = %q, want %q",
					tt.remoteAddr, tt.headers, got, tt.want)
			}
		})
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
