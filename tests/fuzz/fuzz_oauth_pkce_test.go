package fuzz

import (
	"encoding/base64"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/sanitize"
)

// FuzzPKCEChallenge covers the S256 challenge construction used on every
// outbound authorize URL (RFC 7636). The verifier is server-generated hex
// today, but the hash function is also the DPoP ath constructor and must
// stay total over arbitrary input.
func FuzzPKCEChallenge(f *testing.F) {
	f.Add("")
	f.Add("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	f.Add(strings.Repeat("a", 43))
	f.Add(strings.Repeat("a", 128))
	f.Add("not valid base64url!!!")
	f.Add("\x00\x01\xff")
	f.Add(strings.Repeat("0", 64)) // RandomHex(32) shape

	f.Fuzz(func(t *testing.T, verifier string) {
		challenge := vaultcrypto.SHA256Base64URL(verifier)
		if len(challenge) != 43 {
			t.Fatalf("S256 challenge length = %d, want 43 (32-byte SHA-256, unpadded base64url)", len(challenge))
		}
		if _, err := base64.RawURLEncoding.DecodeString(challenge); err != nil {
			t.Fatalf("challenge %q is not valid unpadded base64url: %v", challenge, err)
		}
		if again := vaultcrypto.SHA256Base64URL(verifier); again != challenge {
			t.Fatalf("SHA256Base64URL is not deterministic: %q vs %q", challenge, again)
		}
	})
}

// FuzzOAuthStateHMAC is the signed-state parser used on the OAuth2 callback.
// A random string must never verify as an HMAC; a correctly signed payload
// must. The parse of the payload (provider.nonce.expiry.csrfHash) must not
// panic on any input that survived the HMAC.
func FuzzOAuthStateHMAC(f *testing.F) {
	secret := []byte("fuzz-oauth-state-secret-32-bytes!!")
	validPayload := "github.deadbeef.9999999999." + vaultcrypto.SHA256Hex("csrf")
	f.Add(validPayload + "." + vaultcrypto.HMACSign([]byte(validPayload), secret))
	f.Add("")
	f.Add("no-dots")
	f.Add("a.b.c.d.e")
	f.Add("github.nonce.notanumber.hash.sig")
	f.Add("\x00.\x01.\x02.\x03.\x04")
	f.Add(strings.Repeat(".", 64))

	f.Fuzz(func(t *testing.T, state string) {
		lastDot := strings.LastIndex(state, ".")
		if lastDot < 0 {
			if vaultcrypto.HMACVerify([]byte(state), secret, "") && state != "" {
				t.Fatal("HMACVerify accepted an empty signature over a non-empty message")
			}
			return
		}
		payload := state[:lastDot]
		sig := state[lastDot+1:]
		ok := vaultcrypto.HMACVerify([]byte(payload), secret, sig)
		if ok != vaultcrypto.SecureCompare(vaultcrypto.HMACSign([]byte(payload), secret), sig) {
			t.Fatal("HMACVerify disagreed with HMACSign+SecureCompare")
		}
		if !ok {
			return
		}
		// A verified payload is split the way Callback does. This must not
		// panic; a verified-but-malformed payload is invalid_state, not a crash.
		parts := strings.SplitN(payload, ".", 4)
		if len(parts) != 4 {
			return
		}
		_ = parts[0]
		_ = parts[1]
		_ = parts[2]
		_ = parts[3]
	})
}

// FuzzOAuthRedirectPath is the post-auth redirect sanitiser (same-origin
// relative path). The authorize-URL check lives next to the handler because
// it is unexported; this covers the exported half of "redirect_uri parsing".
func FuzzOAuthRedirectPath(f *testing.F) {
	f.Add("/dashboard")
	f.Add("//evil.com")
	f.Add("/..//evil.com")
	f.Add("https://example.com")

	f.Fuzz(func(t *testing.T, path string) {
		got := sanitize.RedirectPath(path)
		if got != "" && got != path {
			t.Fatalf("RedirectPath rewrote %q to %q", path, got)
		}
		if got != "" && (!strings.HasPrefix(got, "/") || strings.HasPrefix(got, "//")) {
			t.Fatalf("accepted off-origin path %q", got)
		}
	})
}
