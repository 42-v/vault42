package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// fingerprintProbe reads the TLS fingerprint the middleware would use for a
// request arriving from the given peer with the given header value.
func fingerprintProbe(remoteAddr, header, value string) string {
	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.RemoteAddr = remoteAddr
	if value != "" {
		req.Header.Set(header, value)
	}
	return TLSFingerprint(req)
}

// TestTLSFingerprintIgnoresAnUntrustedPeer closes the one device signal that was
// not gated on trust.
//
// The TLS fingerprint exists so that tokens can be bound to a device behind a
// shared address, which is the normal case: NAT, or a Helm default with an empty
// trustedProxies where every ingress client hashes as the ingress pod's IP. The
// IP, the User-Agent and the Accept-Language are all things a replaying attacker
// already controls, so the JA4 was the only component actually distinguishing
// two callers on one address.
//
// It was read straight off the request while ClientIP and AppContext both
// require isTrustedProxy first. So an attacker holding a stolen bearer token
// replayed it with the victim's User-Agent and the victim's fingerprint in the
// header, and ComputeFingerprint matched. The check that was supposed to make a
// stolen token useless from a second device was supplied by the second device.
func TestTLSFingerprintIgnoresAnUntrustedPeer(t *testing.T) {
	SetTLSFingerprintHeader("X-TLS-Fingerprint")
	defer SetTLSFingerprintHeader("")
	SetTrustedProxies(nil)

	if got := fingerprintProbe("203.0.113.9:5555", "X-TLS-Fingerprint", "JA4_victim"); got != "" {
		t.Errorf("fingerprint = %q, want empty. An untrusted peer supplied the victim's JA4 and "+
			"it was believed, so the only component distinguishing two callers behind one "+
			"address is set by whichever of them is replaying the token.", got)
	}
}

// TestTLSFingerprintTrustsAProxy is the negative control, and the deployment the
// feature exists for. A terminating proxy the operator has declared is the only
// thing that can know a JA4 at all.
func TestTLSFingerprintTrustsAProxy(t *testing.T) {
	SetTLSFingerprintHeader("X-TLS-Fingerprint")
	defer SetTLSFingerprintHeader("")
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	if got := fingerprintProbe("10.0.0.7:5555", "X-TLS-Fingerprint", "JA4_victim"); got != "JA4_victim" {
		t.Errorf("fingerprint = %q, want JA4_victim: a value from a declared proxy is the signal "+
			"this feature reads, and dropping it disables device binding entirely.", got)
	}
}

// TestTLSFingerprintStaysEmptyWhenDisabled keeps the off switch working. With no
// header configured the feature contributes nothing regardless of the peer, so a
// deployment that never enabled it is unaffected by the trust gate.
func TestTLSFingerprintStaysEmptyWhenDisabled(t *testing.T) {
	SetTLSFingerprintHeader("")
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)

	if got := fingerprintProbe("10.0.0.7:5555", "X-TLS-Fingerprint", "JA4_victim"); got != "" {
		t.Errorf("fingerprint = %q, want empty when no header is configured", got)
	}
}
