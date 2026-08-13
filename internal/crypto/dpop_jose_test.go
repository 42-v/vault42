package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

// TestValidateDPoPProofRejectsACritHeader closes the DPoP half of the gap
// TestCritHeaderIsRejected closed for access tokens.
//
// RFC 7515 4.1.11 makes crit a MUST-reject for any recipient that does not
// implement every extension it lists, and vault42 implements no JOSE extension
// at all. ParseAndValidate refuses it; ValidateDPoPProof did not, and its
// Keyfunc is a bare `return pubKey, nil` that performs none of the header
// checks the jwt package's own doc comment says live there.
//
// The DPoP path is the reachable one of the two. An access token's header sits
// inside a signature made with vault42's signing key, so planting a crit there
// needs the key. A DPoP proof is self-signed with a key the caller invents in
// the same request, so every byte of its header, crit included, is chosen by
// whoever sends the request. The harm is the one the access-token fix names: a
// gateway or relying party that honors crit refuses a proof vault42 called
// valid, and the two stop agreeing on what a valid proof is.
//
// The empty array is included for the same reason it is there: RFC 7515
// forbids it outright, and it is the case a "nothing is listed, so nothing is
// required" reading waves through.
func TestValidateDPoPProofRejectsACritHeader(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	for _, tc := range []struct {
		name string
		crit any
	}{
		{"unknown extension", []string{"nonce-ext"}},
		{"several unknown extensions", []string{"a", "b"}},
		{"empty array, forbidden by the RFC", []string{}},
		{"naming a header vault42 does understand", []string{"jwk"}},
		{"not an array at all", "nonce-ext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := createDPoPProof(t, key, "POST", "https://vault.test/auth/token",
				func(header map[string]any, _ *DPoPClaims) {
					header["crit"] = tc.crit
				})

			thumbprint, jti, err := ValidateDPoPProof(proof, "POST", "https://vault.test/auth/token", "")
			if err == nil {
				t.Fatalf("a DPoP proof carrying a crit header was accepted (thumbprint %q, jti %q). "+
					"RFC 7515 4.1.11 requires refusing a crit the recipient does not implement, and "+
					"vault42 implements no JOSE extensions, so a verifier that honors crit would "+
					"refuse a proof this vault called valid.", thumbprint, jti)
			}
			if !strings.Contains(err.Error(), "crit") {
				t.Errorf("the rejection did not come from the crit check, so this test is not "+
					"measuring what it claims: %v", err)
			}
		})
	}
}

// TestValidateDPoPProofStillAcceptsAProofWithoutCrit is the negative control
// for the check above: a header rejection that fires on every proof would pass
// that test and break every DPoP client.
func TestValidateDPoPProofStillAcceptsAProofWithoutCrit(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	proof := createDPoPProof(t, key, "POST", "https://vault.test/auth/token")

	thumbprint, jti, err := ValidateDPoPProof(proof, "POST", "https://vault.test/auth/token", "")
	if err != nil {
		t.Fatalf("an ordinary DPoP proof was rejected: %v", err)
	}
	if thumbprint == "" || jti == "" {
		t.Errorf("thumbprint = %q, jti = %q, want both non-empty", thumbprint, jti)
	}
}
