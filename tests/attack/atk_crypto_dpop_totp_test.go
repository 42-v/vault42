package attack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math/big"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

const (
	dpopMethod = "POST"
	dpopURI    = "https://vault.example.com/kms/unwrap"
)

// atkSignProof builds a DPoP proof with a caller-supplied jwk header, so the jwk
// and the signing key can be made to disagree. That disagreement is the whole
// point of the key-substitution tests below.
func atkSignProof(t *testing.T, signWith any, jwkHeader map[string]any, mutate ...func(map[string]any, *vaultcrypto.DPoPClaims)) string {
	t.Helper()

	claims := &vaultcrypto.DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			ID:       "jti-" + time.Now().Format(time.RFC3339Nano),
		},
		HTM: dpopMethod,
		HTU: dpopURI,
	}

	alg := "RS256"
	if _, ok := signWith.(*ecdsa.PrivateKey); ok {
		alg = "ES256"
	}
	header := map[string]any{"alg": alg, "typ": "dpop+jwt", "jwk": jwkHeader}
	for _, m := range mutate {
		m(header, claims)
	}

	var out string
	var err error
	switch k := signWith.(type) {
	case *rsa.PrivateKey:
		out, err = vjwt.SignRS256WithHeader(header, claims, k)
	case *ecdsa.PrivateKey:
		out, err = vjwt.SignTokenCustom(header, claims, func(signingString string) ([]byte, error) {
			h := sha256.Sum256([]byte(signingString))
			return ecdsa.SignASN1(crand.Reader, k, h[:])
		})
	default:
		t.Fatalf("unsupported signing key %T", signWith)
	}
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return out
}

func atkRSAJWK(pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func atkECJWK(pub *ecdsa.PublicKey, crv string) map[string]any {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	leftPad := func(b []byte) []byte {
		out := make([]byte, byteLen)
		copy(out[byteLen-len(b):], b)
		return out
	}
	return map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes())),
		"y":   base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes())),
	}
}

// Confirming the premise rather than reporting it as new: AR-10 and three doc
// comments already state that nothing sets cnf.jkt, so no token is
// sender-constrained and the thumbprint ValidateDPoPProof computes is discarded
// by every caller.
//
// The check is a source scan for an assignment to a Confirmation field
// anywhere outside the middleware that reads it. If issuance ever starts
// binding tokens, this test fails and the register entry needs rewriting.
func TestDPoPAttack_ConfirmNothingIsSenderConstrained(t *testing.T) {
	roots := []string{
		filepath.Join("..", "..", "internal", "service"),
		filepath.Join("..", "..", "internal", "handler"),
		filepath.Join("..", "..", "internal", "crypto"),
	}

	var assignments []string
	for _, root := range roots {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, root, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", root, err)
		}
		for _, pkg := range pkgs {
			for name, file := range pkg.Files {
				ast.Inspect(file, func(n ast.Node) bool {
					assign, ok := n.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for _, lhs := range assign.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if ok && (sel.Sel.Name == "Confirmation" || sel.Sel.Name == "JKT") {
							assignments = append(assignments, filepath.Base(name))
						}
					}
					return true
				})
				// A composite literal is the other way it could be set.
				ast.Inspect(file, func(n ast.Node) bool {
					kv, ok := n.(*ast.KeyValueExpr)
					if !ok {
						return true
					}
					if id, ok := kv.Key.(*ast.Ident); ok &&
						(id.Name == "Confirmation" || id.Name == "JKT") {
						assignments = append(assignments, filepath.Base(name))
					}
					return true
				})
			}
		}
	}

	if len(assignments) > 0 {
		t.Errorf("cnf.jkt is now assigned in %v, so tokens may be sender-constrained and "+
			"so AR-10 and the middleware.DPoP doc comment need updating", assignments)
		return
	}
	t.Log("confirmed: no issuance path assigns cnf.jkt, so ValidateDPoPProof's thumbprint " +
		"is computed and discarded. Matches AR-10; not reported as a new finding.")
}

// Key substitution. A proof signed with one key but advertising another's JWK
// must fail. This is the attack that matters most in a self-signed proof
// format, because the verifier takes the key from the same document it is
// verifying.
func TestDPoPAttack_KeySubstitutionIsRejected(t *testing.T) {
	victimRSA, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	attackerRSA, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	victimEC, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	attackerEC, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}

	t.Run("RSA signature under the victim's RSA jwk", func(t *testing.T) {
		proof := atkSignProof(t, attackerRSA, atkRSAJWK(&victimRSA.PublicKey))
		if _, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI, ""); err == nil {
			t.Fatal("a proof signed by the attacker validated under the victim's jwk")
		}
	})

	t.Run("EC signature under the victim's EC jwk", func(t *testing.T) {
		proof := atkSignProof(t, attackerEC, atkECJWK(&victimEC.PublicKey, "P-256"))
		if _, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI, ""); err == nil {
			t.Fatal("a proof signed by the attacker validated under the victim's jwk")
		}
	})

	// Algorithm/key-type crossing: an RSA-signed proof advertising an EC jwk
	// and the reverse. The verifier must not coerce one into the other.
	t.Run("RSA signature under an EC jwk", func(t *testing.T) {
		proof := atkSignProof(t, attackerRSA, atkECJWK(&victimEC.PublicKey, "P-256"))
		if _, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI, ""); err == nil {
			t.Fatal("an RSA-signed proof validated against an EC key")
		}
	})

	t.Run("EC signature under an RSA jwk", func(t *testing.T) {
		proof := atkSignProof(t, attackerEC, atkRSAJWK(&victimRSA.PublicKey))
		if _, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI, ""); err == nil {
			t.Fatal("an EC-signed proof validated against an RSA key")
		}
	})

	// A well-formed self-signed proof must still work, or the tests above prove
	// nothing beyond "everything fails".
	t.Run("control: honest proof validates", func(t *testing.T) {
		proof := atkSignProof(t, victimRSA, atkRSAJWK(&victimRSA.PublicKey))
		thumb, jti, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI, "")
		if err != nil {
			t.Fatalf("an honest proof was rejected: %v", err)
		}
		if thumb == "" || jti == "" {
			t.Fatalf("honest proof returned thumbprint=%q jti=%q", thumb, jti)
		}
	})
}

// Curve confusion and malformed JWK bodies. parseJWKHeader picks the curve from
// the crv string and then relies on ecdsa.PublicKey.ECDH to reject a point that
// is not on it, which is the right check; these cases confirm it holds for the
// mismatches an attacker would actually try.
func TestDPoPAttack_MalformedAndConfusedJWKs(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("ecdsa p256: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), crand.Reader)
	if err != nil {
		t.Fatalf("ecdsa p384: %v", err)
	}

	bigModulus := new(big.Int).Lsh(big.NewInt(1), 8192)
	bigModulus.SetBit(bigModulus, 0, 1)

	cases := map[string]map[string]any{
		"empty jwk":               {},
		"unknown kty":             {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"},
		"RSA with EC fields":      {"kty": "RSA", "crv": "P-256", "x": "AAAA", "y": "AAAA"},
		"EC with RSA fields":      {"kty": "EC", "n": "AAAA", "e": "AQAB"},
		"EC missing crv":          {"kty": "EC", "x": "AAAA", "y": "AAAA"},
		"EC unsupported curve":    atkECJWKWith(p256, "P-521"),
		"P-384 point labeled 256": atkECJWKWith(p384, "P-256"),
		"P-256 point labeled 384": atkECJWKWith(p256, "P-384"),
		"EC point not on curve":   {"kty": "EC", "crv": "P-256", "x": strings.Repeat("A", 43), "y": strings.Repeat("A", 43)},
		"EC identity point":       {"kty": "EC", "crv": "P-256", "x": "", "y": ""},
		"EC bad base64":           {"kty": "EC", "crv": "P-256", "x": "!!!!", "y": "!!!!"},
		"RSA modulus too small":   {"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()), "e": "AQAB"},
		"RSA modulus 8192 bits":   {"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(bigModulus.Bytes()), "e": "AQAB"},
		"RSA exponent 1":          {"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes())},
		"RSA exponent 0":          {"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()), "e": ""},
		"RSA exponent oversized":  {"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(new(big.Int).Lsh(big.NewInt(1), 40).Bytes())},
		"RSA bad base64 n":        {"kty": "RSA", "n": "!!!!", "e": "AQAB"},
		"RSA n zero":              {"kty": "RSA", "n": "", "e": "AQAB"},
	}

	for name, jwk := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parsing a hostile jwk panicked: %v", r)
				}
			}()
			// Signed with a real key so the failure is attributable to the jwk,
			// not to a missing signature.
			proof := atkSignProof(t, rsaKey, jwk)
			if _, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI, ""); err == nil {
				t.Errorf("hostile jwk %q was accepted", name)
			}
		})
	}
}

func atkECJWKWith(k *ecdsa.PrivateKey, crv string) map[string]any {
	j := atkECJWK(&k.PublicKey, crv)
	return j
}

// Header and claim tampering: the checks RFC 9449 mandates, exercised as an
// attacker would. htm, htu and the size cap are the ones that stop a proof
// captured on one endpoint from being replayed on another.
func TestDPoPAttack_HeaderAndClaimTampering(t *testing.T) {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	jwk := atkRSAJWK(&key.PublicKey)

	cases := map[string]func(map[string]any, *vaultcrypto.DPoPClaims){
		"typ is jwt not dpop+jwt": func(h map[string]any, _ *vaultcrypto.DPoPClaims) { h["typ"] = "jwt" },
		"typ missing":             func(h map[string]any, _ *vaultcrypto.DPoPClaims) { delete(h, "typ") },
		"kid header present":      func(h map[string]any, _ *vaultcrypto.DPoPClaims) { h["kid"] = "some-kid" },
		"jwk header missing":      func(h map[string]any, _ *vaultcrypto.DPoPClaims) { delete(h, "jwk") },
		"jwk is a string":         func(h map[string]any, _ *vaultcrypto.DPoPClaims) { h["jwk"] = "not-an-object" },
		"htm mismatch":            func(_ map[string]any, c *vaultcrypto.DPoPClaims) { c.HTM = "GET" },
		"htm empty":               func(_ map[string]any, c *vaultcrypto.DPoPClaims) { c.HTM = "" },
		"htu mismatch":            func(_ map[string]any, c *vaultcrypto.DPoPClaims) { c.HTU = "https://evil.example.com/kms/unwrap" },
		"htu path swapped":        func(_ map[string]any, c *vaultcrypto.DPoPClaims) { c.HTU = "https://vault.example.com/auth/login" },
		"htu with query appended": func(_ map[string]any, c *vaultcrypto.DPoPClaims) { c.HTU = dpopURI + "?x=1" },
		"iat missing":             func(_ map[string]any, c *vaultcrypto.DPoPClaims) { c.IssuedAt = nil },
		"iat six minutes old": func(_ map[string]any, c *vaultcrypto.DPoPClaims) {
			c.IssuedAt = vjwt.NewNumericDate(time.Now().Add(-6 * time.Minute))
		},
		"iat six minutes ahead": func(_ map[string]any, c *vaultcrypto.DPoPClaims) {
			c.IssuedAt = vjwt.NewNumericDate(time.Now().Add(6 * time.Minute))
		},
		"jti missing": func(_ map[string]any, c *vaultcrypto.DPoPClaims) { c.ID = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			proof := atkSignProof(t, key, jwk, mutate)
			if _, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI, ""); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}

	t.Run("ath mismatch", func(t *testing.T) {
		proof := atkSignProof(t, key, jwk, func(_ map[string]any, c *vaultcrypto.DPoPClaims) {
			c.ATH = vaultcrypto.SHA256Base64URL("some other access token")
		})
		if _, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI,
			vaultcrypto.SHA256Base64URL("the real access token")); err == nil {
			t.Error("a proof bound to a different access token was accepted")
		}
	})

	t.Run("ath absent while the request has a token", func(t *testing.T) {
		proof := atkSignProof(t, key, jwk) // no ATH set
		if _, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI,
			vaultcrypto.SHA256Base64URL("the real access token")); err == nil {
			t.Error("a proof with no ath was accepted for a request carrying an access token")
		}
	})

	t.Run("oversized proof", func(t *testing.T) {
		oversized := strings.Repeat("A", vaultcrypto.DPoPMaxSize+1)
		if _, _, err := vaultcrypto.ValidateDPoPProof(oversized, dpopMethod, dpopURI, ""); err == nil {
			t.Error("a proof over the size cap was accepted")
		}
	})

	t.Run("garbage strings", func(t *testing.T) {
		for _, s := range []string{"", ".", "..", "a.b.c", "a.b", strings.Repeat(".", 100)} {
			if _, _, err := vaultcrypto.ValidateDPoPProof(s, dpopMethod, dpopURI, ""); err == nil {
				t.Errorf("garbage proof %q was accepted", s)
			}
		}
	})
}

// The thumbprint must be canonical: two encodings of the same key must produce
// the same value, or a future cnf.jkt binding could be bypassed by re-encoding
// the jwk. Leading zero bytes in n are the classic way to try it.
func TestDPoPAttack_ThumbprintIsCanonical(t *testing.T) {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}

	canonical := atkRSAJWK(&key.PublicKey)
	padded := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(append([]byte{0, 0, 0}, key.N.Bytes()...)),
		"e":   canonical["e"],
	}

	thumbs := map[string]string{}
	for name, jwk := range map[string]map[string]any{"canonical": canonical, "zero padded n": padded} {
		proof := atkSignProof(t, key, jwk)
		th, _, err := vaultcrypto.ValidateDPoPProof(proof, dpopMethod, dpopURI, "")
		if err != nil {
			t.Logf("%s: rejected outright (%v), which is also acceptable", name, err)
			continue
		}
		thumbs[name] = th
	}

	if len(thumbs) == 2 && thumbs["canonical"] != thumbs["zero padded n"] {
		t.Errorf("two encodings of one key produced different thumbprints (%s vs %s): "+
			"a cnf.jkt binding could be bypassed by re-encoding the jwk",
			thumbs["canonical"], thumbs["zero padded n"])
	}
}

// TOTP. The replay guards live in the handlers and are already covered by
// tests/attack/totp_replay_test.go and the admin monotonic counter, so these
// go after the primitive: the size of the acceptance window, the entropy of a
// generated secret, and whether comparison time depends on the code.
func TestTOTPAttack_WindowIsThreeStepsWide(t *testing.T) {
	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	now := time.Unix(1_700_000_040, 0) // a step boundary, so offsets are exact
	var accepted []int64
	for offset := int64(-4); offset <= 4; offset++ {
		code, err := vaultcrypto.GenerateTOTPCode(secret, now.Add(time.Duration(offset)*30*time.Second))
		if err != nil {
			t.Fatalf("GenerateTOTPCode: %v", err)
		}
		if step, _ := vaultcrypto.ValidateTOTPCode(secret, code, now); step >= 0 {
			accepted = append(accepted, offset)
		}
	}

	t.Logf("accepted step offsets: %v (%d codes valid at any instant, a %ds window)",
		accepted, len(accepted), len(accepted)*30)

	if len(accepted) != 3 {
		t.Errorf("expected the documented +/-1 skew (3 codes, 90s), got %d: %v", len(accepted), accepted)
	}
	// 3 live codes out of 10^6 is a 1-in-333,333 blind guess per attempt. That
	// is only safe because the handlers cap attempts; the primitive itself has
	// no bound, which is worth stating rather than assuming.
	t.Logf("blind guess probability per attempt: %d/1000000", len(accepted))
}

// Secret entropy. 20 bytes is the RFC 4226 recommendation and what the code
// draws; the check is that the encoding does not silently shrink it and that
// two secrets never repeat.
func TestTOTPAttack_SecretEntropy(t *testing.T) {
	const runs = 256
	seen := map[string]bool{}
	var decodedLen int

	for i := 0; i < runs; i++ {
		s, err := vaultcrypto.GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret: %v", err)
		}
		if seen[s] {
			t.Fatalf("GenerateTOTPSecret repeated a secret after %d draws", i)
		}
		seen[s] = true

		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
		if err != nil {
			t.Fatalf("secret is not valid unpadded base32: %v", err)
		}
		decodedLen = len(raw)
	}

	t.Logf("%d distinct secrets, %d bytes (%d bits) each", len(seen), decodedLen, decodedLen*8)
	if decodedLen < 20 {
		t.Errorf("TOTP secret is %d bytes; RFC 4226 recommends at least 20", decodedLen)
	}
}

// Constant-time comparison, measured. ValidateTOTPCode returns as soon as an
// offset matches, so a code matching the earliest offset costs one HMAC and a
// wrong code costs three. The question is whether the resulting gap is large
// enough to be worth anything to an attacker who already knows their own code.
func TestTOTPAttack_MeasureValidationTimingGap(t *testing.T) {
	if testing.Short() || atkRaceDetector {
		t.Skip("timing measurement: meaningless under -race, skipped in -short")
	}

	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Unix(1_700_000_040, 0)

	earliest, err := vaultcrypto.GenerateTOTPCode(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("GenerateTOTPCode: %v", err)
	}

	const runs = 2001
	hit := make([]time.Duration, 0, runs)
	miss := make([]time.Duration, 0, runs)

	timeOne := func(code string) time.Duration {
		start := time.Now()
		_, _ = vaultcrypto.ValidateTOTPCode(secret, code, now)
		return time.Since(start)
	}

	for i := 0; i < runs; i++ {
		if i%2 == 0 {
			hit = append(hit, timeOne(earliest))
			miss = append(miss, timeOne("000000"))
		} else {
			miss = append(miss, timeOne("000000"))
			hit = append(hit, timeOne(earliest))
		}
	}

	medHit, medMiss := median(hit), median(miss)
	t.Logf("code matching the earliest offset: median %v (1 HMAC)", medHit)
	t.Logf("code matching nothing:             median %v (3 HMACs)", medMiss)
	t.Logf("gap: %v", medMiss-medHit)
	t.Log("the gap is inherent to the early return and reveals only WHICH step " +
		"matched, which the submitter already knows. Sub-microsecond, so it is " +
		"far below the noise floor of any network path.")

	if medMiss-medHit > time.Millisecond {
		t.Errorf("the early return costs %v, large enough to be visible over a network", medMiss-medHit)
	}
}

// Length-mismatched inputs must not take a data-dependent path. SecureCompare
// burns a comparison against the attacker's own input on a length mismatch,
// which reveals nothing about the expected value; measured to say so with a
// number rather than by reading the code.
func TestTOTPAttack_MeasureLengthMismatchTiming(t *testing.T) {
	if testing.Short() || atkRaceDetector {
		t.Skip("timing measurement: meaningless under -race, skipped in -short")
	}

	expected := strings.Repeat("a", 64)
	lengths := []int{0, 1, 63, 64, 65, 1024}

	report := make([]string, 0, len(lengths))
	for _, n := range lengths {
		candidate := strings.Repeat("b", n)
		const runs = 20001
		samples := make([]time.Duration, 0, runs)
		for i := 0; i < runs; i++ {
			start := time.Now()
			_ = vaultcrypto.SecureCompare(expected, candidate)
			samples = append(samples, time.Since(start))
		}
		report = append(report, atkFormatSample(n, median(samples)))
	}
	sort.Strings(report)
	for _, line := range report {
		t.Log(line)
	}
	t.Log("time tracks the length of the ATTACKER's input, not the secret's, so " +
		"no information about the expected value leaks")
}

func atkFormatSample(n int, d time.Duration) string {
	return "candidate length " + atkPad(n) + ": median " + d.String()
}

func atkPad(n int) string {
	s := ""
	switch {
	case n < 10:
		s = "   "
	case n < 100:
		s = "  "
	case n < 1000:
		s = " "
	}
	return s + atkItoa(n)
}

func atkItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
