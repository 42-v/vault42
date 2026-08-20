package middleware

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/dpop"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// FuzzDPoPProofBinding fuzzes the DPoP middleware against the sentence the
// middleware exists to hold rather than against a list of verdicts:
//
//	if a request carrying a DPoP proof reaches the next handler, then the proof
//	was signed by the key its own jwk header presented, the thumbprint planted
//	on the context is the RFC 7638 thumbprint of exactly that key, the proof
//	commits to this method, this URI and this access token, and a token that
//	was sender-constrained was presented under the DPoP scheme with a proof
//	over the key it was constrained to.
//
// A refusal is always a correct answer and can never fail this target. Only the
// accept path is asserted on: a target that asserts a refusal re-checks nothing
// but the inputs somebody already thought of, and the input that matters here is
// the one nobody thought of and the middleware LET THROUGH. A panic fails on
// either path, because this middleware runs on the token endpoint, where the
// proof is the only credential and the request is otherwise unauthenticated.
//
// The whole proof is attacker-chosen at no cost, which is what makes this worth
// fuzzing at all. A DPoP proof is self-signed with a key its sender invents in
// the same request, so unlike an access token there is no signing key standing
// between an attacker and every byte of the header and the payload.
func FuzzDPoPProofBinding(f *testing.F) {
	// The middleware logs every refusal, and a fuzz worker runs millions of
	// them. Left on stderr the log would be the slowest thing in the loop and
	// would bury the failure message when one finally arrives.
	log.SetOutput(io.Discard)
	f.Cleanup(func() { log.SetOutput(os.Stderr) })

	kr := newFuzzDPoPKeyring(f)
	addFuzzDPoPSeeds(f)

	f.Fuzz(func(t *testing.T, headerExtra, claimsExtra []byte, authRaw string, sel uint8, post bool) {
		shape := newFuzzDPoPShape(kr, authRaw, sel, post)
		proof, header, claims, ok := kr.buildProof(shape, headerExtra, claimsExtra)
		if !ok {
			return
		}

		replay := newFuzzReplayCache()
		var reached bool
		var seenThumbprint string
		handler := DPoP(replay, fuzzDPoPOrigin)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reached = true
			seenThumbprint = dpop.Thumbprint(r.Context())
		}))

		handler.ServeHTTP(httptest.NewRecorder(), shape.request(proof))
		if !reached {
			return
		}

		// From here on the middleware has already decided to let the request
		// through, so everything below is a statement about what that decision
		// implies.

		signedHeader, okHeader := fuzzDPoPMembers(header)
		signedClaims, okClaims := fuzzDPoPMembers(claims)
		if !okHeader || !okClaims {
			t.Fatalf("proof was accepted but this target cannot decode it: header=%s claims=%s", header, claims)
		}

		presented, hasJWK := signedHeader["jwk"].(map[string]any)
		if !hasJWK {
			t.Fatalf("proof was accepted with no jwk object in its header: %s", header)
		}
		for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, private := presented[member]; private {
				t.Fatalf("proof was accepted with private key material (%q) in its jwk header, so a client that leaked its key got a 200 instead of a refusal: %s",
					member, header)
			}
		}

		// RFC 9449 4.2 puts the proof's key in the jwk header, so a kid names a
		// key from a set the recipient already holds, and RFC 7515 4.1.11 makes
		// any crit a MUST-reject for a recipient implementing no JOSE extension.
		// Both refusals live in one helper in internal/crypto, and this is the
		// only place that proves the helper is actually on the request path.
		if _, ok := signedHeader["kid"]; ok {
			t.Fatalf("proof was accepted carrying a kid header: %s", header)
		}
		if _, ok := signedHeader["crit"]; ok {
			t.Fatalf("proof was accepted carrying a crit header: %s", header)
		}
		if typ, _ := signedHeader["typ"].(string); typ != "dpop+jwt" {
			t.Fatalf("proof was accepted with typ %q, so an access token could be replayed into this position: %s", typ, header)
		}

		alg, _ := signedHeader["alg"].(string)
		kty, _ := presented["kty"].(string)
		if (alg == "ES256") != (kty == "EC") || (alg == "RS256") != (kty == "RSA") {
			t.Fatalf("proof was accepted with alg %q over a %q key: %s", alg, kty, header)
		}

		// The binding itself. If the thumbprint on the context is not the
		// thumbprint of the key that signed the proof, then every token issued
		// against it is constrained to a key nobody demonstrated possession of,
		// which is the entire control failing open while still looking enabled.
		if seenThumbprint == "" {
			t.Fatalf("proof was accepted but no thumbprint reached the handler, so issuance downstream would mint an unbound token: %s", header)
		}
		want, err := fuzzDPoPThumbprint(presented)
		if err != nil {
			t.Fatalf("proof was accepted with a jwk this target cannot thumbprint: %v (%s)", err, header)
		}
		if seenThumbprint != want {
			t.Fatalf("thumbprint on the context is %q but the presented key thumbprints to %q: %s", seenThumbprint, want, header)
		}

		if err := fuzzDPoPVerifySignature(proof, presented); err != nil {
			t.Fatalf("proof was accepted but does not verify against the key it presented: %v (%s)", err, proof)
		}

		if htm, _ := signedClaims["htm"].(string); htm != shape.method {
			t.Fatalf("proof committing to htm %q was accepted on a %s request, so one proof would authorize a different call: %s",
				htm, shape.method, claims)
		}
		if htu, _ := signedClaims["htu"].(string); htu != fuzzDPoPOrigin+shape.path {
			t.Fatalf("proof committing to htu %q was accepted on %q, so one proof would authorize a different endpoint: %s",
				htu, fuzzDPoPOrigin+shape.path, claims)
		}
		if jti, _ := signedClaims["jti"].(string); jti == "" {
			t.Fatalf("proof with no jti was accepted, so the replay cache had nothing to key on: %s", claims)
		}

		// RFC 9449 4.2: ath binds the proof to the access token presented
		// alongside it. The expected value is derived here from the raw header
		// rather than from the middleware's own split, so the day the two
		// middlewares stop agreeing about where the credential starts, this
		// fails: internal/middleware/auth.go validates parts[1] and this file
		// hashes it, and a proof that covers a different string than the one
		// that was validated binds nothing.
		if credential, ok := fuzzDPoPCredential(shape.authHeader); ok {
			ath, _ := signedClaims["ath"].(string)
			if ath != vaultcrypto.SHA256Base64URL(credential) {
				t.Fatalf("proof with ath %q was accepted alongside a credential hashing to %q: %s",
					ath, vaultcrypto.SHA256Base64URL(credential), claims)
			}
		}

		// RFC 9449 7.1: a sender-constrained token is presented under the DPoP
		// scheme with a proof over the key named in its cnf.jkt. Accepting it
		// under Bearer would let a resource server that reads only the scheme
		// treat a bound token as an ordinary one, and accepting a mismatched
		// thumbprint would make the constraint decorative.
		if shape.boundJKT != "" {
			scheme, _, _ := strings.Cut(shape.authHeader, " ")
			if scheme != "DPoP" {
				t.Fatalf("a token bound to %q was accepted under the %q scheme", shape.boundJKT, scheme)
			}
			if !vaultcrypto.SecureCompare(shape.boundJKT, seenThumbprint) {
				t.Fatalf("a token bound to %q was accepted with a proof over the key thumbprinting to %q", shape.boundJKT, seenThumbprint)
			}
		}

		// Replay prevention is the control, not a nicety, on the two arms where
		// the middleware writes the jti down: a token endpoint request, which is
		// about to mint a binding, and a bound token, where the proof is what
		// stands between a captured request and a second use of it. Replaying
		// the identical request must be refused.
		if shape.claims == nil || shape.boundJKT != "" {
			reached = false
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, shape.request(proof))
			if reached {
				t.Fatalf("the same proof was accepted twice (status %d), so a captured request can be replayed for as long as the proof stays fresh: %s",
					rec.Code, claims)
			}
		}
	})
}

const (
	fuzzDPoPOrigin    = "https://vault.test"
	fuzzDPoPTokenPath = "/auth/login"
	fuzzDPoPUserPath  = "/user/profile"
	// fuzzDPoPCredential below splits this the way internal/middleware/auth.go
	// does, and the access token value itself is arbitrary: the middleware never
	// parses it, it only hashes it for the ath comparison.
	fuzzDPoPAccessToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.notasignature"
)

// fuzzDPoPKeyring holds the keys a proof can be signed with.
//
// They are generated once per target rather than once per input for the same
// reason the verifier targets do it: an RSA keygen per execution would cap the
// campaign at a few hundred inputs. ecOther exists so a bound token can be
// pointed at a key the proof does not present, which is the only way the
// thumbprint comparison is exercised at all.
type fuzzDPoPKeyring struct {
	ec      *ecdsa.PrivateKey
	ecOther *ecdsa.PrivateKey
	rsa     *rsa.PrivateKey
}

func newFuzzDPoPKeyring(f *testing.F) *fuzzDPoPKeyring {
	f.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate EC proof key: %v", err)
	}
	ecOther, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate second EC key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate RSA proof key: %v", err)
	}
	return &fuzzDPoPKeyring{ec: ec, ecOther: ecOther, rsa: rsaKey}
}

// fuzzDPoPShape is everything about a request except the proof itself: which
// key signs, what the Authorization header says, and what the access token in
// context was bound to.
type fuzzDPoPShape struct {
	method     string
	path       string
	authHeader string
	claims     *vaultcrypto.VaultClaims
	boundJKT   string
	signAlg    string
	signEC     *ecdsa.PrivateKey
	signRSA    *rsa.PrivateKey
	jwkMembers string
}

// newFuzzDPoPShape decodes one selector byte into a request shape.
//
// The shapes are enumerated rather than left to mutation because the
// interesting ones are combinations the fuzzer would never assemble by chance:
// a bound token under the wrong scheme, a bound token whose cnf.jkt names a key
// the proof does not present, and a token endpoint request with no
// Authorization header at all. Each is one arm of a branch in the middleware
// that only exists to refuse something.
func newFuzzDPoPShape(kr *fuzzDPoPKeyring, authRaw string, sel uint8, post bool) *fuzzDPoPShape {
	s := &fuzzDPoPShape{method: http.MethodGet, path: fuzzDPoPUserPath}
	if post {
		s.method = http.MethodPost
		s.path = fuzzDPoPTokenPath
	}

	switch (sel / 16) % 3 {
	case 0:
		s.signAlg, s.signEC, s.jwkMembers = "ES256", kr.ec, fuzzDPoPECJWK(&kr.ec.PublicKey)
	case 1:
		s.signAlg, s.signEC, s.jwkMembers = "ES256", kr.ecOther, fuzzDPoPECJWK(&kr.ecOther.PublicKey)
	default:
		s.signAlg, s.signRSA, s.jwkMembers = "RS256", kr.rsa, fuzzDPoPRSAJWK(&kr.rsa.PublicKey)
	}

	switch sel % 4 {
	case 0:
		s.authHeader = ""
	case 1:
		s.authHeader = "Bearer " + fuzzDPoPAccessToken
	case 2:
		s.authHeader = "DPoP " + fuzzDPoPAccessToken
	default:
		s.authHeader = authRaw
	}

	// The bound cases name the thumbprint of the key that signs this proof, so
	// the match arm is reachable, and of a key that does not, so the mismatch
	// arm is too.
	presentedJKT := fuzzDPoPThumbprintOfSigner(s)
	otherJKT := fuzzDPoPKeyThumbprint(&kr.ecOther.PublicKey)
	if presentedJKT == otherJKT {
		otherJKT = fuzzDPoPKeyThumbprint(&kr.ec.PublicKey)
	}
	switch (sel / 4) % 4 {
	case 0:
		s.claims = nil
	case 1:
		s.claims = &vaultcrypto.VaultClaims{}
	case 2:
		s.boundJKT = presentedJKT
		s.claims = &vaultcrypto.VaultClaims{Confirmation: &vaultcrypto.Confirmation{JKT: presentedJKT}}
	default:
		s.boundJKT = otherJKT
		s.claims = &vaultcrypto.VaultClaims{Confirmation: &vaultcrypto.Confirmation{JKT: otherJKT}}
	}
	return s
}

func (s *fuzzDPoPShape) request(proof string) *http.Request {
	req := httptest.NewRequest(s.method, fuzzDPoPOrigin+s.path, nil)
	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}
	req.Header.Set("DPoP", proof)
	if s.claims != nil {
		req = req.WithContext(context.WithValue(req.Context(), ClaimsKey, s.claims))
	}
	return req
}

// buildProof assembles the compact serialization, returning the exact header
// and payload bytes that were signed so the oracle can compare against them
// rather than against a re-decode of the segments.
//
// The fuzzer's bytes are spliced in as text after a known-good set of members,
// which keeps every input one edit away from a proof that would be accepted. A
// target whose inputs are almost all refused asserts almost nothing, and the
// refusal paths already have a target in tests/fuzz. Splicing also preserves
// what a decode-and-remarshal would erase: a duplicate member name, and a number
// literal in a spelling no float64 can hold.
func (kr *fuzzDPoPKeyring) buildProof(s *fuzzDPoPShape, headerExtra, claimsExtra []byte) (proof string, header, claims []byte, ok bool) {
	header = fuzzDPoPSplice(fmt.Sprintf(`"alg":%q,"typ":"dpop+jwt","jwk":{%s}`, s.signAlg, s.jwkMembers), headerExtra)

	base := fmt.Sprintf(`"htm":%q,"htu":%q,"iat":%d,"jti":"01J8Z4",`,
		s.method, fuzzDPoPOrigin+s.path, time.Now().Unix())
	if credential, has := fuzzDPoPCredential(s.authHeader); has {
		base += fmt.Sprintf(`"ath":%q`, vaultcrypto.SHA256Base64URL(credential))
	} else {
		base += `"nonce":"unused"`
	}
	claims = fuzzDPoPSplice(base, claimsExtra)

	signingString := vjwt.EncodeSegment(header) + "." + vjwt.EncodeSegment(claims)
	hash := sha256.Sum256([]byte(signingString))

	var sig []byte
	var err error
	if s.signEC != nil {
		var r, sc *big.Int
		r, sc, err = ecdsa.Sign(rand.Reader, s.signEC, hash[:])
		if err == nil {
			raw := make([]byte, 64)
			r.FillBytes(raw[:32])
			sc.FillBytes(raw[32:])
			sig = raw
		}
	} else {
		sig, err = vjwt.SignRS256Bytes(signingString, s.signRSA)
	}
	if err != nil {
		return "", nil, nil, false
	}
	return signingString + "." + vjwt.EncodeSegment(sig), header, claims, true
}

func fuzzDPoPSplice(base string, extra []byte) []byte {
	if len(extra) == 0 {
		return []byte("{" + base + "}")
	}
	return []byte("{" + base + "," + string(extra) + "}")
}

// fuzzDPoPCredential returns the credential an Authorization header carries,
// split the way internal/middleware/auth.go splits it. The middleware under test
// derives the expected ath from the same position, so this is the assertion that
// the two stay the same position.
func fuzzDPoPCredential(authHeader string) (string, bool) {
	if authHeader == "" {
		return "", false
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	return parts[1], true
}

func fuzzDPoPECJWK(pub *ecdsa.PublicKey) string {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return fmt.Sprintf(`"crv":"P-256","kty":"EC","x":%q,"y":%q`,
		base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
}

func fuzzDPoPRSAJWK(pub *rsa.PublicKey) string {
	return fmt.Sprintf(`"e":%q,"kty":"RSA","n":%q`,
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		base64.RawURLEncoding.EncodeToString(pub.N.Bytes()))
}

func fuzzDPoPThumbprintOfSigner(s *fuzzDPoPShape) string {
	if s.signEC != nil {
		return fuzzDPoPKeyThumbprint(&s.signEC.PublicKey)
	}
	return fuzzDPoPKeyThumbprint(&s.signRSA.PublicKey)
}

// fuzzDPoPKeyThumbprint is the RFC 7638 thumbprint of a key this file owns,
// computed from the members this file would publish for it. It is only used to
// choose what a bound token claims, never to judge a result, so it deliberately
// goes through the same construction as the jwk the proof carries.
func fuzzDPoPKeyThumbprint(pub crypto.PublicKey) string {
	var members string
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		members = fuzzDPoPECJWK(k)
	case *rsa.PublicKey:
		members = fuzzDPoPRSAJWK(k)
	default:
		return ""
	}
	sum := sha256.Sum256([]byte("{" + members + "}"))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// fuzzDPoPThumbprint computes the RFC 7638 thumbprint of the jwk the proof
// actually presented, from that object's own members.
//
// It shares no code with crypto.ComputeJWKThumbprint, and it re-derives the
// canonical form itself: coordinates padded to the curve's byte length, the RSA
// modulus and exponent stripped of leading zeros, members in the lexicographic
// order RFC 7638 3.3 requires and no whitespace. A thumbprint computed over a
// non-canonical encoding would still be stable and would still compare equal to
// itself, so only an independent construction can tell that the value binds the
// key rather than binding one spelling of it.
func fuzzDPoPThumbprint(jwk map[string]any) (string, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		crv, _ := jwk["crv"].(string)
		x, err := fuzzDPoPCoordinate(jwk["x"])
		if err != nil {
			return "", fmt.Errorf("x: %w", err)
		}
		y, err := fuzzDPoPCoordinate(jwk["y"])
		if err != nil {
			return "", fmt.Errorf("y: %w", err)
		}
		input := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv,
			base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
		sum := sha256.Sum256([]byte(input))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	case "RSA":
		n, err := fuzzDPoPUnsigned(jwk["n"])
		if err != nil {
			return "", fmt.Errorf("n: %w", err)
		}
		e, err := fuzzDPoPUnsigned(jwk["e"])
		if err != nil {
			return "", fmt.Errorf("e: %w", err)
		}
		input := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`,
			base64.RawURLEncoding.EncodeToString(e), base64.RawURLEncoding.EncodeToString(n))
		sum := sha256.Sum256([]byte(input))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported kty %q", kty)
	}
}

// fuzzDPoPCoordinate reads an EC coordinate and re-pads it to the 32 bytes
// P-256 uses. The padding is what makes the value canonical: a coordinate sent
// one byte short or one leading zero long is the same number, and a thumbprint
// that changed with the spelling would let one key present two identities.
func fuzzDPoPCoordinate(raw any) ([]byte, error) {
	v, err := fuzzDPoPUnsigned(raw)
	if err != nil {
		return nil, err
	}
	if len(v) > 32 {
		return nil, fmt.Errorf("coordinate is %d bytes, wider than P-256", len(v))
	}
	out := make([]byte, 32)
	copy(out[32-len(v):], v)
	return out, nil
}

// fuzzDPoPUnsigned decodes a base64url JWK member into its minimal big-endian
// unsigned form.
func fuzzDPoPUnsigned(raw any) ([]byte, error) {
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("member is %T, not a string", raw)
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return new(big.Int).SetBytes(b).Bytes(), nil
}

// fuzzDPoPVerifySignature re-checks the proof's signature straight against
// crypto/ecdsa and crypto/rsa, using a key it rebuilds from the presented jwk
// and a signing input it re-splits out of the compact serialization itself. It
// shares no code with the verifier, so a defect in segment splitting or in the
// jwk-to-key conversion cannot hide behind the same defect twice.
func fuzzDPoPVerifySignature(proof string, jwk map[string]any) error {
	segs := strings.Split(proof, ".")
	if len(segs) != 3 {
		return fmt.Errorf("compact serialization has %d segments", len(segs))
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(segs[2])
	if err != nil {
		return fmt.Errorf("signature segment does not decode: %w", err)
	}
	hash := sha256.Sum256([]byte(segs[0] + "." + segs[1]))

	switch kty, _ := jwk["kty"].(string); kty {
	case "EC":
		x, err := fuzzDPoPCoordinate(jwk["x"])
		if err != nil {
			return err
		}
		y, err := fuzzDPoPCoordinate(jwk["y"])
		if err != nil {
			return err
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if len(sig) == 64 {
			r := new(big.Int).SetBytes(sig[:32])
			s := new(big.Int).SetBytes(sig[32:])
			if !ecdsa.Verify(pub, hash[:], r, s) {
				return fmt.Errorf("raw R‖S signature does not verify")
			}
			return nil
		}
		if !ecdsa.VerifyASN1(pub, hash[:], sig) {
			return fmt.Errorf("ASN.1 signature does not verify")
		}
		return nil
	case "RSA":
		n, err := fuzzDPoPUnsigned(jwk["n"])
		if err != nil {
			return err
		}
		e, err := fuzzDPoPUnsigned(jwk["e"])
		if err != nil {
			return err
		}
		exp := new(big.Int).SetBytes(e)
		if !exp.IsInt64() || exp.Int64() > 1<<31-1 {
			return fmt.Errorf("exponent does not fit an int")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
	default:
		return fmt.Errorf("unsupported kty %q", kty)
	}
}

// fuzzDPoPMembers decodes signed bytes into the members they name, last-wins on
// a duplicate the same way encoding/json is inside the verifier, so a duplicate
// member is not reported as a finding here. RFC 7515 4 forbids duplicates and a
// stricter reading is defensible, but it is a policy this codebase has not
// adopted and failing on it would bury the disagreements that are not a policy
// question.
func fuzzDPoPMembers(raw []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, false
	}
	return m, true
}

// fuzzReplayCache is a cache.Cache with nothing in it but a map.
//
// A fresh one is built for every execution so a jti spent by one input cannot
// refuse an unrelated later input, which would make the target's verdict depend
// on execution order and turn every finding into a suspected flake. It holds no
// timer and starts no goroutine, because the production in-memory cache starts a
// sweeper per instance and a fuzz worker would create millions of them.
type fuzzReplayCache struct {
	mu     sync.Mutex
	values map[string]string
}

func newFuzzReplayCache() *fuzzReplayCache {
	return &fuzzReplayCache{values: make(map[string]string, 4)}
}

func (c *fuzzReplayCache) Get(_ context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.values[key]
	if !ok {
		return "", cache.ErrNotFound
	}
	return v, nil
}

func (c *fuzzReplayCache) Set(_ context.Context, key, value string, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] = value
	return nil
}

func (c *fuzzReplayCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.values, key)
	return nil
}

func (c *fuzzReplayCache) GetAndDelete(ctx context.Context, key string) (string, error) {
	v, err := c.Get(ctx, key)
	if err != nil {
		return "", err
	}
	return v, c.Delete(ctx, key)
}

func (c *fuzzReplayCache) SetIfNotExists(_ context.Context, key, value string, _ time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.values[key]; exists {
		return false, nil
	}
	c.values[key] = value
	return true, nil
}

func (c *fuzzReplayCache) Increment(_ context.Context, key string, _ time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := int64(len(c.values[key])) + 1
	c.values[key] = strings.Repeat("x", int(n))
	return n, nil
}

func (c *fuzzReplayCache) Exists(_ context.Context, key string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.values[key]
	return ok, nil
}

func (c *fuzzReplayCache) Close() error { return nil }

// fuzzDPoPHeaderSeeds are proof header members worth starting from. The
// key-source headers RFC 8725 3.8 names are here even though a DPoP proof
// carries its key by design, because the rule is that they must be refused on
// every path and not only on the one that has a test.
var fuzzDPoPHeaderSeeds = [][]byte{
	nil,
	[]byte(`"kid":"vault-signing-1"`),
	[]byte(`"crit":["b64"]`),
	[]byte(`"crit":[]`),
	[]byte(`"typ":"JWT"`),
	[]byte(`"typ":"dpop+jwt"`),
	[]byte(`"alg":"none"`),
	[]byte(`"alg":"HS256"`),
	[]byte(`"jku":"https://evil.test/jwks.json"`),
	[]byte(`"x5u":"https://evil.test/chain.pem"`),
	[]byte(`"jwk":{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}`),
	[]byte(`"jwk":{"kty":"oct","k":"c2VjcmV0"}`),
	[]byte(`"cty":"JWT","b64":false`),
}

// fuzzDPoPClaimSeeds are proof payload members worth starting from.
//
// The timestamps are spelled in exponent notation even where the instant is an
// ordinary one, because the freshness check runs through the same float64 to
// int64 conversion that the access-token verifier does and a corpus written only
// in plain digits is several coordinated mutations away from ever producing a
// number an int64 cannot hold.
var fuzzDPoPClaimSeeds = [][]byte{
	nil,
	[]byte(`"iat":0`),
	[]byte(`"iat":2e9`),
	[]byte(`"iat":9e18`),
	[]byte(`"jti":""`),
	[]byte(`"htm":"GET"`),
	[]byte(`"htu":"https://vault.test/admin"`),
	[]byte(`"ath":""`),
	[]byte(`"ath":"AAAA"`),
	[]byte(`"exp":9e18,"nbf":9e18`),
	[]byte(`"cnf":{"jkt":"AAAA"}`),
	[]byte(`"htu":"https://vault.test/auth/login","htu":"https://evil.test/"`),
}

func addFuzzDPoPSeeds(f *testing.F) {
	f.Helper()
	for i, h := range fuzzDPoPHeaderSeeds {
		for j, c := range fuzzDPoPClaimSeeds {
			f.Add(h, c, "Bearer "+fuzzDPoPAccessToken, uint8(i*len(fuzzDPoPClaimSeeds)+j), (i+j)%2 == 0)
		}
	}
	f.Add([]byte(nil), []byte(nil), "DPoP", uint8(3), true)
	f.Add([]byte(nil), []byte(nil), "DPoP "+fuzzDPoPAccessToken+" extra", uint8(3), false)
	f.Add([]byte(nil), []byte(nil), " "+fuzzDPoPAccessToken, uint8(3), true)
}
