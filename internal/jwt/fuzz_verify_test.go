package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The three targets in this file fuzz the verifier against the sentence it
// exists to hold rather than against a list of verdicts:
//
//	if ParseWithClaims returns a nil error, then the token was signed by a key
//	the verifier was configured to trust, under an algorithm in the allowed
//	set, and every registered claim the caller reads back is the one the
//	payload actually carried.
//
// A rejection is therefore always a correct answer and can never fail a target
// here. Only the accept path is asserted on, because a target that asserts a
// refusal can re-check nothing but the inputs somebody already thought of, and
// the input that matters is the one nobody thought of and the verifier ACCEPTED.
// An unrecovered panic is a failure on either path: ParseWithClaims sits on the
// unauthenticated edge of every service that imports this package, so a panic in
// it is a denial of service reachable without a credential.
//
// The targets are separate rather than one target with three assertion blocks
// because Go's fuzzing engine stops at the first failing input. Three targets
// keep three independent corpora and let three distinct violations surface from
// one campaign instead of the first one masking the rest.

// The kids the keyring below files its trusted keys under. They are the only
// two values a Keyfunc in this file will hand a key out for, so a token whose
// header names anything else is refused before a signature is ever checked,
// exactly as internal/middleware/auth.go refuses an unknown kid.
const (
	fuzzKIDRSA = "rsa-trusted"
	fuzzKIDEC  = "ec-trusted"
)

// fuzzIssuer and fuzzAudience are the values the base payload carries. They are
// under .test, which RFC 2606 reserves, so neither can ever name a real vault.
const (
	fuzzIssuer   = "https://vault.test"
	fuzzAudience = "vault42-api"
)

// fuzzClockSlack is how far apart the target lets its own clock reading and the
// verifier's be before it calls a time claim a violation.
//
// validateClaims reads time.Now() itself, at some instant between the two
// readings this file takes around the parse, and a fuzz worker can be descheduled
// in that gap. Without the slack a target would fail on a scheduling hiccup
// instead of on a bug, which is the fastest way to get a real finding dismissed
// as flake. It is seconds wide and the coercion hazard these targets hunt is
// wrong by centuries, so the slack costs no sensitivity.
const fuzzClockSlack = 30 * time.Second

// fuzzBigPrec is the mantissa width the oracle reads timestamp claims at.
//
// The claim is read as an arbitrary-precision decimal rather than a float64
// because float64 is the type the bug class under test hides in: a JSON number
// that does not fit an int64 converts to an implementation-defined value in Go,
// and an oracle that took the same lossy path would compute the same wrong
// answer and agree with the code it is supposed to be judging.
const fuzzBigPrec = 256

// fuzzKeyring holds the keys a target trusts and the ones it does not.
//
// Both sets are generated once per target, not once per input. RSA key
// generation costs milliseconds, and a target that paid it on every execution
// would explore a few hundred inputs where this one explores millions, which is
// the difference between a target that finds something and a target that only
// looks like one.
type fuzzKeyring struct {
	rsaTrusted  *rsa.PrivateKey
	rsaAttacker *rsa.PrivateKey
	ecTrusted   *ecdsa.PrivateKey
	ecAttacker  *ecdsa.PrivateKey
	// trusted is the whole of what this verifier is configured to accept,
	// indexed the way a real key set is. A signature that verifies must verify
	// against a value from this map and nothing else.
	trusted map[string]any
}

func newFuzzKeyring(f *testing.F) *fuzzKeyring {
	f.Helper()
	rsaTrusted, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate trusted RSA key: %v", err)
	}
	rsaAttacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate attacker RSA key: %v", err)
	}
	ecTrusted, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate trusted EC key: %v", err)
	}
	ecAttacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate attacker EC key: %v", err)
	}
	return &fuzzKeyring{
		rsaTrusted:  rsaTrusted,
		rsaAttacker: rsaAttacker,
		ecTrusted:   ecTrusted,
		ecAttacker:  ecAttacker,
		trusted: map[string]any{
			fuzzKIDRSA: &rsaTrusted.PublicKey,
			fuzzKIDEC:  &ecTrusted.PublicKey,
		},
	}
}

// The signers a target can be asked to produce a token with. Four of them hold
// a key the verifier trusts and four do not, and every target asserts that a
// token which verified came from the first group. Naming the attacker keys as
// signers rather than leaving them to random mutation is what makes the
// key-confusion question answerable: mutation alone will not produce a valid
// RSA signature over the fuzzer's own header bytes, so without these the accept
// path would only ever be reached by the honest signer and the assertion would
// be vacuous.
const (
	// fuzzSignRSATrusted is the shape vault42 mints: RS256 over the trusted
	// signing key.
	fuzzSignRSATrusted = iota
	// fuzzSignECTrustedRaw is the RFC 7515 3.4 raw R‖S form.
	fuzzSignECTrustedRaw
	// fuzzSignECTrustedDER is the ASN.1 form VerifyES256 also accepts, because
	// the ES256 tokens it must verify include proofs from HSMs that return DER.
	fuzzSignECTrustedDER
	// fuzzSignRSAAttacker signs with a key the verifier never heard of while
	// the header still names a trusted kid, which is the shape of a plain
	// forgery.
	fuzzSignRSAAttacker
	// fuzzSignECAttacker is the same forgery on the ES256 path.
	fuzzSignECAttacker
	// fuzzSignEmpty leaves the signature segment empty, the alg-none shape.
	fuzzSignEmpty
	// fuzzSignGarbage puts the payload bytes in the signature segment, so the
	// segment is well-formed base64url over data that is not a signature.
	fuzzSignGarbage
	// fuzzSignWrongInput signs the trusted key over the payload alone instead
	// of over "header.payload", so the signature is genuine but is not bound to
	// the header the verifier read the alg and kid out of.
	fuzzSignWrongInput
	fuzzSignerCount
)

// fuzzSignerIsTrusted reports whether a signer holds a key the verifier is
// configured to trust and signed the bytes the verifier hashes. Everything else
// must be refused, whatever the header says.
func fuzzSignerIsTrusted(signer int) bool {
	switch signer {
	case fuzzSignRSATrusted, fuzzSignECTrustedRaw, fuzzSignECTrustedDER:
		return true
	default:
		return false
	}
}

// fuzzToken is one built token together with the exact header and payload bytes
// that went into it, which is what makes the round-trip check possible: the
// oracle compares against the bytes that were signed, not against a re-decode of
// the segments, so a disagreement inside the base64 layer cannot hide from it.
type fuzzToken struct {
	compact string
	header  []byte
	payload []byte
	signer  int
}

// algAndKID picks the header the given signer's key would honestly carry. The
// forging signers still name a trusted kid, because a forgery that named an
// unknown kid would be refused by the Keyfunc before any signature check and
// would prove nothing about the verifier.
func (kr *fuzzKeyring) algAndKID(signer int) (alg, kid string) {
	switch signer {
	case fuzzSignECTrustedRaw, fuzzSignECTrustedDER, fuzzSignECAttacker:
		return "ES256", fuzzKIDEC
	default:
		return "RS256", fuzzKIDRSA
	}
}

// spliceJSON builds a JSON object from a known-good list of members with the
// fuzzer's own text appended verbatim.
//
// Splicing text rather than merging a decoded map is deliberate. A map merge
// would round-trip through encoding/json and normalize away the two things this
// file most wants the fuzzer to be able to write: a duplicate member name, where
// last-wins is a property of the parser and not of the JWT, and a number literal
// in a spelling that a float64 cannot hold. Both survive a splice untouched.
//
// The base members come first, so anything the fuzzer writes overrides them
// under last-wins and every input still starts from a token that would verify.
// That is what keeps the accept path reachable: a target whose inputs are almost
// all rejected asserts almost nothing.
func spliceJSON(base string, extra []byte) []byte {
	if len(extra) == 0 {
		return []byte("{" + base + "}")
	}
	return []byte("{" + base + "," + string(extra) + "}")
}

// fuzzBaseClaims is a payload that validates cleanly at the instant it is built.
func fuzzBaseClaims(now time.Time) string {
	return fmt.Sprintf(`"iss":%q,"sub":"alice","jti":"7f3a2b","aud":[%q],"exp":%d,"nbf":%d,"iat":%d`,
		fuzzIssuer, fuzzAudience, now.Add(time.Hour).Unix(), now.Add(-time.Minute).Unix(), now.Add(-time.Minute).Unix())
}

// build assembles the compact serialization for one fuzz input. It reports
// false only when the signer itself failed, which no input can cause and which
// therefore must not be reported as a finding.
func (kr *fuzzKeyring) build(headerExtra, payloadExtra []byte, signerSel uint8, now time.Time) (fuzzToken, bool) {
	signer := int(signerSel) % fuzzSignerCount
	alg, kid := kr.algAndKID(signer)

	header := spliceJSON(fmt.Sprintf(`"alg":%q,"typ":"JWT","kid":%q`, alg, kid), headerExtra)
	payload := spliceJSON(fuzzBaseClaims(now), payloadExtra)
	signingString := encodeSegment(header) + "." + encodeSegment(payload)

	sigSeg, ok := kr.signSegment(signer, signingString, payload)
	if !ok {
		return fuzzToken{}, false
	}
	return fuzzToken{
		compact: signingString + "." + sigSeg,
		header:  header,
		payload: payload,
		signer:  signer,
	}, true
}

func (kr *fuzzKeyring) signSegment(signer int, signingString string, payload []byte) (string, bool) {
	switch signer {
	case fuzzSignRSATrusted:
		return rsaSegment(kr.rsaTrusted, signingString)
	case fuzzSignRSAAttacker:
		return rsaSegment(kr.rsaAttacker, signingString)
	case fuzzSignWrongInput:
		return rsaSegment(kr.rsaTrusted, string(payload))
	case fuzzSignECTrustedRaw:
		return ecRawSegment(kr.ecTrusted, signingString)
	case fuzzSignECAttacker:
		return ecRawSegment(kr.ecAttacker, signingString)
	case fuzzSignECTrustedDER:
		hash := sha256.Sum256([]byte(signingString))
		der, err := ecdsa.SignASN1(rand.Reader, kr.ecTrusted, hash[:])
		if err != nil {
			return "", false
		}
		return encodeSegment(der), true
	case fuzzSignEmpty:
		return "", true
	case fuzzSignGarbage:
		return encodeSegment(payload), true
	default:
		return "", false
	}
}

func rsaSegment(key *rsa.PrivateKey, signingString string) (string, bool) {
	sig, err := SignRS256Bytes(signingString, key)
	if err != nil {
		return "", false
	}
	return encodeSegment(sig), true
}

// ecRawSegment produces the RFC 7515 3.4 raw R‖S form, with both halves padded
// to the curve's coordinate size. The padding is not cosmetic: isRawRS
// discriminates the raw form from DER on length alone, so a short R would make
// an honest signature look like DER and be rejected, and the target would then
// be asserting against its own encoder rather than against the verifier.
func ecRawSegment(key *ecdsa.PrivateKey, signingString string) (string, bool) {
	hash := sha256.Sum256([]byte(signingString))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", false
	}
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	raw := make([]byte, 2*byteLen)
	r.FillBytes(raw[:byteLen])
	s.FillBytes(raw[byteLen:])
	return encodeSegment(raw), true
}

// parse runs the verifier the way a caller does, and reports which trusted kid
// the Keyfunc handed a key out for. An empty kid means the Keyfunc never
// produced a key, so a token that verified anyway verified against nothing the
// caller chose.
func (kr *fuzzKeyring) parse(tok fuzzToken, claims Claims, opts ...ParseOption) (*Token, string, error) {
	var handedKID string
	keyFunc := func(t *Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := kr.trusted[kid]
		if !ok {
			return nil, ErrTokenSignatureInvalid
		}
		handedKID = kid
		return key, nil
	}
	parsed, err := ParseWithClaims(tok.compact, claims, keyFunc, opts...)
	return parsed, handedKID, err
}

// fuzzHeaderSeeds are header members worth starting from. The key-source headers
// RFC 8725 3.8 says to reject are all here because the rejection lives in the
// caller's Keyfunc rather than in this package, so a target that never fed one
// would not notice the day a caller stopped rejecting them.
var fuzzHeaderSeeds = [][]byte{
	nil,
	[]byte(`"jku":"https://evil.test/jwks.json"`),
	[]byte(`"x5u":"https://evil.test/chain.pem"`),
	[]byte(`"x5c":["MIIBkTCB+w"]`),
	[]byte(`"jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}`),
	[]byte(`"crit":["b64"]`),
	[]byte(`"crit":[]`),
	[]byte(`"alg":"none"`),
	[]byte(`"alg":"HS256"`),
	[]byte(`"alg":"RS256"`),
	[]byte(`"alg":"ES256"`),
	[]byte(`"kid":"../../etc/passwd"`),
	[]byte(`"kid":"rsa-trusted"`),
	[]byte(`"typ":"dpop+jwt"`),
	[]byte(`"typ":null,"cty":"JWT"`),
}

// fuzzPayloadSeeds are claim members worth starting from.
//
// Several carry a timestamp in exponent notation even though every one of them
// is an ordinary in-range instant. That is the point: the hazard being hunted is
// a number too large for an int64, and a corpus written only in plain digits puts
// the fuzzer several coordinated mutations away from ever spelling one, while a
// corpus that already contains "2e9" puts it one byte away.
var fuzzPayloadSeeds = [][]byte{
	nil,
	[]byte(`"exp":0`),
	[]byte(`"nbf":0`),
	[]byte(`"iat":0`),
	[]byte(`"exp":2e9`),
	[]byte(`"nbf":1e9`),
	[]byte(`"iat":1.5e9`),
	[]byte(`"exp":9e18`),
	[]byte(`"nbf":9e18,"iat":9e18`),
	[]byte(`"exp":9999999999`),
	[]byte(`"exp":null,"nbf":null,"iat":null`),
	[]byte(`"exp":1,"exp":9999999999`),
	[]byte(`"iss":""`),
	[]byte(`"sub":"root"`),
	[]byte(`"jti":""`),
	[]byte(`"aud":"vault42-api"`),
	[]byte(`"aud":[]`),
	[]byte(`"aud":["a","b"]`),
	[]byte(`"iss":"https://vault.test","iss":"https://evil.test"`),
	[]byte(`"cnf":{"jkt":"AAAA"},"scopes":["kms:unwrap"]`),
	[]byte(`"exp":1.5,"nbf":-1.5`),
}

// addFuzzSeeds seeds the cross product of the header and payload corpora across
// every signer, so each corpus entry is exercised once with a signature that
// verifies and once with one that must not.
func addFuzzSeeds(f *testing.F) {
	f.Helper()
	for i, h := range fuzzHeaderSeeds {
		for j, p := range fuzzPayloadSeeds {
			f.Add(h, p, uint8((i+j)%fuzzSignerCount))
		}
	}
}

// addFuzzPayloadSeeds is the payload-only corpus for the targets that do not
// vary the header.
func addFuzzPayloadSeeds(f *testing.F) {
	f.Helper()
	for j, p := range fuzzPayloadSeeds {
		f.Add(p, uint8(j%fuzzSignerCount))
	}
}

// FuzzVerifiedTokenProvenance asserts the provenance half of the contract: a
// token that verifies was signed, over the exact bytes the verifier hashed, by a
// key the caller's Keyfunc handed out, under an algorithm the signature switch
// implements.
//
// The failure it exists to catch is the whole family of key and algorithm
// confusion: a public JWKS modulus replayed as an HMAC secret, an alg the
// allowlist narrowed away still reaching a verify call, a signature that is
// genuine but was made over different bytes, and any path that reaches
// token.Valid without the Keyfunc ever producing a key. Every one of those turns
// a forged token into an authenticated request, which is the worst outcome this
// package has.
func FuzzVerifiedTokenProvenance(f *testing.F) {
	kr := newFuzzKeyring(f)
	addFuzzSeeds(f)

	f.Fuzz(func(t *testing.T, headerExtra, payloadExtra []byte, signerSel uint8) {
		tok, ok := kr.build(headerExtra, payloadExtra, signerSel, time.Now())
		if !ok {
			return
		}

		claims := &RegisteredClaims{}
		parsed, handedKID, err := kr.parse(tok, claims, WithValidMethods([]string{"RS256", "ES256"}))
		if err != nil {
			return
		}

		if parsed == nil {
			t.Fatalf("nil error and nil token for %q", tok.compact)
		}
		if !parsed.Valid {
			t.Fatalf("nil error but Valid is false; a caller reading Valid and a caller reading err disagree about %q", tok.compact)
		}
		if parsed.Raw != tok.compact {
			t.Fatalf("Raw = %q, want the string that was verified, %q", parsed.Raw, tok.compact)
		}
		if handedKID == "" {
			t.Fatalf("token verified without the Keyfunc ever handing out a key: %q", tok.compact)
		}
		if !fuzzSignerIsTrusted(tok.signer) {
			t.Fatalf("signer %d, which holds no key this verifier trusts, produced a token that verified under kid %q: %q",
				tok.signer, handedKID, tok.compact)
		}

		alg, _ := parsed.Header["alg"].(string)
		if alg != "RS256" && alg != "ES256" {
			t.Fatalf("token verified under alg %q, which is outside the implemented set: %q", alg, tok.compact)
		}
		if (alg == "RS256") != (handedKID == fuzzKIDRSA) {
			t.Fatalf("alg %q verified against the key filed under kid %q: %q", alg, handedKID, tok.compact)
		}

		if err := fuzzVerifyIndependently(tok.compact, kr.trusted[handedKID]); err != nil {
			t.Fatalf("verifier accepted a token this target cannot verify against the same key: %v (%q)", err, tok.compact)
		}
	})
}

// fuzzVerifyIndependently re-checks the signature straight against crypto/rsa
// and crypto/ecdsa, from the token string alone.
//
// It exists so the accept path has a second opinion that shares no code with the
// verifier: it re-splits the compact serialization, re-decodes the signature and
// re-hashes the signing input itself. A defect in splitToken or decodeSegment
// that made the verifier hash something other than the bytes between the dots
// would be invisible to a check that reused them.
func fuzzVerifyIndependently(compact string, key any) error {
	segs := strings.Split(compact, ".")
	if len(segs) != 3 {
		return fmt.Errorf("compact serialization has %d segments", len(segs))
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(segs[2])
	if err != nil {
		return fmt.Errorf("signature segment does not decode: %w", err)
	}
	hash := sha256.Sum256([]byte(segs[0] + "." + segs[1]))

	switch k := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], sig)
	case *ecdsa.PublicKey:
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) == 2*byteLen {
			r := new(big.Int).SetBytes(sig[:byteLen])
			s := new(big.Int).SetBytes(sig[byteLen:])
			if !ecdsa.Verify(k, hash[:], r, s) {
				return fmt.Errorf("raw R‖S signature does not verify")
			}
			return nil
		}
		if !ecdsa.VerifyASN1(k, hash[:], sig) {
			return fmt.Errorf("ASN.1 signature does not verify")
		}
		return nil
	default:
		return fmt.Errorf("keyfunc handed out an unusable key of type %T", key)
	}
}

// FuzzVerifiedTokenTimeBounds asserts the time half of the contract: a token
// that verifies is one whose exp is still ahead and whose nbf and iat are
// already behind, measured against the number the payload actually carried.
//
// The oracle reads each timestamp as an arbitrary-precision decimal, which is
// the only way it can disagree with the verifier at all. NumericDate parses a
// claim through float64 and then converts to int64, and converting a float64
// that does not fit an int64 is implementation-defined in Go: the result is not
// an error and not a saturation, it is whatever the hardware returns. An oracle
// that read the claim as a float64 would take the same path, compute the same
// wrong instant and agree with the verifier every time.
//
// The failure this catches is a token that is not yet valid, or that was issued
// in the future, being accepted as current. exp fails in the safe direction
// under the same coercion and is asserted anyway, because a package that got the
// safe direction by accident should not keep it by accident.
func FuzzVerifiedTokenTimeBounds(f *testing.F) {
	kr := newFuzzKeyring(f)
	addFuzzPayloadSeeds(f)

	f.Fuzz(func(t *testing.T, payloadExtra []byte, signerSel uint8) {
		before := time.Now()
		tok, ok := kr.build(nil, payloadExtra, signerSel, before)
		if !ok {
			return
		}

		claims := &RegisteredClaims{}
		_, _, err := kr.parse(tok, claims, WithValidMethods([]string{"RS256", "ES256"}), WithIssuedAt())
		if err != nil {
			return
		}
		after := time.Now()

		signed, ok := fuzzSignedMembers(tok.payload)
		if !ok {
			t.Fatalf("payload verified but this target cannot decode it: %s", tok.payload)
		}

		// exp is compared against the earlier reading and nbf and iat against
		// the later one, so every comparison is the one that gives the verifier
		// the benefit of the doubt. A finding here is then a claim that is wrong
		// by more than the whole window plus the slack, never a race with the
		// clock.
		if exp, ok := fuzzClaimSeconds(signed, "exp"); ok {
			if exp.Cmp(fuzzUnixBig(before.Add(-fuzzClockSlack))) < 0 {
				t.Fatalf("token verified with exp %s, already past at %s: %s", exp.Text('g', 20), before, tok.payload)
			}
		}
		if nbf, ok := fuzzClaimSeconds(signed, "nbf"); ok {
			if nbf.Cmp(fuzzUnixBig(after.Add(fuzzClockSlack))) > 0 {
				t.Fatalf("token verified with nbf %s, still in the future at %s: %s", nbf.Text('g', 20), after, tok.payload)
			}
		}
		if iat, ok := fuzzClaimSeconds(signed, "iat"); ok {
			if iat.Cmp(fuzzUnixBig(after.Add(fuzzClockSlack))) > 0 {
				t.Fatalf("token verified under WithIssuedAt with iat %s, still in the future at %s: %s", iat.Text('g', 20), after, tok.payload)
			}
		}
	})
}

// FuzzVerifiedClaimsRoundTrip asserts the read-back half of the contract: every
// registered claim a caller reads off a verified token is the one the signed
// payload carried, under that exact name.
//
// The failure it catches is a verified token whose claims are not the claims it
// was signed with. That is not only a correctness problem: iss and aud are
// checked by comparing the value read back, so a claim the caller reads under a
// name the payload never used is a claim an issuer check can pass on.
func FuzzVerifiedClaimsRoundTrip(f *testing.F) {
	kr := newFuzzKeyring(f)
	addFuzzPayloadSeeds(f)

	f.Fuzz(func(t *testing.T, payloadExtra []byte, signerSel uint8) {
		tok, ok := kr.build(nil, payloadExtra, signerSel, time.Now())
		if !ok {
			return
		}

		claims := &RegisteredClaims{}
		_, _, err := kr.parse(tok, claims, WithValidMethods([]string{"RS256", "ES256"}))
		if err != nil {
			return
		}

		signed, ok := fuzzSignedMembers(tok.payload)
		if !ok {
			t.Fatalf("payload verified but this target cannot decode it: %s", tok.payload)
		}

		for _, c := range []struct {
			name string
			got  string
		}{
			{"iss", claims.GetIssuer()},
			{"sub", claims.GetSubject()},
			{"jti", claims.ID},
		} {
			raw, present := signed[c.name]
			if present && raw == nil {
				continue
			}
			want, _ := raw.(string)
			if c.got != want {
				t.Fatalf("caller reads %s = %q from a token whose payload carries %s = %q: %s",
					c.name, c.got, c.name, want, tok.payload)
			}
		}

		// A member whose value is JSON null is skipped above and here. Decoding
		// null leaves a string field untouched and is a documented no-op for a
		// type with its own UnmarshalJSON, so under last-wins a null that
		// follows a real value keeps the earlier one. That is a convention of
		// encoding/json rather than a defect in this package, and failing on it
		// would bury the disagreements that are.
		if raw, present := signed["aud"]; !present || raw != nil {
			if got, want := claims.GetAudience(), fuzzSignedAudience(signed); !fuzzSameStrings(got, want) {
				t.Fatalf("caller reads aud = %q from a token whose payload carries aud = %q: %s", got, want, tok.payload)
			}
		}

		// A timestamp claim the caller can read must have been carried as a JSON
		// number, which is the only form RFC 7519 2 defines for a NumericDate.
		// The two Claims implementations in this package disagree about anything
		// else: RegisteredClaims routes the value through json.Number, which
		// accepts a quoted number, while MapClaims reads a wrong-typed claim as
		// absent. One code path then treats a token as expired that the other
		// treats as carrying no expiry at all.
		for _, c := range []struct {
			name string
			got  *NumericDate
		}{
			{"exp", claims.GetExpirationTime()},
			{"nbf", claims.GetNotBefore()},
			{"iat", claims.GetIssuedAt()},
		} {
			_, isNumber := signed[c.name].(json.Number)
			if c.got != nil && !isNumber {
				t.Fatalf("caller reads %s = %v from a token whose payload carries %s as %T: %s",
					c.name, c.got.Time, c.name, signed[c.name], tok.payload)
			}
			if c.got == nil && isNumber {
				t.Fatalf("caller reads no %s from a token whose payload carries %s = %v: %s",
					c.name, c.name, signed[c.name], tok.payload)
			}
		}
	})
}

// fuzzSignedMembers decodes the exact bytes that were signed into the members
// they name.
//
// It is deliberately last-wins on a duplicate member name, matching what
// encoding/json does inside the verifier, so a duplicate is not reported as a
// finding. RFC 7515 4 forbids duplicates outright and a stricter reading is
// defensible, but that is a policy this package has not adopted and a target
// that failed on it would bury the disagreements that are not a policy question.
func fuzzSignedMembers(payload []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, false
	}
	return m, true
}

// fuzzSignedAudience reads aud in the two shapes RFC 7519 4.1.3 allows. A shape
// outside those two would have failed ClaimStrings.UnmarshalJSON and never
// reached the accept path, so reading it as absent here cannot mask anything.
func fuzzSignedAudience(signed map[string]any) ClaimStrings {
	switch v := signed["aud"].(type) {
	case string:
		return ClaimStrings{v}
	case []any:
		out := make(ClaimStrings, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}

// fuzzSameStrings compares two audiences by content, treating nil and empty as
// the same absence. ClaimStrings distinguishes them only by allocation, and an
// audience check iterates either one zero times.
func fuzzSameStrings(a, b ClaimStrings) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fuzzClaimSeconds reads a timestamp claim at full precision, reporting false
// for anything that is not a JSON number so the caller compares only claims the
// verifier could have read as a time.
func fuzzClaimSeconds(signed map[string]any, name string) (*big.Float, bool) {
	raw, ok := signed[name].(json.Number)
	if !ok {
		return nil, false
	}
	v, _, err := big.ParseFloat(string(raw), 10, fuzzBigPrec, big.ToNearestEven)
	if err != nil {
		return nil, false
	}
	return v, true
}

func fuzzUnixBig(t time.Time) *big.Float {
	return new(big.Float).SetPrec(fuzzBigPrec).SetInt64(t.Unix())
}
