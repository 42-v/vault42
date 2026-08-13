package service

import (
	"crypto/rsa"
	"errors"
	"io"
	"math"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/seed"
)

const (
	mintTestIssuer   = "https://vault.example"
	mintTestAudience = "https://legacy.example"
)

var (
	mintKeyOnce sync.Once
	mintKey     *rsa.PrivateKey
	mintKID     string
)

// mintTestSigner returns a package-shared 2048-bit key so each test does not pay
// for its own key generation.
func mintTestSigner(t *testing.T) SigningKeyProvider {
	t.Helper()
	mintKeyOnce.Do(func() {
		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("generate signing key: %v", err)
		}
		mintKey = key
		mintKID = vaultcrypto.KIDFromPublicKey(&key.PublicKey)
	})
	return func() (*rsa.PrivateKey, string) { return mintKey, mintKID }
}

func mintTestConfig() MintConfig {
	return MintConfig{
		Issuer:        mintTestIssuer,
		Audience:      mintTestAudience,
		DefaultTTL:    5 * time.Minute,
		MaxTTL:        10 * time.Minute,
		AllowedRoles:  []string{"moderator", "premium_user"},
		AllowedScopes: []string{"read", "write"},
	}
}

func newMintService(t *testing.T, cfg MintConfig) *MintService {
	t.Helper()
	svc, err := NewMintService(mintTestSigner(t), cfg, nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}
	return svc
}

func parseMinted(t *testing.T, token, audience string) (*vaultcrypto.VaultClaims, error) {
	t.Helper()
	return vaultcrypto.ParseAndValidate(token, func(*vjwt.Token) (any, error) {
		return &mintKey.PublicKey, nil
	}, mintTestIssuer, audience)
}

// ---------------------------------------------------------------------------
// Startup policy validation
// ---------------------------------------------------------------------------

// A misconfiguration that would let the oracle issue dangerous tokens must stop
// the process, not fail safe once and unsafely later.
func TestNewMintService_RejectsUnsafeConfiguration(t *testing.T) {
	signer := mintTestSigner(t)

	cases := []struct {
		name string
		cfg  MintConfig
	}{
		{"no issuer", MintConfig{Audience: mintTestAudience, DefaultTTL: time.Minute, MaxTTL: time.Minute}},
		{"no audience", MintConfig{Issuer: mintTestIssuer, DefaultTTL: time.Minute, MaxTTL: time.Minute}},
		{"audience equals issuer", MintConfig{Issuer: mintTestIssuer, Audience: mintTestIssuer, DefaultTTL: time.Minute, MaxTTL: time.Minute}},
		{"ttl above the hard ceiling", MintConfig{Issuer: mintTestIssuer, Audience: mintTestAudience, DefaultTTL: time.Minute, MaxTTL: time.Hour}},
		{"zero max ttl", MintConfig{Issuer: mintTestIssuer, Audience: mintTestAudience, DefaultTTL: time.Minute}},
		{"default ttl above max", MintConfig{Issuer: mintTestIssuer, Audience: mintTestAudience, DefaultTTL: 10 * time.Minute, MaxTTL: time.Minute}},
		{"admin role allow-listed", MintConfig{Issuer: mintTestIssuer, Audience: mintTestAudience, DefaultTTL: time.Minute, MaxTTL: time.Minute, AllowedRoles: []string{"admin"}}},
		{"super admin role allow-listed", MintConfig{Issuer: mintTestIssuer, Audience: mintTestAudience, DefaultTTL: time.Minute, MaxTTL: time.Minute, AllowedRoles: []string{"super_admin"}}},
		{"mint scope allow-listed", MintConfig{Issuer: mintTestIssuer, Audience: mintTestAudience, DefaultTTL: time.Minute, MaxTTL: time.Minute, AllowedScopes: []string{"mint:token"}}},
		{"kms scope allow-listed", MintConfig{Issuer: mintTestIssuer, Audience: mintTestAudience, DefaultTTL: time.Minute, MaxTTL: time.Minute, AllowedScopes: []string{"kms:unwrap"}}},
		{"svcdoc scope allow-listed", MintConfig{Issuer: mintTestIssuer, Audience: mintTestAudience, DefaultTTL: time.Minute, MaxTTL: time.Minute, AllowedScopes: []string{"svcdoc:write"}}},
	}
	for _, tc := range cases {
		if _, err := NewMintService(signer, tc.cfg, nil); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if _, err := NewMintService(nil, mintTestConfig(), nil); err == nil {
		t.Error("nil signing key provider accepted")
	}
}

// ---------------------------------------------------------------------------
// Claim shape: the whole trust model rests on these
// ---------------------------------------------------------------------------

// The minted subject is whatever the caller asserted. That is the entire reason
// the endpoint exists: eleven downstream services hold foreign keys to the
// calling platform's user ids.
func TestMint_SubjectIsTheCallerSuppliedValue(t *testing.T) {
	svc := newMintService(t, mintTestConfig())
	res, err := svc.Mint(MintRequest{Subject: "a5bd6c1e-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := parseMinted(t, res.Token, mintTestAudience)
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	if claims.Subject != "a5bd6c1e-0000-4000-8000-000000000001" {
		t.Fatalf("sub = %q, want the caller-supplied subject", claims.Subject)
	}
}

// A minted token must not be usable against vault42 itself. Its token_type is
// outside the allow-list vault42's auth middleware accepts, and its audience is
// not vault42's own, so either check alone stops it at the door. Without both,
// a mint credential is a full account takeover of every vault42 user.
func TestMint_TokenIsRejectedByVaultsOwnValidation(t *testing.T) {
	svc := newMintService(t, mintTestConfig())
	res, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	claims, err := parseMinted(t, res.Token, mintTestAudience)
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	if claims.TokenType != MintedTokenType {
		t.Fatalf("token_type = %q, want %q", claims.TokenType, MintedTokenType)
	}
	if claims.TokenType == "Bearer" {
		t.Fatal("a minted token presents as an ordinary access token")
	}

	// vault42 validates its own tokens against its own audience.
	if _, err := parseMinted(t, res.Token, mintTestIssuer); err == nil {
		t.Fatal("a minted token validated against vault42's own audience")
	}
}

// A minted token carries no client_id. Setting it would make the token
// indistinguishable from a client-credentials token to any code that reads the
// claim's presence as proof of a service caller. The service document store
// asserts exactly that.
func TestMint_CarriesNoServiceOrBindingClaims(t *testing.T) {
	svc := newMintService(t, mintTestConfig())
	res, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := parseMinted(t, res.Token, mintTestAudience)
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	if claims.ClientID != "" {
		t.Errorf("client_id = %q, want empty", claims.ClientID)
	}
	if claims.Fingerprint != "" {
		t.Errorf("fingerprint = %q, want empty", claims.Fingerprint)
	}
	if claims.Confirmation != nil {
		t.Error("minted token carries a proof-of-possession confirmation")
	}
	if claims.ID == "" {
		t.Error("minted token carries no jti, so nothing downstream can trace or replay-track it")
	}
}

func TestMint_EveryTokenGetsAFreshJTI(t *testing.T) {
	svc := newMintService(t, mintTestConfig())
	first, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	second, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if first.JTI == second.JTI {
		t.Fatal("two mints shared a jti")
	}
}

// ---------------------------------------------------------------------------
// Deny-by-default roles and scopes
// ---------------------------------------------------------------------------

// A freshly enabled mint with no allow-lists must issue bare subject
// assertions and nothing more.
func TestMint_EmptyAllowListsGrantNothing(t *testing.T) {
	cfg := mintTestConfig()
	cfg.AllowedRoles = nil
	cfg.AllowedScopes = nil
	svc := newMintService(t, cfg)

	if _, err := svc.Mint(MintRequest{Subject: "user-1", Roles: []string{"moderator"}}); !errors.Is(err, ErrMintRoleNotPermitted) {
		t.Fatalf("role granted with an empty allow-list: %v", err)
	}
	if _, err := svc.Mint(MintRequest{Subject: "user-1", Scopes: []string{"read"}}); !errors.Is(err, ErrMintScopeNotPermitted) {
		t.Fatalf("scope granted with an empty allow-list: %v", err)
	}
	res, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("bare mint refused: %v", err)
	}
	if len(res.Roles) != 0 || len(res.Scopes) != 0 {
		t.Fatalf("bare mint carried roles=%v scopes=%v", res.Roles, res.Scopes)
	}
}

// seed.FilterUserRoles strips admin and super_admin from every user token. The
// mint path must not bypass it: those tiers belong to the admin gateway, and a
// signing oracle that could inject them would escalate straight into vault42's
// own administrative surface. The request is refused rather than silently
// downgraded, so a misconfigured caller is visible instead of quietly weakened.
func TestMint_RefusesAdminTierRolesEvenIfAllowListedLater(t *testing.T) {
	cfg := mintTestConfig()
	cfg.AllowedRoles = []string{"moderator"}
	svc := newMintService(t, cfg)

	for role := range seed.ReservedAdminRoles {
		if _, err := svc.Mint(MintRequest{Subject: "user-1", Roles: []string{role}}); !errors.Is(err, ErrMintRoleNotPermitted) {
			t.Errorf("admin-tier role %q was not refused: %v", role, err)
		}
	}
	// A mixed request must fail whole, not have the admin role quietly dropped.
	if _, err := svc.Mint(MintRequest{Subject: "user-1", Roles: []string{"moderator", "admin"}}); !errors.Is(err, ErrMintRoleNotPermitted) {
		t.Fatalf("mixed role request silently downgraded: %v", err)
	}
	res, err := svc.Mint(MintRequest{Subject: "user-1", Roles: []string{"moderator"}})
	if err != nil {
		t.Fatalf("allow-listed role refused: %v", err)
	}
	if len(res.Roles) != 1 || res.Roles[0] != "moderator" {
		t.Fatalf("roles = %v", res.Roles)
	}
}

// A minted token that carried one of vault42's own capability scopes would let
// the mint holder pivot into the endpoints those scopes gate.
func TestMint_RefusesVaultCapabilityScopes(t *testing.T) {
	cfg := mintTestConfig()
	svc := newMintService(t, cfg)
	for _, scope := range []string{"mint:token", "kms:unwrap", "svcdoc:read", "svcdoc:write"} {
		if _, err := svc.Mint(MintRequest{Subject: "user-1", Scopes: []string{scope}}); !errors.Is(err, ErrMintScopeNotPermitted) {
			t.Errorf("capability scope %q was minted: %v", scope, err)
		}
	}
}

func TestMint_GrantsOnlyAllowListedScopes(t *testing.T) {
	svc := newMintService(t, mintTestConfig())
	res, err := svc.Mint(MintRequest{Subject: "user-1", Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(res.Scopes) != 1 || res.Scopes[0] != "read" {
		t.Fatalf("scopes = %v", res.Scopes)
	}
	if _, err := svc.Mint(MintRequest{Subject: "user-1", Scopes: []string{"read", "delete"}}); !errors.Is(err, ErrMintScopeNotPermitted) {
		t.Fatalf("unlisted scope granted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Subject and lifetime bounds
// ---------------------------------------------------------------------------

func TestValidateMintSubject(t *testing.T) {
	for _, s := range []string{"a5bd6c1e-0000-4000-8000-000000000001", "user.1", "a@b.example", "X1"} {
		if err := ValidateMintSubject(s); err != nil {
			t.Errorf("valid subject %q rejected: %v", s, err)
		}
	}
	for _, s := range []string{"", " ", "-lead", "has space", "a\nb", "a\x00b", `a"b`, strings.Repeat("a", 129)} {
		if err := ValidateMintSubject(s); !errors.Is(err, ErrMintSubjectInvalid) {
			t.Errorf("invalid subject %q accepted", s)
		}
	}
}

// A minted token cannot be revoked, because vault42 keeps no record of it. Its
// lifetime is therefore its whole exposure window, and a request above the
// ceiling is refused rather than clamped: silently issuing something other than
// what was asked for hides the misconfigured caller.
func TestMint_TTLBounds(t *testing.T) {
	svc := newMintService(t, mintTestConfig())

	res, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if res.ExpiresIn != int((5 * time.Minute).Seconds()) {
		t.Fatalf("default ttl = %ds", res.ExpiresIn)
	}

	res, err = svc.Mint(MintRequest{Subject: "user-1", TTL: 30 * time.Second})
	if err != nil {
		t.Fatalf("short ttl refused: %v", err)
	}
	if res.ExpiresIn != 30 {
		t.Fatalf("requested ttl = %ds, want 30", res.ExpiresIn)
	}

	if _, err := svc.Mint(MintRequest{Subject: "user-1", TTL: time.Hour}); !errors.Is(err, ErrMintTTLInvalid) {
		t.Fatalf("ttl above the configured maximum accepted: %v", err)
	}
	if _, err := svc.Mint(MintRequest{Subject: "user-1", TTL: -time.Second}); !errors.Is(err, ErrMintTTLInvalid) {
		t.Fatalf("negative ttl accepted: %v", err)
	}
}

// Every value MintTTLFromSeconds accepts must convert to exactly that many
// seconds, and every value it rejects must be reported as ErrMintTTLInvalid so
// the endpoint answers with the invalid_ttl the contract documents.
//
// The rejections are the point. time.Second is 1e9 = 2^9 * 1953125, so the
// int64 nanosecond product repeats with period 2^55 in the seconds operand:
// 2^55 + 300 seconds, about 1.1 billion years, converts to exactly five
// minutes. Any bound applied after that multiply reads it as an ordinary
// request. If this conversion silently wraps in production, the signing oracle
// mints a token for input nobody validated, and the exact_conversion cases
// below are what stops a future rewrite from clamping instead of refusing:
// clamping would grant a lifetime the caller never asked for and never sees.
func TestMintTTLFromSeconds_AcceptsOnlyExactlyRepresentableLifetimesAndRefusesTheRest(t *testing.T) {
	// Seconds values differing by this convert to the identical nanosecond count.
	const wrapPeriod = 1 << 55
	const ceilingSeconds = int(mintTTLCeiling / time.Second)
	const maxExact = math.MaxInt64 / int64(time.Second)

	accepted := []int{0, 1, 60, 300, 900, ceilingSeconds}
	for _, seconds := range accepted {
		got, err := MintTTLFromSeconds(seconds)
		if err != nil {
			t.Errorf("%d seconds refused: %v", seconds, err)
			continue
		}
		if got != time.Duration(seconds)*time.Second || int(got.Seconds()) != seconds {
			t.Errorf("%d seconds converted to %v, want exactly %d seconds", seconds, got, seconds)
		}
	}

	refused := []struct {
		name    string
		seconds int
	}{
		{"one past the hard ceiling", ceilingSeconds + 1},
		{"largest value that converts without wrapping", int(maxExact)},
		{"first value whose conversion wraps", int(maxExact) + 1},
		{"maximum int64", math.MaxInt64},
		{"wraps to zero, which Mint would read as no TTL requested", wrapPeriod},
		{"wraps to the hard ceiling", wrapPeriod + ceilingSeconds},
		{"wraps to five minutes", wrapPeriod + 300},
		{"wraps to five minutes after two periods", 2*wrapPeriod + 300},
		{"negative", -1},
		{"minimum int64", math.MinInt64},
	}
	for _, tc := range refused {
		got, err := MintTTLFromSeconds(tc.seconds)
		if !errors.Is(err, ErrMintTTLInvalid) {
			t.Errorf("%s: %d seconds gave (%v, %v), want ErrMintTTLInvalid", tc.name, tc.seconds, got, err)
		}
		if got != 0 {
			t.Errorf("%s: %d seconds returned duration %v alongside its error, want 0", tc.name, tc.seconds, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Signing key availability
// ---------------------------------------------------------------------------

// A rotation window with no active key must fail the request, not sign with a
// zero key or panic.
func TestMint_FailsWhenNoSigningKeyIsAvailable(t *testing.T) {
	svc, err := NewMintService(func() (*rsa.PrivateKey, string) { return nil, "" }, mintTestConfig(), nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}
	if _, err := svc.Mint(MintRequest{Subject: "user-1"}); !errors.Is(err, ErrMintUnavailable) {
		t.Fatalf("mint with no signing key: %v", err)
	}
}

// The service must pick up a rotated key rather than pinning the one it saw at
// construction.
func TestMint_UsesTheCurrentSigningKey(t *testing.T) {
	base := mintTestSigner(t)
	rotated, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate rotated key: %v", err)
	}
	rotatedKID := vaultcrypto.KIDFromPublicKey(&rotated.PublicKey)

	useRotated := false
	svc, err := NewMintService(func() (*rsa.PrivateKey, string) {
		if useRotated {
			return rotated, rotatedKID
		}
		return base()
	}, mintTestConfig(), nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}

	first, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	useRotated = true
	second, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("mint after rotation: %v", err)
	}
	if first.KID == second.KID {
		t.Fatal("mint kept signing with the pre-rotation key")
	}
	if second.KID != rotatedKID {
		t.Fatalf("kid = %q, want %q", second.KID, rotatedKID)
	}
}

// mintUnusableSigner reports a key and a kid the way a live provider does, but
// the key's factors do not multiply to its modulus: the shape a signing key
// corrupted at rest has. crypto/rsa refuses it instead of producing a signature
// that would not verify.
func mintUnusableSigner(t *testing.T) SigningKeyProvider {
	t.Helper()
	mintTestSigner(t)
	broken := *mintKey
	broken.Primes = []*big.Int{big.NewInt(61), big.NewInt(53)}
	broken.Precomputed = rsa.PrecomputedValues{}
	return func() (*rsa.PrivateKey, string) { return &broken, mintKID }
}

// A key that is present but cannot sign is a different failure from no key at
// all, and it must not be smoothed into one: no-key is a rotation window a
// caller retries through, an unusable key is an operator fault. Neither may
// produce a token.
func TestMint_FailsWhenTheSigningKeyCannotSign(t *testing.T) {
	svc, err := NewMintService(mintUnusableSigner(t), mintTestConfig(), nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}

	result, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err == nil {
		t.Fatal("Mint returned a token signed with an unusable key")
	}
	if result != nil {
		t.Fatalf("a result came back alongside the error: %+v", result)
	}
	if !strings.Contains(err.Error(), "sign") {
		t.Errorf("err = %v, want it to name the signing step", err)
	}
	if errors.Is(err, ErrMintUnavailable) {
		t.Error("a key that is present but unusable was reported as no key at all")
	}
}

// mintUUIDStarvedReader fails only the 16-byte draw a UUID is made of. RS256
// signing does not consume entropy on this path, so sizing the failure rather
// than counting calls kills the jti and nothing else, and does not drift with
// crypto internals.
type mintUUIDStarvedReader struct{ real io.Reader }

func (r mintUUIDStarvedReader) Read(p []byte) (int, error) {
	if len(p) == 16 {
		return 0, errors.New("entropy exhausted")
	}
	return r.real.Read(p)
}

// The jti is how a downstream incident is traced back to the exact assertion,
// and it is the only handle on a token vault42 keeps no record of. An assertion
// that could not be given one is not issued, so the audit event never names a
// token nobody can identify.
func TestMint_FailsWhenTheJTICannotBeMinted(t *testing.T) {
	svc := newMintService(t, mintTestConfig())
	serviceRandUse(t, mintUUIDStarvedReader{real: serviceRandReal})

	result, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err == nil {
		t.Fatal("Mint issued a token with no jti")
	}
	if result != nil {
		t.Fatalf("a result came back alongside the error: %+v", result)
	}
	if !strings.Contains(err.Error(), "jti") {
		t.Errorf("err = %v, want it to name the jti step", err)
	}
	// It is not a policy refusal, so a caller cannot read it as "the operator
	// forbade this" and stop retrying.
	for _, sentinel := range []error{
		ErrMintSubjectInvalid, ErrMintRoleNotPermitted,
		ErrMintScopeNotPermitted, ErrMintTTLInvalid, ErrMintUnavailable,
	} {
		if errors.Is(err, sentinel) {
			t.Errorf("an entropy failure was reported as %v", sentinel)
		}
	}
}

// ---------------------------------------------------------------------------
// Audience
// ---------------------------------------------------------------------------

// The resource audience is the second of the two controls that keep a minted
// token out of vault42's own routes, the other being the token_type claim. The
// accessor is what the wiring reads it back through, so it has to report the
// value that is actually stamped on the token and not vault42's own issuer.
func TestMintService_AudienceMatchesTheStampedClaim(t *testing.T) {
	svc := newMintService(t, mintTestConfig())

	if got := svc.Audience(); got != mintTestAudience {
		t.Fatalf("Audience() = %q, want %q", got, mintTestAudience)
	}
	if svc.Audience() == mintTestIssuer {
		t.Fatal("the mint audience is vault42's own issuer, so a minted token would satisfy vault42's audience validation")
	}

	result, err := svc.Mint(MintRequest{Subject: "user-1"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if result.Audience != svc.Audience() {
		t.Fatalf("minted audience %q, accessor reports %q", result.Audience, svc.Audience())
	}
	claims, err := parseMinted(t, result.Token, svc.Audience())
	if err != nil {
		t.Fatalf("minted token does not validate against the reported audience: %v", err)
	}
	if aud := claims.GetAudience(); len(aud) != 1 || aud[0] != svc.Audience() {
		t.Fatalf("aud claim = %v, want [%s]", aud, svc.Audience())
	}
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

type fakeMintMetrics struct{ issued, rejected int }

func (f *fakeMintMetrics) RecordMintIssued()   { f.issued++ }
func (f *fakeMintMetrics) RecordMintRejected() { f.rejected++ }

func TestMint_RecordsMetrics(t *testing.T) {
	m := &fakeMintMetrics{}
	svc, err := NewMintService(mintTestSigner(t), mintTestConfig(), m)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}
	if _, err := svc.Mint(MintRequest{Subject: "user-1"}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := svc.Mint(MintRequest{Subject: "bad subject"}); err == nil {
		t.Fatal("invalid subject accepted")
	}
	if m.issued != 1 || m.rejected != 1 {
		t.Fatalf("metrics: issued=%d rejected=%d", m.issued, m.rejected)
	}
}
