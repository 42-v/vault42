package attack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/honeypot"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// A trap credential being used is the honeypot's entire product, and the audit
// row is the only durable copy of it: the webhook is rate limited and
// best-effort, and a line in the process log is not evidence. The attacker
// decides how much traffic the trap sees, so they decide when the audit buffer
// is full. A droppable honeypot_trigger therefore lets a flood erase the record
// of the one visit the operator needed to keep.
func TestAHoneypotTriggerIsWrittenEvenWhenTheAuditBufferIsFull(t *testing.T) {
	var mu sync.Mutex
	var written []string
	repo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			mu.Lock()
			defer mu.Unlock()
			written = append(written, entry.EventType)
			return nil
		},
	}
	// A one-entry buffer that will not flush for an hour: the first Log fills
	// it, and every Log after that meets the full-buffer branch.
	logger := audit.NewLoggerWithBufferSize(repo, time.Hour, 1)
	ctx := context.Background()
	defer logger.Close(ctx) // #nosec G104 -- test cleanup

	if err := logger.Log(ctx, audit.LoginSuccess, "", "", "", "", "", "", nil, 0); err != nil {
		t.Fatalf("filling the buffer: %v", err)
	}
	if err := logger.Log(ctx, audit.HoneypotTrigger, "", "", "203.0.113.7", "", "", "", nil, 100); err != nil {
		t.Fatalf("logging the trigger: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, ev := range written {
		if ev == audit.HoneypotTrigger {
			return
		}
	}
	t.Fatalf("a honeypot_trigger met a full audit buffer and was dropped; the events written through were %v", written)
}

// TestHoneypotToken_StructureMatchesRealJWT verifies that fake JWTs have
// the same three-part base64url structure as real JWTs.
func TestHoneypotToken_StructureMatchesRealJWT(t *testing.T) {
	// Generate a real JWT for comparison
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	realToken, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "real-user",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"vault"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles: []string{"user"},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	fakeToken := hpTrapAccessToken(t, hpService(t, false))

	// Both should have 3 dot-separated parts
	realParts := strings.Split(realToken, ".")
	fakeParts := strings.Split(fakeToken, ".")

	if len(realParts) != 3 {
		t.Fatalf("Real token has %d parts, expected 3", len(realParts))
	}
	if len(fakeParts) != 3 {
		t.Fatalf("Fake token has %d parts, expected 3", len(fakeParts))
	}

	// Each part should be valid base64url
	for i, part := range fakeParts {
		_, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatalf("Fake token part %d is not valid base64url: %v", i, err)
		}
	}
}

// TestHoneypotToken_HeaderMatchesRealFormat pins the trap token's header
// against a header a real signing key actually produced.
//
// It used to assert len(kid) >= 32 under this name, which was not a comparison
// against anything: every key the vault files is named by
// crypto.KIDFromPublicKey, whose output is 17 characters, so the assertion
// guaranteed the trap's kid could not be the shape of a real one. A trap token
// whose key id is visibly not a vault key id gives the deployment away from the
// first segment of the first token it hands over, and vault42 is public source
// so the attacker knows the shape to look for.
func TestHoneypotToken_HeaderMatchesRealFormat(t *testing.T) {
	fakeToken := hpTrapAccessToken(t, hpService(t, false))

	// A real header, produced by signing with a real key under a real kid.
	realKey, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate a real signing key: %v", err)
	}
	realKID := vaultcrypto.KIDFromPublicKey(&realKey.PublicKey)
	realToken, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "real-user",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"vault"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, realKey, realKID)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	realHeader := honeypotDecodeHeader(t, realToken)
	fakeHeader := honeypotDecodeHeader(t, fakeToken)

	for name, want := range realHeader {
		got, present := fakeHeader[name]
		if !present {
			t.Errorf("the trap header has no %q; a real header carries it", name)
			continue
		}
		// kid names a different key on every deployment, so only its shape can
		// be compared. Every other header member is a constant of the algorithm
		// and must match exactly.
		if name == "kid" {
			continue
		}
		if got != want {
			t.Errorf("trap header %s = %v, a real header carries %v", name, got, want)
		}
	}
	for name := range fakeHeader {
		if _, present := realHeader[name]; !present {
			t.Errorf("the trap header carries %q, which a real header does not", name)
		}
	}

	fakeKID, _ := fakeHeader["kid"].(string)
	if len(fakeKID) != len(realKID) {
		t.Errorf("the trap key id %q is %d characters; every key the vault files is %d", fakeKID, len(fakeKID), len(realKID))
	}
	if strings.Count(fakeKID, "-") != strings.Count(realKID, "-") {
		t.Errorf("the trap key id %q is not shaped like a real one (%q)", fakeKID, realKID)
	}
}

// honeypotDecodeHeader decodes a token's header segment.
func honeypotDecodeHeader(t *testing.T, token string) map[string]interface{} {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not three segments: %q", token)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return header
}

// TestHoneypotToken_ClaimsLookRealistic verifies that fake JWT claims contain
// the standard fields that a real vault JWT would have.
func TestHoneypotToken_ClaimsLookRealistic(t *testing.T) {
	fakeToken := hpTrapAccessToken(t, hpService(t, false))

	parts := strings.Split(fakeToken, ".")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode fake payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("Failed to unmarshal fake claims: %v", err)
	}

	// Must have sub, iss, aud, exp, iat
	requiredFields := []string{"sub", "iss", "aud", "exp", "iat"}
	for _, field := range requiredFields {
		if _, exists := claims[field]; !exists {
			t.Fatalf("Fake JWT missing required claim %q", field)
		}
	}

	// sub should be UUID-like
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		t.Fatal("Expected non-empty string sub claim")
	}
	if len(sub) < 32 {
		t.Fatalf("sub too short for UUID format: %q", sub)
	}

	// exp should be in the future
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("Expected numeric exp claim")
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		t.Fatal("Fake JWT exp should be in the future")
	}

	// iat should be approximately now
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal("Expected numeric iat claim")
	}
	iatTime := time.Unix(int64(iat), 0)
	if time.Since(iatTime) > 5*time.Second {
		t.Fatalf("Fake JWT iat too far from now: %v", iatTime)
	}

	// The client id the caller presented. GenerateFakeJWT, the orphan this test
	// used to mint through, passed an empty TrapCaller, so client_id was absent
	// from every token the suite ever inspected while the deployment's trap
	// always carries the attacker's own client id back to them.
	if got, _ := claims["client_id"].(string); got != "acme-web" {
		t.Errorf("trap token carries client_id %q, want the one the caller presented", got)
	}

	// Should have roles (to look like a real vault token)
	roles, ok := claims["roles"]
	if !ok {
		t.Fatal("Fake JWT should have roles claim for realism")
	}
	rolesArr, ok := roles.([]interface{})
	if !ok || len(rolesArr) == 0 {
		t.Fatal("Fake JWT roles should be a non-empty array")
	}
}

// TestHoneypotToken_SignatureDoesNotVerify verifies that the fake JWT signature
// fails verification against a real RSA key pair.
func TestHoneypotToken_SignatureDoesNotVerify(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()

	fakeToken := hpTrapAccessToken(t, hpService(t, false))

	// Hand the parser a real deployment key for whatever kid the trap named.
	// A trap token that verified under it would be a token the production vault
	// accepts, which is the one outcome the trap must never produce.
	keyFunc := func(*vjwt.Token) (any, error) { return &key.PublicKey, nil }

	if _, err := vaultcrypto.ParseAndValidate(fakeToken, keyFunc, "vault", "vault"); err == nil {
		t.Fatal("a trap token validated against a real signing key")
	}
}

// TestHoneypotToken_UniquePerGeneration pins which parts of a trap token are
// fresh per mint and which hold still per account.
//
// It used to assert that 50 mints produced 50 distinct sub values, which pinned
// the defect rather than the property: sub is a user id, stable for the life of
// an account, and jti is the claim that is supposed to be fresh. Two logins with
// one planted credential coming back as two different accounts is decisive in
// two requests, and after that the honeypot collects nothing but the behavior of
// an attacker who knows they are being watched.
func TestHoneypotToken_UniquePerGeneration(t *testing.T) {
	const iterations = 50
	const identity = "admin@trap.example"

	seen := make(map[string]bool, iterations)
	jtis := make(map[string]bool, iterations)
	firstSub := ""

	for i := 0; i < iterations; i++ {
		token, err := honeypot.GenerateFakeJWTForIdentity(honeypot.TrapCaller{Identity: identity})
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}

		if seen[token] {
			t.Fatalf("two mints produced the same token at iteration %d", i)
		}
		seen[token] = true

		claims := honeypotDecodeClaims(t, token)
		sub, _ := claims["sub"].(string)
		jti, _ := claims["jti"].(string)

		if sub == "" {
			t.Fatalf("mint %d carries no sub; a real access token always does", i)
		}
		if firstSub == "" {
			firstSub = sub
		} else if sub != firstSub {
			t.Fatalf("login %d with %q was answered with user id %q, but login 0 was answered with %q",
				i, identity, sub, firstSub)
		}

		if jtis[jti] {
			t.Fatalf("two trap tokens share the token id %q at iteration %d", jti, i)
		}
		jtis[jti] = true
	}

	other, err := honeypot.GenerateFakeJWTForIdentity(honeypot.TrapCaller{Identity: "root@trap.example"})
	if err != nil {
		t.Fatalf("mint for a second identity: %v", err)
	}
	if sub, _ := honeypotDecodeClaims(t, other)["sub"].(string); sub == firstSub {
		t.Errorf("two different trap addresses were answered with the same user id %q", sub)
	}
}

// honeypotDecodeClaims decodes a token's payload segment.
func honeypotDecodeClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not three segments: %q", token)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

// TestHoneypotToken_SignatureLengthRealistic verifies that the fake signature
// has a realistic length for an RS256 signature (256 bytes = 342-344 base64url chars).
func TestHoneypotToken_SignatureLengthRealistic(t *testing.T) {
	fakeToken := hpTrapAccessToken(t, hpService(t, false))

	parts := strings.Split(fakeToken, ".")
	sigB64 := parts[2]

	// RS256 signature is 256 bytes. Base64url encoding of 256 bytes:
	// ceil(256 / 3) * 4 = 344 chars with padding, 342 without
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("Failed to decode fake signature: %v", err)
	}

	if len(sigBytes) != 256 {
		t.Fatalf("Fake signature is %d bytes, expected 256 (RS256 standard)", len(sigBytes))
	}
}

// The trap login's response shape used to be certified against
// honeypot.FakeLoginResponse and honeypot.FakeLoginCookie, neither of which has
// a non-test caller. The live trap path builds its own LoginResult in
// service.Login (internal/service/auth.go), from GenerateFakeJWTForIdentity and
// GenerateFakeRefresh, so the two assertions below moved on to it. They live
// beside the rest of the trap-login suite, after the harness that builds it.

// ---------------------------------------------------------------------------
// The trap login path
//
// The honeypot's deception lives or dies on the login endpoint answering a
// planted credential the way the real vault answers a real one. vault42 is
// public source, so an attacker knows byte for byte what a real answer looks
// like, and docs/bridge.md says the bridge reroutes a flagged caller
// mid-session, so they are holding real samples to compare against.
// ---------------------------------------------------------------------------

const (
	hpTrapEmail  = "planted-admin@trap.example"
	hpRealEmail  = "nobody@trap.example"
	hpAttackerIP = "203.0.113.9"
	hpUserAgent  = "curl/8.6.0"

	// hpAccessTTL is deliberately not honeypot's built-in default of 15 minutes.
	// The trap token's exp comes from the honeypot's published config and the
	// login body's expires_in comes from the token service, and at the default
	// the two agree whether or not anything wired them together — which is a
	// fixture that cannot fail. A distinct value makes the agreement mean
	// something.
	hpAccessTTL = 23 * time.Minute
)

// cmd/vault calls honeypot.ConfigureFakeJWT with the same
// cfg.AccessTokenTTL it hands service.NewTokenService. ConfigureFakeJWT is a
// sync.Once, so this fixture has to publish before any test mints, and an init
// is the only place in a test binary that reliably is. The issuer and audience
// stay at the values the rest of this suite parses against.
func init() {
	honeypot.ConfigureFakeJWT("vault", "vault", hpAccessTTL)
}

// hpCounts records the repository round trips one login made, which is the
// closest a unit test gets to the wall-clock cost an attacker measures.
type hpCounts struct {
	mu                  sync.Mutex
	getByEmail          int
	resetFailedLogin    int
	incrementFailed     int
	setLastLogin        int
	countActiveFamilies int
	deviceLookup        int
	totpLookup          int
}

func (c *hpCounts) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getByEmail + c.resetFailedLogin + c.incrementFailed + c.setLastLogin +
		c.countActiveFamilies + c.deviceLookup + c.totpLookup
}

// hpDeps is everything a constructed AuthService writes through, plus the
// counters and the metrics collector the assertions read back.
type hpDeps struct {
	svc      *service.AuthService
	tokenSvc *service.TokenService
	tokens   *mocks.MockRefreshTokenRepo
	totp     *mocks.MockTOTPRepo
	counts   *hpCounts
	metrics  *metrics.Collector
	cache    *mocks.MockCache
}

// hpService builds an AuthService in the shape the honeypot profile runs in:
// trap users configured, metrics on, a session cap so the session-count query
// is actually issued, and an empty user table, which is what a honeypot
// database looks like.
func hpService(t *testing.T, mfaRequired bool) *hpDeps {
	t.Helper()

	counts := &hpCounts{}
	bump := func(n *int) {
		counts.mu.Lock()
		*n++
		counts.mu.Unlock()
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
			bump(&counts.getByEmail)
			return nil, nil
		},
		ResetFailedLoginFn:     func(_ context.Context, _ string) error { bump(&counts.resetFailedLogin); return nil },
		IncrementFailedLoginFn: func(_ context.Context, _ string) error { bump(&counts.incrementFailed); return nil },
		SetLastLoginFn:         func(_ context.Context, _ string) error { bump(&counts.setLastLogin); return nil },
	}
	tokens := &mocks.MockRefreshTokenRepo{
		CountActiveFamiliesFn: func(_ context.Context, _ string) (int, error) {
			bump(&counts.countActiveFamilies)
			return 0, nil
		},
	}
	devices := &mocks.MockDeviceRepo{
		GetByFingerprintFn: func(_ context.Context, _, _ string) (*model.Device, error) {
			bump(&counts.deviceLookup)
			return nil, nil
		},
	}
	totp := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
			bump(&counts.totpLookup)
			return nil, nil
		},
	}
	appCache := &mocks.MockCache{}

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	tokenSvc := service.NewTokenService(
		key, vaultcrypto.KIDFromPublicKey(&key.PublicKey), "https://vault.test", "https://vault.test",
		hpAccessTTL, 7*24*time.Hour, 30*24*time.Hour,
	)
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{}, 0)
	mfaSvc := service.NewMFAService(totp, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, mfaRequired)

	svc := service.NewAuthService(
		users, tokens, devices, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, mfaSvc, auditLog, service.NewHIBPClient(),
		appCache, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 15, false, nil,
	)
	svc.SetMaxSessionsPerUser(5)
	svc.SetHoneypotAlerter(honeypot.NewAlerter("", []string{hpTrapEmail}, auditLog))

	collector := metrics.NewCollector(
		vaultcrypto.Argon2ActiveCount, vaultcrypto.Argon2RejectedCount, vaultcrypto.Argon2MaxConcurrent,
	)
	svc.SetMetrics(collector)

	return &hpDeps{
		svc: svc, tokenSvc: tokenSvc, tokens: tokens, totp: totp,
		counts: counts, metrics: collector, cache: appCache,
	}
}

// hpScrape reads one counter out of the Prometheus text the /metrics handler
// serves, which is the surface an unauthenticated attacker actually reads.
func hpScrape(t *testing.T, c *metrics.Collector, name string) string {
	t.Helper()

	rec := httptest.NewRecorder()
	c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, name+" ") {
			return strings.TrimSpace(strings.TrimPrefix(line, name+" "))
		}
	}
	t.Fatalf("the scrape carries no %s line:\n%s", name, rec.Body.String())
	return ""
}

// hpTrapAccessToken performs one trap login and returns the access token the
// caller is handed. Every indistinguishability assertion below reads this
// token rather than honeypot.GenerateFakeJWT, which had no caller outside these
// tests and minted for an empty TrapCaller: no client id, and a fingerprint
// derived from the salt instead of computed from the request. Those are two of
// the claims an attacker compares, and the deployment never produces that shape.
func hpTrapAccessToken(t *testing.T, d *hpDeps) string {
	t.Helper()
	res, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever", ClientID: "acme-web",
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("trap login: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("the trap login answered with no access token")
	}
	return res.AccessToken
}

// /metrics is served unauthenticated. An attacker who scrapes it before and
// after a login they believe succeeded reads vault_login_attempts_total move
// while vault_login_success_total stands still, which says the endpoint that
// just returned them a token and a 200 did not consider it a login. Two scrapes
// and one request.
func TestATrapLoginIsCountedAsALoginSuccessInTheMetrics(t *testing.T) {
	d := hpService(t, false)

	before := hpScrape(t, d.metrics, "vault_login_success_total")

	if _, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent); err != nil {
		t.Fatalf("trap login: %v", err)
	}

	after := hpScrape(t, d.metrics, "vault_login_success_total")
	if after == before {
		t.Errorf("vault_login_success_total stayed at %s across a trap login that answered with tokens", before)
	}
	if got := hpScrape(t, d.metrics, "vault_login_attempts_total"); got == "0" {
		t.Error("vault_login_attempts_total did not move either; this test is measuring the wrong thing")
	}
}

// The IP lockout is what makes credential stuffing expensive, and it is applied
// to every caller. A trap check sitting above it left the planted address as the
// one address in the vault that still answers 200 from an IP that is locked out,
// so an attacker burns the lockout with bad logins and then walks their
// candidate list: whichever address still returns tokens is the trap.
func TestATrapLoginIsRefusedWhileTheCallersIPIsLockedOut(t *testing.T) {
	d := hpService(t, false)
	d.cache.GetFn = func(_ context.Context, key string) (string, error) {
		if key == "lockout_ip:"+hpAttackerIP {
			return "99", nil
		}
		return "", cache.ErrNotFound
	}

	_, trapErr := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)
	_, realErr := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpRealEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)

	if !errors.Is(realErr, service.ErrAccountLocked) {
		t.Fatalf("an ordinary address on a locked-out IP answered %v, want ErrAccountLocked; this test is measuring the wrong thing", realErr)
	}
	if !errors.Is(trapErr, service.ErrAccountLocked) {
		t.Errorf("the trap address answered %v from a locked-out IP, where every other address answers ErrAccountLocked", trapErr)
	}
}

// With VAULT_MFA_REQUIRED=true every login in the deployment answers with a
// challenge and no tokens. A trap login that hands tokens straight back is then
// the only login in the system that does, and the attacker does not even need a
// second address to compare against: they know the deployment requires a second
// factor because every other account they try asks for one.
func TestATrapLoginAnswersWithAChallengeWhenTheDeploymentRequiresMFA(t *testing.T) {
	d := hpService(t, true)

	res, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("trap login: %v", err)
	}

	if !res.Requires2FA {
		t.Error("the trap login skipped the second factor every other login in the deployment demands")
	}
	if res.AccessToken != "" {
		t.Error("the trap login answered with an access token where a real one answers with a challenge")
	}
	if res.ChallengeToken == "" {
		t.Error("the trap login answered without a challenge token, so the caller has nothing to verify against")
	}
	if len(res.AvailableMethods) == 0 {
		t.Error("the trap login offered no second-factor methods; a real MFA-required login offers email_otp")
	}
}

// remember_me is what decides the refresh cookie's Max-Age, and the two TTLs are
// far enough apart to read off one response header. A trap path that ignores the
// flag answers a remember_me login with the short cookie, which no real login
// does.
func TestATrapLoginHonorsRememberMeInTheRefreshCookieLifetime(t *testing.T) {
	d := hpService(t, false)

	plain, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("trap login: %v", err)
	}
	remembered, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever", RememberMe: true,
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("trap login with remember_me: %v", err)
	}

	if remembered.CookieMaxAge <= plain.CookieMaxAge {
		t.Errorf("remember_me bought the trap caller a %ds cookie against %ds without it; a real login answers with the longer remember-me lifetime",
			remembered.CookieMaxAge, plain.CookieMaxAge)
	}
}

// The trap login must not be cheaper than a login that fails.
//
// A real deployment does four or more database round trips on a success and one
// or two on a failure, so success is the slower answer. The trap branch did one
// dummy Argon2id and returned, with no round trips at all, which inverted the
// sign: on the honeypot the successful login came back faster than the failed
// one. That is a self-contained oracle. It needs no reference host, no second
// address and no knowledge of the deployment, only a stopwatch and two requests.
func TestATrapLoginCostsAtLeastAsMuchWorkAsAFailedOne(t *testing.T) {
	failed := hpService(t, false)
	if _, err := failed.svc.Login(context.Background(), service.LoginInput{
		Email: hpRealEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent); err == nil {
		t.Fatal("a login for an address that is not in the database succeeded; this test is measuring the wrong thing")
	}
	failedTrips := failed.counts.total()

	trap := hpService(t, false)
	if _, err := trap.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent); err != nil {
		t.Fatalf("trap login: %v", err)
	}
	trapTrips := trap.counts.total()

	if failedTrips == 0 {
		t.Fatal("a failed login made no repository calls at all; this test is measuring the wrong thing")
	}
	if trapTrips <= failedTrips {
		t.Errorf("the trap login made %d repository round trips against %d for a failed login, so success is the cheaper answer on the honeypot and the reverse on every real deployment",
			trapTrips, failedTrips)
	}
}

// The individual round trips a successful login is made of, named one at a time
// so a regression says which one went missing rather than only that the total
// moved. Each is a query the honeypot's own database can answer for a user id
// that is not in it, so none of them writes a row or fails a foreign key.
func TestATrapLoginMakesTheRoundTripsASuccessfulLoginMakes(t *testing.T) {
	d := hpService(t, false)

	if _, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent); err != nil {
		t.Fatalf("trap login: %v", err)
	}

	d.counts.mu.Lock()
	defer d.counts.mu.Unlock()
	for _, probe := range []struct {
		name string
		got  int
	}{
		{"the address lookup every login begins with", d.counts.getByEmail},
		{"the failed-login counter reset a success does", d.counts.resetFailedLogin},
		{"the second-factor status lookup", d.counts.totpLookup},
		{"the active-session count", d.counts.countActiveFamilies},
		{"the device lookup", d.counts.deviceLookup},
		{"the last-login stamp", d.counts.setLastLogin},
	} {
		if probe.got == 0 {
			t.Errorf("the trap login skipped %s, so it answers faster than a real success does", probe.name)
		}
	}
}

// A trap address that has a second factor enrolled must be offered that factor,
// not the email fallback. A honeypot whose planted account always answers
// "email_otp" whatever it has enrolled is answering from a branch the real login
// does not have.
func TestATrapLoginOffersTheFactorsTheTrapAccountHasEnrolled(t *testing.T) {
	d := hpService(t, false)
	d.totp.GetByUserIDFn = func(_ context.Context, userID string) (*model.TOTPSecret, error) {
		return &model.TOTPSecret{UserID: userID, Verified: true}, nil
	}

	res, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("trap login: %v", err)
	}

	if !res.Requires2FA {
		t.Fatal("the trap account has a factor enrolled and the login did not challenge for it")
	}
	if len(res.AvailableMethods) == 0 || res.AvailableMethods[0] != "totp" {
		t.Errorf("the trap login offered %v, want the enrolled factor", res.AvailableMethods)
	}
}

// Key rotation can leave a pod with a nil private key, and every flow that mints
// a JWT has an error return for it. The trap's challenge is no different: it must
// fail closed rather than answer with an empty challenge token the caller cannot
// use, which is a response no real deployment ever produces.
func TestATrapChallengeFailsClosedWhenTheSigningKeyIsUnusable(t *testing.T) {
	d := hpService(t, true)
	d.tokenSvc.UpdateSigningKey(nil, "")

	res, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)
	if err == nil {
		t.Fatalf("the trap answered %+v with an unusable signing key", res)
	}
	if !strings.Contains(err.Error(), "issue 2FA challenge") {
		t.Errorf("err = %v, want it to name the challenge that could not be signed", err)
	}
}

// The session cap applies to every account. A trap login that ignored it would
// be the one address in the deployment that can open an unlimited number of
// sessions, which an attacker finds by opening a few more than the cap allows.
func TestATrapLoginIsRefusedWhenTheSessionCapIsAlreadyReached(t *testing.T) {
	d := hpService(t, false)
	d.svc.SetMaxSessionsPerUser(1)
	d.tokens.CountActiveFamiliesFn = func(_ context.Context, _ string) (int, error) {
		return 5, nil
	}

	if _, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent); !errors.Is(err, service.ErrTooManySessions) {
		t.Errorf("the trap answered %v with the session cap already reached, want ErrTooManySessions", err)
	}
}

// VAULT_MAX_SESSION_LIFETIME bounds how long any refresh family may live, and a
// real login clamps the cookie it answers with to it. A trap cookie that
// outlived the deployment's own bound would say the trap is not subject to the
// policy the rest of the vault is.
func TestATrapRefreshCookieIsClampedToTheAbsoluteSessionLifetime(t *testing.T) {
	d := hpService(t, false)
	const bound = 2 * time.Hour
	d.tokenSvc.SetMaxSessionLifetime(bound)

	res, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever", RememberMe: true,
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("trap login: %v", err)
	}

	if got := time.Duration(res.CookieMaxAge) * time.Second; got != bound {
		t.Errorf("the trap answered with a %s cookie where the deployment bounds every session at %s", got, bound)
	}
}

// The response's stated lifetime has to agree with the lifetime inside the
// token it wraps. They come from two different places — expires_in from the
// token service's access TTL, exp from the honeypot's own published config — and
// a deployment that sets VAULT_ACCESS_TOKEN_TTL without reaching
// honeypot.ConfigureFakeJWT makes them disagree. That is a tell read off one
// response with no second request and no reference host.
//
// The orphan this replaces, honeypot.FakeLoginResponse, computed expires_in from
// the honeypot config, so it agreed with the token by construction and could not
// have caught the disagreement on the path that ships.
func TestATrapLoginQuotesTheLifetimeItsOwnTokenCarries(t *testing.T) {
	d := hpService(t, false)

	res, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("trap login: %v", err)
	}

	if res.TokenType != "Bearer" {
		t.Errorf("trap login answered token_type %q, want Bearer", res.TokenType)
	}
	parts := strings.Split(res.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("trap access_token has %d dot-separated parts, want 3", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode trap token payload: %v", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal trap token payload: %v", err)
	}
	if claims.Exp == 0 || claims.Iat == 0 {
		t.Fatalf("trap token carries exp=%d iat=%d; a real access token carries both", claims.Exp, claims.Iat)
	}

	if tokenLifetime := claims.Exp - claims.Iat; tokenLifetime != int64(res.ExpiresIn) {
		t.Errorf("the trap login said expires_in=%d and handed over a token that lives %ds; "+
			"a response whose stated lifetime disagrees with the token inside it is read off one request",
			res.ExpiresIn, tokenLifetime)
	}
}

// The refresh token the trap sets as a cookie has to be indistinguishable from
// the real one, which is crypto.RandomToken(32) — 64 lowercase hex characters.
// Anything else is a tell in a value the attacker is handed on every login.
func TestATrapRefreshTokenIsTheShapeARealOneIs(t *testing.T) {
	d := hpService(t, false)

	res, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("trap login: %v", err)
	}

	genuine, err := vaultcrypto.RandomToken(32)
	if err != nil {
		t.Fatalf("mint a real refresh token to compare against: %v", err)
	}
	if len(res.RefreshToken) != len(genuine) {
		t.Fatalf("the trap refresh token is %d characters against a real one's %d",
			len(res.RefreshToken), len(genuine))
	}
	for _, c := range res.RefreshToken {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("the trap refresh token contains %q, which lowercase hex does not: %s",
				c, res.RefreshToken)
		}
	}

	second, err := d.svc.Login(context.Background(), service.LoginInput{
		Email: hpTrapEmail, Password: "whatever",
	}, hpAttackerIP, hpUserAgent)
	if err != nil {
		t.Fatalf("second trap login: %v", err)
	}
	if second.RefreshToken == res.RefreshToken {
		t.Error("two trap logins handed over the same refresh token")
	}
}
