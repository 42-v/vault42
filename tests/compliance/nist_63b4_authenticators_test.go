package compliance

import (
	"context"
	"encoding/hex"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// NIST SP 800-63B-4 authenticator-type and lifecycle clauses proven against
// the shipped code rather than an adjacent test.
//
//   - §2.2.2  AAL2 requires two distinct factors (service.AALForMethods, the
//     §5.2.4 combination rules the product ships).
//   - §3.1.3  Out-of-band device: the email OTP is bound to the authentication
//     request that produced it and expires (service.SendEmailOTP).
//   - §3.2.12 Random values come from an approved DRBG (internal/crypto/random.go
//     draws from crypto/rand.Reader; no seeded PRNG is present).
//   - §4.4    The ephemeral authenticators (WebAuthn assertion ceremony, email
//     OTP) carry a finite lifetime and cannot be used after it.
// =============================================================================

// capturedOTPSet records the cache write that SendEmailOTP performs for the
// out-of-band code, so a test can assert both what key it is bound to and the
// expiry it is written with.
type capturedOTPSet struct {
	called bool
	key    string
	ttl    time.Duration
}

// emailOTPServiceWithCaptureCache builds a real AuthService whose cache records
// the out-of-band SET. Email OTP is only permitted for an account with no
// stronger enrolled factor when MFA is required, so the MFA service is modeled
// exactly that way (empty factor repositories, required=true).
func emailOTPServiceWithCaptureCache(t *testing.T, captured *capturedOTPSet, hmacSecret []byte) *service.AuthService {
	t.Helper()

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("kid: %v", err)
	}
	tokenSvc := service.NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)
	mfaSvc := service.NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, true)

	cacheMock := &mocks.MockCache{
		SetFn: func(_ context.Context, k, _ string, ttl time.Duration) error {
			captured.called = true
			captured.key = k
			captured.ttl = ttl
			return nil
		},
	}
	sender := &mocks.MockEmailSender{
		SendFn: func(_ context.Context, _, _, _, _ string) error { return nil },
	}

	return service.NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, mfaSvc, auditLogger, service.NewHIBPClient(),
		cacheMock, sender, "https://vault.test", "TestVault",
		"", 15, false, hmacSecret,
	)
}

// TestNIST63B4_2_2_2_AAL2RequiresTwoDistinctFactors proves the core AAL2
// requirement (§2.2.2): reaching AAL2 requires two distinct authentication
// factors. It drives the shipped combination rules (service.AALForMethods,
// §5.2.4): a single factor never reaches AAL2, a memorized secret plus a second
// factor does, and a phishing-resistant authenticator reaches AAL3.
func TestNIST63B4_2_2_2_AAL2RequiresTwoDistinctFactors(t *testing.T) {
	if got := service.AALForMethods([]string{service.MethodPassword}, false); got != service.AAL1 {
		t.Fatalf("§2.2.2: password alone reached AAL%d, want AAL1; a single factor must not satisfy AAL2", got)
	}
	if got := service.AALForMethods([]string{service.MethodTOTP}, false); got != service.AAL1 {
		t.Fatalf("§2.2.2: a lone OTP factor reached AAL%d, want AAL1", got)
	}
	if got := service.AALForMethods([]string{service.MethodPassword, service.MethodTOTP}, false); got != service.AAL2 {
		t.Fatalf("§2.2.2: password+TOTP reached AAL%d, want AAL2", got)
	}
	if got := service.AALForMethods([]string{service.MethodPassword, service.MethodEmailOTP}, false); got != service.AAL2 {
		t.Fatalf("§2.2.2: password+email-OTP reached AAL%d, want AAL2", got)
	}
	// §5.1.7 / §5.2.4: a WebAuthn assertion is a multi-factor cryptographic
	// device only when the authenticator verified the user. With UV clear it
	// proves possession of a key and nothing else, so it is one factor and
	// cannot reach AAL2 on its own, let alone AAL3.
	if got := service.AALForMethods([]string{service.MethodWebAuthn}, true); got != service.AAL3 {
		t.Fatalf("§2.2.2: user-verified WebAuthn reached AAL%d, want AAL3 (phishing-resistant MFA)", got)
	}
	if got := service.AALForMethods([]string{service.MethodWebAuthn}, false); got != service.AAL1 {
		t.Fatalf("§2.2.2: WebAuthn without user verification reached AAL%d, want AAL1; possession alone is one factor", got)
	}
	if got := service.AALForMethods([]string{service.MethodPassword, service.MethodWebAuthn}, false); got != service.AAL2 {
		t.Fatalf("§2.2.2: password + unverified WebAuthn reached AAL%d, want AAL2", got)
	}
	if got := service.AALForMethods(nil, false); got == service.AAL2 || got == service.AAL3 {
		t.Fatalf("§2.2.2: an empty factor set reached AAL%d, must be below AAL2", got)
	}
}

// TestNIST63B4_3_1_3_OutOfBandEmailOTPBindsToRequestAndExpires proves the
// out-of-band device clause (§3.1.3) against the shipped SendEmailOTP path: the
// one-time code is bound to the authenticating subject (cache key
// "email_otp:<userID>", so a code minted for one request cannot complete
// another) and is written with a finite expiry so it cannot be used
// indefinitely. The complementary verify round-trip and single-use property are
// covered by TestASVSAuth_V6_6_2_EmailOTPBoundToOriginalRequest.
func TestNIST63B4_3_1_3_OutOfBandEmailOTPBindsToRequestAndExpires(t *testing.T) {
	const subject = "user-oob-0000-0000-000000000042"
	captured := &capturedOTPSet{}
	svc := emailOTPServiceWithCaptureCache(t, captured, []byte("nist-3-1-3-out-of-band-secret"))

	if err := svc.SendEmailOTP(context.Background(), subject, "oob@vault.test"); err != nil {
		t.Fatalf("§3.1.3: SendEmailOTP failed: %v", err)
	}
	if !captured.called {
		t.Fatal("§3.1.3: SendEmailOTP did not persist an out-of-band code")
	}
	if captured.key != "email_otp:"+subject {
		t.Fatalf("§3.1.3: OOB code is not bound to the authenticating subject: key=%q, want email_otp:%s", captured.key, subject)
	}
	if captured.ttl <= 0 {
		t.Fatalf("§3.1.3: OOB code stored without an expiry (ttl=%v); it must not be usable indefinitely", captured.ttl)
	}
	if captured.ttl != 5*time.Minute {
		t.Fatalf("§3.1.3: OOB code expiry changed from the shipped 5m window: %v", captured.ttl)
	}
}

// TestNIST63B4_3_2_12_RandomSourceIsApprovedDRBG proves that random values come
// from an approved DRBG (§3.2.12). Output uniqueness alone cannot distinguish an
// approved generator from a well-seeded non-approved one, so this inspects the
// source primitive directly: internal/crypto/random.go must draw from
// crypto/rand.Reader and must not import a seeded PRNG (math/rand). It then
// exercises the generators to confirm they produce well-formed output.
func TestNIST63B4_3_2_12_RandomSourceIsApprovedDRBG(t *testing.T) {
	path := filepath.Join(repoRoot(t), "internal", "crypto", "random.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse random.go: %v", err)
	}
	imports := map[string]bool{}
	for _, imp := range f.Imports {
		imports[strings.Trim(imp.Path.Value, `"`)] = true
	}
	if !imports["crypto/rand"] {
		t.Fatal("§3.2.12: random.go does not import crypto/rand, so the approved-DRBG claim is unbacked")
	}
	if imports["math/rand"] || imports["math/rand/v2"] {
		t.Fatal("§3.2.12: random.go imports a seeded, non-approved PRNG (math/rand)")
	}

	src := readProductionSource(t, "internal/crypto/random.go")
	if !strings.Contains(src, "rand.Reader") {
		t.Fatal("§3.2.12: random.go does not read from crypto/rand.Reader")
	}

	b, err := vaultcrypto.RandomBytes(32)
	if err != nil || len(b) != 32 {
		t.Fatalf("§3.2.12: RandomBytes(32) = %d bytes, err=%v", len(b), err)
	}
	uuid, err := vaultcrypto.RandomUUID()
	if err != nil || len(uuid) != 36 || uuid[14] != '4' {
		t.Fatalf("§3.2.12: RandomUUID() = %q, err=%v (want a 36-char v4 UUID)", uuid, err)
	}
	hexStr, err := vaultcrypto.RandomHex(16)
	if err != nil || len(hexStr) != 32 {
		t.Fatalf("§3.2.12: RandomHex(16) = %q, err=%v (want 32 hex chars)", hexStr, err)
	}
	if _, err := hex.DecodeString(hexStr); err != nil {
		t.Fatalf("§3.2.12: RandomHex output is not valid hex: %v", err)
	}
}

// TestNIST63B4_4_4_EphemeralAuthenticatorsExpire proves the expiration clause
// (§4.4) for the authenticators that carry a lifetime. The persistent
// authenticators (password, TOTP, passkey) deliberately do not expire on a
// timer, which the register records; the ephemeral ones do. The WebAuthn
// assertion ceremony (its challenge is answerable only within a bounded window)
// and the out-of-band email code (written with a finite TTL) are both checked to
// carry a short, finite lifetime so a stale one cannot be used.
func TestNIST63B4_4_4_EphemeralAuthenticatorsExpire(t *testing.T) {
	if handler.WebAuthnCeremonyTTL <= 0 {
		t.Fatalf("§4.4: the WebAuthn assertion ceremony has no expiry window: %v", handler.WebAuthnCeremonyTTL)
	}
	if handler.WebAuthnCeremonyTTL > time.Hour {
		t.Fatalf("§4.4: the WebAuthn ceremony window is not bounded to a short lifetime: %v", handler.WebAuthnCeremonyTTL)
	}

	captured := &capturedOTPSet{}
	svc := emailOTPServiceWithCaptureCache(t, captured, []byte("nist-4-4-expiration-secret"))
	if err := svc.SendEmailOTP(context.Background(), "user-exp-0000-0000-000000000007", "exp@vault.test"); err != nil {
		t.Fatalf("§4.4: SendEmailOTP failed: %v", err)
	}
	if !captured.called || captured.ttl <= 0 {
		t.Fatalf("§4.4: the out-of-band authenticator was stored without a finite expiry (called=%v ttl=%v)", captured.called, captured.ttl)
	}
	if captured.ttl > time.Hour {
		t.Fatalf("§4.4: the out-of-band authenticator lifetime is not bounded to a short window: %v", captured.ttl)
	}
}
