package compliance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// OWASP ASVS 5.0.0 — Authentication group (V6) and Authorization (V8)
//
// These tests replace four register entries whose named tests were found to be
// vacuous or adjacent by the register audit:
//   - V6.4.2 was "proven" by constructing VaultClaims and asserting Subject!="".
//   - V6.6.2 was "proven" by rejecting five hard-coded TOTP strings (TOTP is
//     in-band; the clause is about OUT-OF-BAND binding).
//   - V6.2.2 was "proven" by a password-HISTORY repository test that never
//     invoked the change-password flow.
//   - V8.2.2 (authorization) was "proven" by an encryption-at-rest test that
//     exercised no access decision.
//
// Each test here drives the real shipped mechanism end to end.
// =============================================================================

// --- V6.4.2: No knowledge-based / secret-question authentication anywhere -----

// forbiddenKBAPhrases are the multi-word markers of knowledge-based
// authentication and password hints. They are phrases rather than bare tokens
// (e.g. "kba") on purpose: a bare token collides with ordinary identifiers such
// as "mockBackup", producing false positives that would make the scan either
// noisy or, once suppressed, meaningless.
var forbiddenKBAPhrases = []string{
	"security question",
	"securityquestion",
	"security_question",
	"secret question",
	"secretquestion",
	"secret_question",
	"knowledge-based",
	"knowledge based",
	"knowledgebased",
	"challenge question",
	"challenge_question",
	"recovery question",
	"recovery_question",
	"personal question",
	"maiden name",
	"maidenname",
	"maiden_name",
	"memorable word",
	"memorable_word",
	"password hint",
	"passwordhint",
	"password_hint",
	"first pet",
}

// TestASVSAuth_V6_4_2_NoKnowledgeBasedSecrets asserts that no password hints or
// knowledge-based "secret questions" exist anywhere in the shipped surface:
// production Go (handlers/services/config/schema types), the SQL migrations
// (the account schema), and the HTTP route table. This is an absence property,
// so it is only meaningful if the scan is proven to actually read the real
// surface — hence the anchor and floor assertions below. Were a secret-question
// endpoint, column, or config field added tomorrow, this would fail.
func TestASVSAuth_V6_4_2_NoKnowledgeBasedSecrets(t *testing.T) {
	root := repoRoot(t)

	type scanned struct {
		path    string
		lower   string
		content string
	}
	var files []scanned

	// 1. Production Go source (excluding tests, mocks, and the compiled SPA).
	for _, sub := range []string{"internal", "cmd"} {
		base := filepath.Join(root, sub)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if name == "testdata" || name == "mocks" || name == "dist" || name == "frontend" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path) // #nosec G304 -- walking the repo's own source tree
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			files = append(files, scanned{path: filepath.ToSlash(rel), lower: strings.ToLower(string(b)), content: string(b)})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}

	// 2. SQL migrations — the account/auth schema. A secret-question feature
	//    would need a column here.
	migDir := filepath.Join(root, "migrations")
	migCount := 0
	err := filepath.WalkDir(migDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 -- walking the repo's own migrations
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		files = append(files, scanned{path: filepath.ToSlash(rel), lower: strings.ToLower(string(b)), content: string(b)})
		migCount++
		return nil
	})
	if err != nil {
		t.Fatalf("walk migrations: %v", err)
	}

	// 3. The HTTP route table.
	routeBytes, err := os.ReadFile(filepath.Join(root, "internal", "server", "server.go")) // #nosec G304 -- repo's own route file
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	routeSrc := string(routeBytes)
	files = append(files, scanned{path: "internal/server/server.go", lower: strings.ToLower(routeSrc), content: routeSrc})

	// --- Meaningfulness guards: prove the scan read the real surface. ---
	if len(files) < 150 {
		t.Fatalf("V6.4.2: scan collected only %d files; the walk is broken and the absence claim would be vacuous", len(files))
	}
	if migCount < 10 {
		t.Fatalf("V6.4.2: only %d migrations scanned; the schema walk is broken", migCount)
	}
	// The route file must actually contain the known auth surface, proving the
	// scan sees live route strings and would see a secret-question route.
	for _, anchor := range []string{"/auth/password/reset", "/auth/login", "/user/password"} {
		if !strings.Contains(routeSrc, anchor) {
			t.Fatalf("V6.4.2: route anchor %q missing; the route scan is not reading server.go", anchor)
		}
	}

	// --- The absence assertion. ---
	for _, f := range files {
		for _, phrase := range forbiddenKBAPhrases {
			if strings.Contains(f.lower, phrase) {
				idx := strings.Index(f.lower, phrase)
				start := idx - 40
				if start < 0 {
					start = 0
				}
				end := idx + len(phrase) + 40
				if end > len(f.content) {
					end = len(f.content)
				}
				t.Errorf("V6.4.2: knowledge-based-secret marker %q found in %s: ...%s...",
					phrase, f.path, strings.ReplaceAll(f.content[start:end], "\n", " "))
			}
		}
	}

	// The recovery mechanism that DOES ship must be the token-based reset (not a
	// secret question). Confirm it is present so "no secret questions" does not
	// silently mean "no account recovery at all".
	if !strings.Contains(routeSrc, "/auth/password/reset") {
		t.Fatal("V6.4.2: token-based password reset route absent")
	}
}

// --- V6.6.2: Out-of-band auth codes bound to the original request ------------

// asvsAuthEmailOTPService builds a real AuthService wired for the email-OTP
// fallback path (MFA required, no stronger factor enrolled — the exact gate at
// internal/service/auth.go where the OOB email code is minted and bound). The
// cache is the real in-memory implementation so GetAndDelete single-use
// semantics are genuine.
func asvsAuthEmailOTPService(t *testing.T, hmacSecret []byte, capture *mocks.MockEmailSender) (*service.AuthService, *cache.MemoryCache) {
	t.Helper()
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := service.NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)
	mem := cache.NewMemoryCache()

	// Email-OTP is only a permitted factor for an account with NO stronger
	// enrolled method when MFA is required. Model exactly that.
	mfaSvc := service.NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, true)

	svc := service.NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, mfaSvc, auditLogger, service.NewHIBPClient(),
		mem, capture, "https://vault.test", "TestVault",
		"", 15, false, hmacSecret,
	)
	return svc, mem
}

var asvsAuthSixDigits = regexp.MustCompile(`\b\d{6}\b`)

// TestASVSAuth_V6_6_2_EmailOTPBoundToOriginalRequest exercises the real
// out-of-band email-OTP binding two ways:
//
//  1. Subject binding: an OOB code minted for subject A's authentication cannot
//     complete a different subject B's authentication — the code is keyed to the
//     original request's subject (cache key "email_otp:<userID>"). This drives
//     the shipped SendEmailOTP -> VerifyEmailOTP path with a real cache, and
//     captures the actual emailed code (not a hard-coded string).
//  2. Device binding: the 2FA challenge issued for the original request carries
//     that request's device fingerprint; a redemption from a different device is
//     rejected (ChallengeFingerprintMatches).
//
// Together these are the "bound to the original request" property of V6.6.2.
func TestASVSAuth_V6_6_2_EmailOTPBoundToOriginalRequest(t *testing.T) {
	hmacSecret := []byte("asvsauth-v662-oob-binding-secret")

	var mu sync.Mutex
	var capturedBody string
	sender := &mocks.MockEmailSender{
		SendFn: func(_ context.Context, _, _, _, textBody string) error {
			mu.Lock()
			capturedBody = textBody
			mu.Unlock()
			return nil
		},
	}

	svc, mem := asvsAuthEmailOTPService(t, hmacSecret, sender)
	defer mem.Close()
	ctx := context.Background()

	const subjectA = "user-alice-0000-0000-000000000001"
	const subjectB = "user-bob-0000-0000-0000-000000000002"

	// The original authentication request mints and delivers the OOB code for
	// subject A. This stores HMAC(code) at "email_otp:user-alice...".
	if err := svc.SendEmailOTP(ctx, subjectA, "alice@vault.test"); err != nil {
		t.Fatalf("V6.6.2: SendEmailOTP for original subject failed: %v", err)
	}

	mu.Lock()
	body := capturedBody
	mu.Unlock()
	code := asvsAuthSixDigits.FindString(body)
	if code == "" {
		t.Fatalf("V6.6.2: could not recover the emailed OTP from the delivered body: %q", body)
	}

	// (1a) The OOB code, presented for a DIFFERENT subject, is refused. The code
	// is bound to the original request's subject, so it cannot authenticate B.
	if err := svc.VerifyEmailOTP(ctx, subjectB, code); err == nil {
		t.Fatal("V6.6.2: OOB code minted for subject A was accepted for subject B — code is not bound to the original request")
	}

	// (1b) The same code, presented for the ORIGINAL subject, is accepted.
	if err := svc.VerifyEmailOTP(ctx, subjectA, code); err != nil {
		t.Fatalf("V6.6.2: OOB code was rejected for its original subject: %v", err)
	}

	// (1c) Single-use: a replay for the original subject is refused (the binding
	// is consumed atomically via GetAndDelete).
	if err := svc.VerifyEmailOTP(ctx, subjectA, code); err == nil {
		t.Fatal("V6.6.2: OOB code was accepted a second time — it is not single-use")
	}

	// (2) Device binding of the challenge issued alongside the OOB code. The
	// original request's fingerprint is embedded in the 2FA challenge; a
	// redemption from a different device fingerprint is rejected.
	original := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "203.0.113.7", UserAgent: "Mozilla/5.0 original-device", AcceptLanguage: "en-US",
	})
	attacker := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "198.51.100.9", UserAgent: "curl/8.0 other-device", AcceptLanguage: "en-US",
	})
	if !svc.ChallengeFingerprintMatches(ctx, subjectA, original, original, "203.0.113.7", "Mozilla/5.0 original-device") {
		t.Fatal("V6.6.2: challenge redemption from the ORIGINAL device was rejected")
	}
	if svc.ChallengeFingerprintMatches(ctx, subjectA, original, attacker, "198.51.100.9", "curl/8.0 other-device") {
		t.Fatal("V6.6.2: challenge redemption from a DIFFERENT device was accepted — not bound to the original request")
	}
}

// --- V6.2.2: A user can change their password --------------------------------

// TestASVSAuth_V6_2_2_UserCanChangePassword drives the real change-password
// handler (POST /user/password -> PasswordHandler.ChangePassword) end to end:
// an authenticated user supplies their current password plus a new one, and the
// handler verifies the current secret, stores the new hash, records history, and
// revokes existing sessions. The old register entry never invoked this handler.
func TestASVSAuth_V6_2_2_UserCanChangePassword(t *testing.T) {
	const pepper = "asvsauth-v622-pepper"
	const userID = "user-carol-0000-0000-000000000003"
	const currentPassword = "correct-horse-battery-staple-1"
	const newPassword = "brand-new-passphrase-xyzzy-9876"

	currentHash, err := vaultcrypto.HashPassword(currentPassword, pepper)
	if err != nil {
		t.Fatalf("hash current password: %v", err)
	}

	// Track the stored hash and whether sessions were revoked.
	storedHash := currentHash
	var updateCalled, revokeCalled bool
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			if id != userID {
				return nil, nil
			}
			return &model.User{ID: userID, Email: "carol@vault.test", PasswordHash: storedHash}, nil
		},
		UpdatePasswordFn: func(_ context.Context, id, hash string) error {
			updateCalled = true
			storedHash = hash
			return nil
		},
	}
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(_ context.Context, id string) error {
			if id == userID {
				revokeCalled = true
			}
			return nil
		},
	}
	pwHistory := &mocks.MockPasswordHistoryRepo{}
	auditLogger := audit.NewLogger(&mocks.MockAuditRepo{}, 0)
	mem := cache.NewMemoryCache()
	defer mem.Close()

	h := handler.NewPasswordHandler(
		users, pwHistory, tokens, &mocks.MockEmailSender{},
		auditLogger, mem, "https://vault.test", "TestVault", pepper,
		15, nil, false,
	)

	body := `{"current_password":"` + currentPassword + `","new_password":"` + newPassword + `"}`
	req := httptest.NewRequest(http.MethodPost, "/user/password", strings.NewReader(body))
	claims := &vaultcrypto.VaultClaims{RegisteredClaims: vjwt.RegisteredClaims{Subject: userID}}
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("V6.2.2: change-password returned %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "password_changed") {
		t.Fatalf("V6.2.2: response did not report password_changed: %s", rec.Body.String())
	}
	if !updateCalled {
		t.Fatal("V6.2.2: handler returned success without persisting the new password")
	}
	if !revokeCalled {
		t.Fatal("V6.2.2: password change did not revoke existing sessions")
	}

	// The change is real: the stored hash now verifies the NEW password and no
	// longer the old one.
	okNew, _ := vaultcrypto.VerifyPassword(newPassword, storedHash, pepper)
	if !okNew {
		t.Fatal("V6.2.2: stored hash does not verify the new password after change")
	}
	okOld, _ := vaultcrypto.VerifyPassword(currentPassword, storedHash, pepper)
	if okOld {
		t.Fatal("V6.2.2: stored hash still verifies the OLD password after change")
	}

	// Negative control: the same handler rejects a change when the current
	// password is wrong, proving the success above went through verification.
	badBody := `{"current_password":"totally-wrong-current","new_password":"another-fresh-pass-3344"}`
	badReq := httptest.NewRequest(http.MethodPost, "/user/password", strings.NewReader(badBody))
	badReq = badReq.WithContext(context.WithValue(badReq.Context(), middleware.ClaimsKey, claims))
	badRec := httptest.NewRecorder()
	h.ChangePassword(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("V6.2.2: wrong current password returned %d, want 401", badRec.Code)
	}
}

// --- V8.2.2: Data-specific authorization -------------------------------------

// asvsAuthBlobRepo is a faithful in-memory BlobRepository. Its
// GetByIDAndPseudonym reproduces exactly the access decision the Postgres repo
// makes ("WHERE id=$1 AND pseudonym_id=$2"): a blob is returned only when the
// requesting pseudonym owns that specific id. It is the real access-decision
// layer, not a stub that always answers.
type asvsAuthBlobRepo struct {
	mu    sync.Mutex
	blobs map[string]*model.Blob // keyed by blob ID
}

func newASVSAuthBlobRepo() *asvsAuthBlobRepo {
	return &asvsAuthBlobRepo{blobs: make(map[string]*model.Blob)}
}

func (r *asvsAuthBlobRepo) Create(_ context.Context, blob *model.Blob) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *blob
	r.blobs[blob.ID] = &cp
	return nil
}

func (r *asvsAuthBlobRepo) GetByIDAndPseudonym(_ context.Context, id, pseudonymID string) (*model.Blob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.blobs[id]
	if !ok || b.PseudonymID != pseudonymID {
		// Not found OR not owned by this pseudonym -> access denied (nil,nil is
		// the repository's "no such row for you" contract).
		return nil, nil
	}
	cp := *b
	return &cp, nil
}

func (r *asvsAuthBlobRepo) GetByRefAndPseudonym(_ context.Context, refHash, pseudonymID string) (*model.Blob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.blobs {
		if b.RefHash == refHash && b.PseudonymID == pseudonymID {
			cp := *b
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *asvsAuthBlobRepo) DeleteByRefAndPseudonym(_ context.Context, refHash, pseudonymID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, b := range r.blobs {
		if b.RefHash == refHash && b.PseudonymID == pseudonymID {
			delete(r.blobs, id)
		}
	}
	return nil
}

func (r *asvsAuthBlobRepo) ListByPseudonym(_ context.Context, pseudonymID string) ([]*model.Blob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*model.Blob
	for _, b := range r.blobs {
		if b.PseudonymID == pseudonymID {
			cp := *b
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *asvsAuthBlobRepo) GetQuota(_ context.Context, pseudonymID string) (*model.BlobQuota, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := &model.BlobQuota{}
	for _, b := range r.blobs {
		if b.PseudonymID == pseudonymID {
			q.UsedCount++
			q.UsedBytes += b.StoredBytes
		}
	}
	return q, nil
}

func (r *asvsAuthBlobRepo) Delete(_ context.Context, id, pseudonymID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.blobs[id]
	if !ok || b.PseudonymID != pseudonymID {
		return nil
	}
	delete(r.blobs, id)
	return nil
}

func (r *asvsAuthBlobRepo) DeleteAllForPseudonym(_ context.Context, pseudonymID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, b := range r.blobs {
		if b.PseudonymID == pseudonymID {
			delete(r.blobs, id)
		}
	}
	return nil
}

// TestASVSAuth_V8_2_2_BlobAccessDeniedWithoutPermission exercises the shipped
// data-specific access decision (BlobService.Download -> repo
// GetByIDAndPseudonym). A consumer without permission to a specific data item
// (a different user) is denied that item, while the owner reads it back
// verbatim. This is an authorization property, distinct from the
// encryption-at-rest test the register previously cited.
func TestASVSAuth_V8_2_2_BlobAccessDeniedWithoutPermission(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	hmacSecret := []byte("asvsauth-v822-blob-hmac-secret-0")

	repo := newASVSAuthBlobRepo()
	svc := service.NewBlobService(repo, masterKey, hmacSecret, service.BlobConfig{
		MinBlobSize:     0,
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
	ctx := context.Background()

	const owner = "user-dave-0000-0000-0000-000000000004"
	const outsider = "user-erin-0000-0000-000000000005"
	secret := []byte("dave's private object contents — not for erin")

	blob, err := svc.Upload(ctx, owner, secret, "dave-label")
	if err != nil {
		t.Fatalf("V8.2.2: owner upload failed: %v", err)
	}
	if blob.ID == "" {
		t.Fatal("V8.2.2: upload returned no blob id")
	}

	// The owner (a consumer WITH permission to this specific item) reads it back.
	got, label, _, err := svc.Download(ctx, owner, blob.ID)
	if err != nil {
		t.Fatalf("V8.2.2: owner download failed: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("V8.2.2: owner got wrong data: %q", string(got))
	}
	if label != "dave-label" {
		t.Fatalf("V8.2.2: owner got wrong label: %q", label)
	}

	// A different user (a consumer WITHOUT permission to this specific item)
	// requests the exact same blob ID and is denied: no data is returned. The
	// denial is the pseudonym-scoped access decision, NOT mere absence — the row
	// demonstrably exists and is readable by its owner above.
	leaked, _, _, err := svc.Download(ctx, outsider, blob.ID)
	if err == nil && len(leaked) > 0 {
		t.Fatalf("V8.2.2: non-owner obtained %d bytes of another user's data item", len(leaked))
	}
	if len(leaked) != 0 {
		t.Fatalf("V8.2.2: non-owner received %d bytes; expected zero", len(leaked))
	}

	// Cross-check the mechanism directly: the two users resolve to different
	// pseudonyms, which is what scopes every repository access.
	if svc.Pseudonym(owner) == svc.Pseudonym(outsider) {
		t.Fatal("V8.2.2: distinct users collapsed to the same pseudonym; access scoping is broken")
	}
	if _, ownerOK, err := repoHas(ctx, repo, blob.ID, svc.Pseudonym(owner)); err != nil || !ownerOK {
		t.Fatal("V8.2.2: owner pseudonym cannot see its own row")
	}
	if _, outsiderOK, err := repoHas(ctx, repo, blob.ID, svc.Pseudonym(outsider)); err != nil || outsiderOK {
		t.Fatal("V8.2.2: outsider pseudonym can see a row it does not own")
	}
}

// repoHas reports whether the access-scoped lookup returns a row for the given
// (id, pseudonym) pair — the exact decision the download path relies on.
func repoHas(ctx context.Context, repo *asvsAuthBlobRepo, id, pseudonym string) (*model.Blob, bool, error) {
	b, err := repo.GetByIDAndPseudonym(ctx, id, pseudonym)
	return b, b != nil, err
}
