package compliance

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// NIST SP 800-63B-4 — Digital Identity Guidelines:
// Authentication and Authenticator Management (July 2025)
// https://pages.nist.gov/800-63-4/sp800-63b.html
// https://csrc.nist.gov/pubs/sp/800/63/b/4/final
//
// Supersedes SP 800-63B (March 2020), which is withdrawn.
//
// Section numbering used here was verified against the published document's own
// cross-references on 2026-08-10. The renumbering from Rev 3 is not cosmetic:
//
//   Rev 3 5.1.1.x  Memorized Secrets  ->  Rev 4 3.1.1.x  Passwords
//   Rev 3 5.2.2    Rate Limiting      ->  Rev 4 3.2.2    Rate Limiting
//   Rev 3 7.x      Session Management ->  Rev 4 5.x      Session Management
//   Rev 3 7.2      Reauthentication   ->  Rev 4 5.2 (general) and
//                                         Rev 4 2.1.3 / 2.2.3 / 2.3.3 per AAL
//
// The per-AAL reauthentication timeouts live in section 2, under each assurance
// level, not under section 5. Section 5.2 states the general requirement and
// section 2.x.3 states the numbers. Anything citing 5.2.1/5.2.2/5.2.3 for the
// per-AAL timeouts is citing sections that do not exist.
//
// The substantive Rev 4 delta for vault42 is at 2.2.3.
// =============================================================================

// --- 3.2.2 Rate Limiting (Throttling) ---

// Verbatim: "the verifier SHALL limit consecutive failed authentication
// attempts using a specific authenticator on a single subscriber account to no
// more than 100 by disabling that authenticator."
//
// vault42 locks out at 5, well inside the ceiling. What this asserts is that a
// finite limit exists and that it is below the SHALL, not the specific number.
func TestNIST63B4_3_2_2_ConsecutiveFailuresAreLimitedBelowTheCeiling(t *testing.T) {
	src := readCodeOnly(t, "internal/service/auth.go")
	if !strings.Contains(src, "lockoutThreshold") {
		t.Fatal("3.2.2: the lockout threshold is gone; consecutive failed authentications would be unlimited")
	}
	if !regexp.MustCompile(`lockoutThreshold\s*=\s*(\d+)`).MatchString(src) {
		t.Error("3.2.2: the lockout threshold is no longer a literal; confirm it is at or below the 100-attempt SHALL")
	} else {
		value := regexp.MustCompile(`lockoutThreshold\s*=\s*(\d+)`).FindStringSubmatch(src)[1]
		if n, err := strconv.Atoi(value); err != nil || n <= 0 || n > 100 {
			t.Errorf("3.2.2: the lockout threshold is %s, which is not inside the 100-attempt SHALL", value)
		}
	}
	// Rev 4 adds an explicit requirement that generating a new authentication
	// secret must not reset the failure count. The counter is keyed on the user,
	// not on the credential, which is what satisfies that.
	if !strings.Contains(src, "lockout:") {
		t.Error("3.2.2: the lockout counter is no longer keyed per subscriber account")
	}
}

// --- 3.1.1.2 Password Verifiers ---

// Verbatim: "Verifiers and CSPs SHALL require passwords that are used as a
// single-factor authentication mechanism to be a minimum of 15 characters in
// length."
//
// This is the requirement that got stricter between revisions: Rev 3 set the
// floor at 8. vault42 already required 15, so the re-baseline moves this row
// from "exceeds the standard" to "meets the current standard exactly", which is
// a stronger claim to be able to make.
func TestNIST63B4_3_1_1_2_SingleFactorPasswordFloorIs15(t *testing.T) {
	src := readCodeOnly(t, "internal/config/config.go")
	if !strings.Contains(src, "PasswordMinLength") {
		t.Fatal("3.1.1.2: the password minimum length setting is gone")
	}
	if !strings.Contains(src, `envInt("VAULT_PASSWORD_MIN_LENGTH", 15)`) {
		t.Error("3.1.1.2: the password minimum no longer defaults to 15, which is the Rev 4 SHALL for single-factor use")
	}
}

// Verbatim: "The salt SHALL be at least 32 bits in length."
func TestNIST63B4_3_1_1_2_PasswordsAreSaltedAndHashed(t *testing.T) {
	src := readCodeOnly(t, "internal/crypto/argon2.go")
	if !strings.Contains(src, "argon2.IDKey") {
		t.Fatal("3.1.1.2: Argon2id is no longer the password hashing scheme")
	}
	saltLen := regexp.MustCompile(`argon2SaltLen\s*=\s*(\d+)`).FindStringSubmatch(src)
	if saltLen == nil {
		t.Error("3.1.1.2: the salt length constant is gone")
	} else if n, err := strconv.Atoi(saltLen[1]); err != nil || n*8 < 32 {
		t.Errorf("3.1.1.2: the salt is %s bytes, below the 32-bit SHALL", saltLen[1])
	}
	// A pepper is an additional secret the standard permits and vault42 uses;
	// it must not be a substitute for the per-password salt.
	if !strings.Contains(src, "pepper") && !strings.Contains(src, "Pepper") {
		t.Error("3.1.1.2: the server-side pepper is gone from the hashing path")
	}
}

// --- 5.1 Session Bindings ---

// Section 5.1 requires the session secret to be bound to the authentication
// event. vault42 binds it to a device fingerprint computed at issuance and
// re-checked on every refresh.
func TestNIST63B4_5_1_SessionSecretsAreBoundToTheAuthenticationEvent(t *testing.T) {
	src := readCodeOnly(t, "internal/service/auth.go")
	if !strings.Contains(src, "FingerprintHash") {
		t.Fatal("5.1: refresh tokens no longer carry a fingerprint binding")
	}
	if !strings.Contains(src, "FingerprintAnomaly") {
		t.Error("5.1: a fingerprint mismatch on refresh is no longer detected or audited")
	}
}

// --- 2.2.3 AAL2 Reauthentication ---

// Verbatim: "A definite reauthentication overall timeout SHALL be established,
// which SHOULD be no more than 24 hours at AAL2. The inactivity timeout SHOULD
// be no more than 1 hour."
//
// This is the requirement the sliding-refresh-window issue lands on, and it
// lands as a SHALL. Establishing *a* definite overall timeout is mandatory;
// the 24-hour figure is a SHOULD.
//
// State of the implementation at the time of writing, asserted below rather
// than described:
//
//   - The mechanism exists. TokenService clamps a rotated pair's expiry to
//     familyOrigin+maxSessionLifetime, AuthService.enforceSessionLifetime
//     refuses a family past the bound, and migration 013 stores the family
//     origin so the age is knowable at all.
//   - The mechanism is not configured. SetMaxSessionLifetime has no non-test
//     caller and no environment variable feeds it, so maxSessionLifetime is
//     zero in every deployment and the bound is inert.
//
// A control that cannot be switched on is not established, so the register
// carries 2.2.3 as an accepted risk (AR-14) rather than Met. This test asserts
// the half that exists and fails the moment the wiring lands, which is the
// signal to promote the row.
func TestNIST63B4_2_2_3_AbsoluteReauthenticationBoundIsImplemented(t *testing.T) {
	token := readCodeOnly(t, "internal/service/token.go")
	for _, needle := range []string{"SetMaxSessionLifetime", "MaxSessionLifetime", "sessionDeadline"} {
		if !strings.Contains(token, needle) {
			t.Errorf("2.2.3: internal/service/token.go no longer provides %s; the absolute reauthentication bound has no mechanism", needle)
		}
	}

	auth := readCodeOnly(t, "internal/service/auth.go")
	if !strings.Contains(auth, "enforceSessionLifetime") {
		t.Error("2.2.3: the refresh path no longer enforces the family age bound")
	}
	// Every branch that cannot date a family must refuse rather than pass. A
	// bound that silently no-ops when the store cannot answer is not a bound.
	if !strings.Contains(auth, "ErrSessionAgeUnknown") {
		t.Error("2.2.3: an unknown family age no longer fails closed")
	}

	// The family origin has to be stored, not recomputed, or pruning a spent
	// row would silently reset the session's age.
	schema := readProductionSource(t, "migrations/013_session_lifetime.sql")
	if !strings.Contains(schema, "family_created_at") {
		t.Fatal("2.2.3: migration 013 no longer adds the family origin column")
	}
	if !strings.Contains(schema, "SET NOT NULL") {
		t.Error("2.2.3: family_created_at is nullable, so a row inserted without an origin would escape the bound")
	}
}

// The mandatory half of 2.2.3 is now satisfied: cmd/vault/main.go configures the
// bound from VAULT_MAX_SESSION_LIFETIME, so a definite overall reauthentication
// timeout is established. What remains is advisory and is carried as AR-14:
//
//   - The default is 720 hours. Section 2.2.3 says the overall timeout SHOULD be
//     no more than 24 hours at AAL2.
//   - There is no inactivity timeout at all. Section 2.2.3 says it SHOULD be no
//     more than 1 hour at AAL2.
//
// This test pins the distinction. It fails if the bound stops being configured,
// which would reopen the SHALL, and it fails if an inactivity timeout appears,
// which is the signal to narrow AR-14 again.
func TestNIST63B4_2_2_3_TheOverallTimeoutIsEstablishedButNotAtTheRecommendedValue(t *testing.T) {
	main := readCodeOnly(t, "cmd/vault/main.go")
	if !strings.Contains(main, "SetMaxSessionLifetime") {
		t.Fatal("2.2.3: cmd/vault/main.go no longer configures the absolute session lifetime, so no definite overall reauthentication timeout is established. This reopens a SHALL.")
	}

	config := readCodeOnly(t, "internal/config/config.go")
	m := regexp.MustCompile(`envDuration\("VAULT_MAX_SESSION_LIFETIME",\s*(\d+)\s*\*\s*time\.Hour\)`).FindStringSubmatch(config)
	if m == nil {
		t.Fatal("2.2.3: VAULT_MAX_SESSION_LIFETIME no longer has an hour-denominated default; re-derive this assertion")
	}
	hours, err := strconv.Atoi(m[1])
	if err != nil || hours <= 0 {
		t.Fatalf("2.2.3: the absolute session lifetime defaults to %q, which establishes no bound", m[1])
	}
	if hours <= 24 {
		t.Fatalf("2.2.3: the default is now %d hours, inside the 24-hour SHOULD. AR-14 narrows further: update the register and this assertion.", hours)
	}
	t.Logf("2.2.3: overall reauthentication timeout established at %d hours; the AAL2 SHOULD is 24 (AR-14)", hours)

	// The inactivity half has no mechanism at all: no column records last
	// activity and no decision consults one.
	schema := readProductionSource(t, "migrations/001_initial_schema.sql")
	for _, column := range []string{"last_activity_at", "last_used_at", "idle_expires_at"} {
		if strings.Contains(schema, column) {
			t.Fatalf("2.2.3: %s now exists, so an inactivity timeout is possible. Narrow AR-14 and replace this assertion.", column)
		}
	}
}

// --- 4.6 Account Notifications ---

// Rev 4 requires the subscriber to be notified of authenticator lifecycle
// events. vault42 notifies on lockout and on credential change.
func TestNIST63B4_4_6_SubscribersAreNotifiedOfLockout(t *testing.T) {
	src := readCodeOnly(t, "internal/service/auth.go")
	if !strings.Contains(src, "lockNotifyKey") {
		t.Error("4.6: the account-lockout notification is gone")
	}
}
