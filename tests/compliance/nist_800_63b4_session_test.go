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
// This asserts the mechanism the ABSOLUTE bound is built from: TokenService
// clamps a rotated pair's expiry to familyOrigin+maxSessionLifetime,
// AuthService.enforceSessionLifetime refuses a family past the bound, and
// migration 013 stores the family origin so the age is knowable at all.
//
// The paragraph that used to sit here said the mechanism had no non-test caller
// and no environment variable feeding it, and concluded that a control which
// cannot be switched on is not established. That stopped being true when
// cmd/vault/main.go started calling SetMaxSessionLifetime, and the sentence
// outlived the fact by a release. It is replaced rather than amended: the
// wiring is now asserted, next door, by
// TestNIST63B4_2_2_3_TheInactivityDefaultIsTheAAL2FigureAndTheOverallOneIsNot,
// which reads the shipped defaults out of config.Load rather than describing
// them.
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

// --- 2.2.3, the inactivity half: a retired tripwire ---
//
// TestNIST63B4_2_2_3_TheOverallTimeoutIsEstablishedButNotAtTheRecommendedValue
// lived here. It asserted that the overall timeout was configured but above the
// AAL2 SHOULD, and then walked every migration looking for a column named
// last_activity_at, last_used_at or idle_expires_at, failing the moment one
// appeared. That second half was the tripwire: it was written to fire on
// whoever closed the gap, so the register could not be left behind by the code.
//
// It is retired, and it is worth saying exactly why, because "the tripwire did
// not fire" is not the reason.
//
// The tripwire watched for an IMPLEMENTATION — a new column — and not for the
// property. The inactivity timeout shipped without one: the presented refresh
// token's own created_at is already the instant its family last rotated, which
// is the only activity a rotating family has, and repository.ActiveFamily
// already publishes that same value to the user as LastUsedAt. So the gap
// closed, the column never appeared, and this test would have gone on passing
// and logging "no inactivity column across 39 migrations" for as long as anyone
// left it there.
//
// That is the failure mode gate_liveness_test.go exists for, arriving through a
// door it does not cover: not a gate that cannot fail, but a live gate watching
// the wrong noun. A tripwire keyed on how a control is expected to be built
// fires only on implementers who guessed the same way. Its replacements are
// keyed on what the control does, and they are in session_inactivity_test.go —
// TestASVS_V7_3_1_AnIdleSessionCannotRotateAndAnActiveOneCan and its siblings
// drive the real refresh path, and
// TestNIST63B4_2_2_3_TheInactivityDefaultIsTheAAL2FigureAndTheOverallOneIsNot
// carries what is left of this one: it fails if the inactivity default rises
// above the 1-hour SHOULD, and it fails if the 720-hour overall default drops
// inside the 24-hour SHOULD, which is the remaining half of CR-14.

// --- 4.6 Account Notifications ---

// Rev 4 requires the subscriber to be notified of authenticator lifecycle
// events. vault42 notifies on lockout and on credential change.
func TestNIST63B4_4_6_SubscribersAreNotifiedOfLockout(t *testing.T) {
	src := readCodeOnly(t, "internal/service/auth.go")
	if !strings.Contains(src, "lockNotifyKey") {
		t.Error("4.6: the account-lockout notification is gone")
	}
}
