// Package service implements the business logic layer for the Vault auth
// service, including user authentication, token issuance and rotation, MFA
// policy enforcement, and HIBP breach checking.
package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/deferwork"
	vaultemail "github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/ipintel"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/sanitize"
	"github.com/42-v/vault42/internal/seed"
	"github.com/42-v/vault42/internal/useragent"
)

// isUniqueViolation checks if an error is a PostgreSQL unique constraint violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// maskEmail masks an email address for audit logs: shows the first character of
// the local part, masks the rest with asterisks, and preserves the full domain.
// Example: "alice@example.com" becomes "a***@example.com".
func maskEmail(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at <= 0 {
		return "***"
	}
	local := addr[:at]
	domain := addr[at:] // includes '@'
	if len(local) <= 1 {
		return local + "***" + domain
	}
	return string(local[0]) + "***" + domain
}

// Sentinel errors returned by AuthService methods.
var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrEmailTaken         = errors.New("email already registered")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked")
	ErrAccountBanned      = errors.New("account banned")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrPasswordBreached   = errors.New("password found in breach database")
	ErrPasswordTooShort   = errors.New("password too short")
	ErrPasswordReused     = errors.New("password recently used")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenUsed          = errors.New("token already used")
	ErrTokenInvalid       = errors.New("invalid token")
	ErrReplayDetected     = errors.New("refresh token replay detected")
	// ErrEmailOTPNotAllowed is returned when email-OTP is requested for a user
	// who has a stronger enrolled factor (TOTP/WebAuthn). Email-OTP is only a
	// fallback for accounts with no second factor when MFA is required.
	ErrEmailOTPNotAllowed = errors.New("email OTP not permitted for this account")
	ErrMFARequired        = errors.New("MFA verification required")
	ErrChallengeConsumed  = errors.New("challenge token already consumed")
	ErrTooManySessions    = errors.New("maximum concurrent sessions reached")
	// ErrSessionExpired is returned when a refresh-token family has reached the
	// absolute session lifetime and must reauthenticate regardless of activity
	// (NIST SP 800-63B-4 §2.2.3). It wraps ErrTokenExpired so every transport that
	// already maps an expired refresh token keeps its status code and its
	// cookie-clearing behavior, and so the outcome is indistinguishable from an
	// ordinary expiry to the client.
	ErrSessionExpired = fmt.Errorf("session exceeded maximum lifetime: %w", ErrTokenExpired)
	// ErrSessionAgeUnknown is the fail-closed outcome when the absolute session
	// lifetime is configured but the family's age cannot be established. It wraps
	// ErrTokenInvalid: an unbounded session must not be issued because a lookup
	// failed.
	ErrSessionAgeUnknown = fmt.Errorf("session age could not be determined: %w", ErrTokenInvalid)
)

// familyOriginReader is the one capability the absolute session lifetime needs
// from the refresh-token store: when the rotation family was created.
//
// It is asserted on repository.RefreshTokenRepository rather than added to it so
// that a store which cannot answer is detected at the enforcement point and fails
// closed there, instead of every implementation growing a method it does not use.
type familyOriginReader interface {
	FamilyOrigin(ctx context.Context, familyID string) (time.Time, error)
}

// Lockout defaults: 5 failures locks one (account, source address) pair for 15
// minutes, 50 failures across all sources locks the account itself, and 20
// failures from one address locks that address.
//
// The per-source key is what makes lockout a defense rather than a weapon. The
// counter used to be keyed on the user id alone, so five wrong passwords from
// one address denied logins to any account whose email the caller knew, for
// fifteen minutes, at a cost of five HTTP requests and no credential. MFA verify
// shared that counter, so the victim could not climb out with a second factor
// either. Keying the hard lock on (user, source) means an attacker locks only
// the path they are attacking from.
//
// distributedLockoutThreshold keeps the account-wide lock for what it was
// actually for: a genuine distributed attack. Reaching it needs at least ten
// distinct source addresses, because each is cut off at lockoutThreshold and the
// per-IP lockout stops any one address at ipLockoutThreshold across all
// accounts. This is an explicit trade, and it is the one NIST SP 800-63B 5.2.2
// asks for: aggregate guesses against one account rise from 5 to 50 per window,
// throttled from the sixth failure by loginThrottleDelay, in exchange for
// removing a five-request remote denial of service against every account. 50 is
// half the ">= 100 consecutive failures, with throttling" that guidance allows.
//
// The reset-from-email escape (handler/password.go) still works from any state,
// unchanged.
const (
	lockoutThreshold            = 5
	distributedLockoutThreshold = 50
	ipLockoutThreshold          = 20
	lockoutDuration             = 15 * time.Minute
)

// Progressive delay applied to every login attempt against an identity that has
// recent failures, whether or not that identity exists.
//
// It is the throughput half of the lockout rework: the per-source hard lock
// stops one address, and this stops a botnet from spending the account-wide
// budget in a burst. The delay grows 100ms, 200ms, 400ms... and stops at 2s,
// well inside the server's write timeout, costing a sleeping goroutine rather
// than the 46 MiB the same request's argon2 hash costs.
//
// It is applied identically to every outcome — success, wrong password, unknown
// address, locked, deleted — because a delay only existing accounts pay is an
// enumeration oracle. The counter behind it is keyed on the submitted address
// rather than on a user id for the same reason: an address with no account must
// accrue and spend it exactly like one that has.
//
// Variables, not constants, so a test that has to drive dozens of failures
// through the real Login path does not have to spend the real minutes.
var (
	loginThrottleBase = 100 * time.Millisecond
	loginThrottleMax  = 2 * time.Second
)

// AuthService handles registration, login, and token operations.
type AuthService struct {
	users              repository.UserRepository
	tokens             repository.RefreshTokenRepository
	devices            repository.DeviceRepository
	pwHistory          repository.PasswordHistoryRepository
	rateLimits         repository.RateLimitRepository
	tokenSvc           *TokenService
	mfaSvc             *MFAService
	roleCatalog        *RoleCatalog
	auditLog           *audit.Logger
	hibp               *HIBPClient
	cache              cache.Cache
	emailSender        vaultemail.Sender
	mailer             *vaultemail.Mailer
	honeypotAlert      *honeypot.Alerter
	ipIntel            *ipintel.DB
	loginCountries     repository.LoginCountryRepository
	metrics            *metrics.Collector
	maxSessionsPerUser int
	origin             string
	appName            string
	pepper             string
	minPwLength        int
	hibpEnabled        bool
	hmacSecret         []byte
	strictSessionLimit bool
}

// SetStrictSessionLimit controls checkSessionLimit's behavior on a count-query
// error: true fails closed (rejects login + audits), false (default) fails open.
func (s *AuthService) SetStrictSessionLimit(strict bool) {
	s.strictSessionLimit = strict
}

// NewAuthService creates a new auth service.
func NewAuthService(
	users repository.UserRepository,
	tokens repository.RefreshTokenRepository,
	devices repository.DeviceRepository,
	pwHistory repository.PasswordHistoryRepository,
	tokenSvc *TokenService,
	mfaSvc *MFAService,
	auditLog *audit.Logger,
	hibp *HIBPClient,
	c cache.Cache,
	emailSender vaultemail.Sender,
	origin, appName, pepper string,
	minPwLength int,
	hibpEnabled bool,
	hmacSecret []byte,
) *AuthService {
	s := &AuthService{
		users: users, tokens: tokens, devices: devices,
		pwHistory: pwHistory, tokenSvc: tokenSvc, mfaSvc: mfaSvc,
		auditLog: auditLog, hibp: hibp, cache: c, emailSender: emailSender,
		origin: origin, appName: appName, pepper: pepper,
		minPwLength: minPwLength, hibpEnabled: hibpEnabled,
		hmacSecret: hmacSecret,
	}
	// Default mailer: global branding only, no per-app overrides. SetMailer
	// upgrades it with an OverrideStore + allowlist at wiring time.
	s.mailer = vaultemail.NewMailer(nil, emailSender, nil, vaultemail.Branding{AppName: appName}, nil)
	return s
}

// SetMailer replaces the email mailer to enable per-app white-label branding and
// template overrides (resolved through an email.OverrideStore). Called once at
// wiring time; a nil mailer is ignored.
func (s *AuthService) SetMailer(m *vaultemail.Mailer) {
	if m != nil {
		s.mailer = m
	}
}

// emailMailer returns the configured mailer, or a global-branding fallback built
// from the sender. The fallback covers services constructed as struct literals
// (tests) that bypass NewAuthService; the send-site guards ensure emailSender is
// non-nil before this is reached.
func (s *AuthService) emailMailer() *vaultemail.Mailer {
	if s.mailer != nil {
		return s.mailer
	}
	return vaultemail.NewMailer(nil, s.emailSender, nil, vaultemail.Branding{AppName: s.appName}, nil)
}

// SetRateLimitRepo configures the PostgreSQL-backed rate limit repository
// used as a fallback for IP lockout when the cache is unavailable.
func (s *AuthService) SetRateLimitRepo(r repository.RateLimitRepository) {
	s.rateLimits = r
}

// SetHoneypotAlerter configures the honeypot alerter for trap user detection.
// When set, login attempts with trap user credentials return fake tokens
// instead of real authentication failures.
func (s *AuthService) SetHoneypotAlerter(a *honeypot.Alerter) {
	s.honeypotAlert = a
}

// SetIPIntel configures the IP-intelligence handle used to derive a coarse
// country signal (and, in the rate limiter, VPN/hosting/Tor flags) from a
// client address. When nil — the default — the new-location notice no-ops
// entirely; the whole feature is gated on this handle being present.
func (s *AuthService) SetIPIntel(db *ipintel.DB) {
	s.ipIntel = db
}

// SetLoginCountryRepo configures the store that remembers which countries a user
// has logged in from, backing the new-location notice. Without it (the default)
// the notice no-ops: there is nothing to compare a login's country against.
func (s *AuthService) SetLoginCountryRepo(r repository.LoginCountryRepository) {
	s.loginCountries = r
}

// newLocationNotifyWindow throttles the new-location notice to at most one per
// user per country per window, mirroring the once-per-window shape of the
// account-lock notice.
const newLocationNotifyWindow = 24 * time.Hour

// notifyNewCountry records the country a successful login came from and, when it
// is a NEW country for a user who already had at least one recorded country,
// sends a throttled out-of-band notice. Country granularity only: the raw IP is
// resolved to a country here and never leaves this function — not into the
// store, not into the audit log, not into the email.
//
// It is fail-open and best-effort by construction: it is invoked in its own
// goroutine from the login success paths, every error degrades to "no notice",
// and nothing here can block or fail a login. When either the ipintel handle or
// the country store is absent the feature no-ops.
//
// A first-ever login (the user had no recorded country) seeds the set silently:
// the very first place someone logs in from is not a location change, so it must
// not fire a notice.
func (s *AuthService) notifyNewCountry(userID, emailAddr, ip, app string) {
	if s.ipIntel == nil || s.loginCountries == nil {
		return
	}
	cc := s.ipIntel.LookupString(ip).CountryCode
	if cc == "" {
		// Fail-open: an unknown/private/unparseable address yields no country, so
		// there is nothing to compare or notify about.
		return
	}
	ctx := context.Background()
	wasNew, hadAny, err := s.loginCountries.UpsertAndWasNew(ctx, userID, cc)
	if err != nil {
		log.Printf("auth: login-country upsert failed for %s: %v", userID, err)
		return
	}
	if !wasNew || !hadAny {
		// Known country, or the first country ever recorded for this user.
		return
	}

	// Audit the new-country event with the country only — never the IP.
	if s.auditLog != nil {
		s.auditLog.Log(ctx, audit.LoginNewCountry, userID, "", "", "", "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"country": cc}, 0)
	}

	// Throttle: one notice per user per country per window. Reuses the
	// SetIfNotExists gate the account-lock notice uses.
	if s.cache == nil || s.emailSender == nil {
		return
	}
	notifyKey := fmt.Sprintf("newloc_notified:%s:%s", userID, cc)
	if sent, _ := s.cache.SetIfNotExists(ctx, notifyKey, "1", newLocationNotifyWindow); !sent {
		return
	}
	deferwork.Go(func(ctx context.Context) {
		// Email is best-effort; pass ONLY the country, never the IP.
		_ = s.emailMailer().Send(ctx, app, vaultemail.TemplateNewLocation, emailAddr, vaultemail.TemplateData{
			Country: cc,
		})
	})
}

// SetMetrics configures the metrics collector for login/token counters.
func (s *AuthService) SetMetrics(m *metrics.Collector) {
	s.metrics = m
}

// SetMaxSessionsPerUser configures the maximum concurrent refresh token families
// allowed per user. When the limit is reached, new logins are rejected with
// ErrTooManySessions. A value of 0 disables the check.
func (s *AuthService) SetMaxSessionsPerUser(n int) {
	s.maxSessionsPerUser = n
}

// MaxSessionsPerUser returns the configured concurrent-family cap, or 0 when
// the bound is disabled. Login paths that persist a family themselves (the
// OAuth callback) pass this into CreateWithinCap so the insert, not only the
// CheckSessionLimit pre-check, is the hard bound.
func (s *AuthService) MaxSessionsPerUser() int {
	return s.maxSessionsPerUser
}

// SetRoleCatalog enables catalog-aware role validation. When set, JWT issuance
// keeps only roles present in the auth.app_roles catalog (in addition to the
// admin-reserved filter). Nil (the default) preserves the prior behavior.
func (s *AuthService) SetRoleCatalog(c *RoleCatalog) {
	s.roleCatalog = c
}

// ChallengeFingerprintMatches reports whether the device fingerprint embedded in
// a 2fa_challenge token matches the fingerprint recomputed from the redeeming
// request. An empty challengeFP (legacy token without the claim) is treated as a
// match so in-flight challenges aren't bricked. On mismatch it records a
// FingerprintAnomaly audit event — the device/network-switch signal the claim was
// added to detect, kept consistent with the refresh path (audit M1).
func (s *AuthService) ChallengeFingerprintMatches(ctx context.Context, userID, challengeFP, requestFP, ip, ua string) bool {
	if challengeFP == "" {
		return true
	}
	if vaultcrypto.CompareFingerprints(challengeFP, requestFP) {
		return true
	}
	s.auditLog.Log(ctx, audit.FingerprintAnomaly, userID, "", ip, ua, requestFP, "", // #nosec G104 -- audit is best-effort, never blocks auth flow
		map[string]interface{}{"expected": challengeFP, "stage": "mfa_challenge"}, 70)
	return false
}

// effectiveRoles computes the roles embedded in a JWT for a user: strip
// admin-reserved tiers (seed.FilterUserRoles), then — when a catalog is
// configured — keep only catalog-defined roles, falling back to ["user"] when
// the result is empty (preserving the historical default).
func (s *AuthService) effectiveRoles(ctx context.Context, roles []string) []string {
	out := seed.FilterUserRoles(roles)
	if s.roleCatalog != nil {
		out = s.roleCatalog.Filter(ctx, out)
	}
	if len(out) == 0 {
		return []string{"user"}
	}
	return out
}

// RegisterInput is the registration request payload.
type RegisterInput struct {
	Email       string `json:"email"`
	Password    string `json:"password"` // #nosec G117 -- password field in request DTO, not stored
	DisplayName string `json:"display_name"`
	Locale      string `json:"locale"`
	RedirectTo  string `json:"redirect_to"` // relative path to redirect after email verification
}

// RegisterResult is the registration response.
type RegisterResult struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

// Register creates a new user account.
func (s *AuthService) Register(ctx context.Context, input RegisterInput, ip string) (*RegisterResult, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if !sanitize.Email(email) {
		return nil, ErrInvalidInput
	}

	if utf8.RuneCountInString(input.Password) < s.minPwLength {
		return nil, ErrPasswordTooShort
	}

	if s.hibpEnabled && s.hibp.IsBreached(input.Password) {
		return nil, ErrPasswordBreached
	}

	// Check if email is taken
	existing, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		// Burn constant-time Argon2id to prevent timing-based user enumeration:
		// without this, "email taken" returns ~0ms vs "new email" takes ~150ms.
		if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return nil, err // 503 — same status as new-email path (HashPassword also acquires semaphore)
		}
		return nil, ErrEmailTaken
	}

	hash, err := vaultcrypto.HashPassword(input.Password, s.pepper)
	if err != nil {
		return nil, err
	}

	userID, err := vaultcrypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("generate user ID: %w", err)
	}
	now := time.Now()
	locale := sanitize.Locale(input.Locale)

	user := &model.User{
		ID:           userID,
		Email:        email,
		PasswordHash: hash,
		DisplayName:  sanitize.String(input.DisplayName, 255),
		Locale:       locale,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		// Handle concurrent registration with the same email (UNIQUE violation)
		if isUniqueViolation(err) {
			return nil, ErrEmailTaken
		}
		return nil, err
	}

	// Store in password history (non-critical — log but don't fail)
	if histID, err := vaultcrypto.RandomUUID(); err != nil {
		log.Printf("auth: failed to generate password history ID: %v", err)
	} else if err := s.pwHistory.Create(ctx, &model.PasswordHistory{
		ID: histID, UserID: userID, PasswordHash: hash, CreatedAt: now,
	}); err != nil {
		log.Printf("auth: failed to store password history: %v", err)
	}

	s.auditLog.Log(ctx, audit.Registration, userID, "", ip, "", "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
		map[string]interface{}{"email": maskEmail(email)}, 0)

	s.SendSignupVerification(ctx, email, userID, sanitize.RedirectPath(input.RedirectTo))

	return &RegisterResult{UserID: userID, Email: email}, nil
}

// SendSignupVerification mails a verification link for an account that was just
// created, and returns immediately. Delivery outlives the request and is best
// effort: the row is already committed when this is called, so a mailer outage
// must not turn a completed signup into a failure the caller reports.
//
// Every signup path goes through here so none of them can drift into its own
// error convention. Password registration is one. A social login whose provider
// does not vouch for the address is the other, and that one is not optional:
// GET /auth/verify-email consumes a token it never issues, so an unverified
// OAuth account that received no mail can never become verified, and because the
// address is taken a later login through a provider that does verify it is
// refused with 409.
//
// redirectTo is a sanitized relative path the verification link returns the user
// to, or empty for the default landing page.
func (s *AuthService) SendSignupVerification(ctx context.Context, to, userID, redirectTo string) {
	if s.cache == nil || s.emailSender == nil {
		return
	}
	app := vaultemail.AppFromContext(ctx)
	deferwork.Go(func(ctx context.Context) { s.sendVerificationEmail(ctx, to, userID, app, redirectTo) })
}

// sendVerificationEmail generates a verification token, stores it, and sends the
// email. app is the white-label tenant slug (may be empty for global branding).
func (s *AuthService) sendVerificationEmail(ctx context.Context, to, userID, app, redirectTo string) {
	token, err := vaultcrypto.RandomHex(32)
	if err != nil {
		log.Printf("auth: failed to generate verification token: %v", err)
		s.auditVerificationNotSent(ctx, userID, to, "token_generation_failed")
		return
	}

	tokenHash := vaultcrypto.SHA256Hex(token)
	if err := s.cache.Set(ctx, "verify:"+tokenHash, userID, 24*time.Hour); err != nil {
		log.Printf("auth: failed to store verification token: %v", err)
		s.auditVerificationNotSent(ctx, userID, to, "token_store_failed")
		return
	}

	verifyURL := s.origin + "/verify-email?token=" + token
	if redirectTo != "" {
		verifyURL += "&redirect=" + url.QueryEscape(redirectTo)
	}

	if err := s.emailMailer().Send(ctx, app, vaultemail.TemplateVerification, to, vaultemail.TemplateData{
		URL: verifyURL,
	}); err != nil {
		log.Printf("auth: failed to send verification email to %s: %v", maskEmail(to), err)
		s.auditVerificationNotSent(ctx, userID, to, "delivery_failed")
	}
}

// auditVerificationNotSent records that an account was left without the
// verification link it needs. The send is deliberately non-fatal, which means
// the only evidence it ever failed is this record plus the log line: the account
// looks like any other unverified one, and an operator asked why a user cannot
// log in has nothing else to read. The address is masked, matching the
// Registration event the same signup already writes.
func (s *AuthService) auditVerificationNotSent(ctx context.Context, userID, to, reason string) {
	if s.auditLog == nil {
		return
	}
	s.auditLog.Log(ctx, audit.Registration, userID, "", "", "", "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
		map[string]interface{}{
			"action": "verification_email_not_sent",
			"reason": reason,
			"email":  maskEmail(to),
		}, 0)
}

// importClaimTTL is how long an import claim link stays valid, and therefore also
// how often a new one may be minted for the same account.
const importClaimTTL = time.Hour

// sendImportClaimLink mints a one-time reset token (compatible with the
// password reset-confirm flow) for an imported account and emails the magic
// link. Fire-and-forget; failures are logged, not surfaced (anti-enumeration).
//
// SECURITY INVARIANT: at most one claim link per account per importClaimTTL. The
// caller is an unauthenticated login attempt, so without the throttle anyone who
// knows an imported address holds two primitives: mail the account holder at will,
// and invalidate whatever claim link they are in the middle of using, because each
// mint revokes the previous one. The reservation is taken before any work so the
// invalidation below cannot run more often than the send.
func (s *AuthService) sendImportClaimLink(userID, emailAddr, app string) {
	if s.cache == nil || s.emailSender == nil {
		return
	}
	deferwork.Go(func(ctx context.Context) {
		// Fail closed on a cache error: an unthrottled send is worse than a claim
		// link the user re-requests, and the claim token needs this same cache to
		// be stored at all.
		reserved, err := s.cache.SetIfNotExists(ctx, "import_claim_sent:"+userID, "1", importClaimTTL)
		if err != nil || !reserved {
			return
		}
		// Invalidate any prior outstanding claim link so only the latest is valid.
		if oldHash, err := s.cache.GetAndDelete(ctx, "pwreset_user:"+userID); err == nil && oldHash != "" {
			s.cache.Delete(ctx, "reset:"+oldHash) // #nosec G104 -- best-effort invalidation
		}
		token, err := vaultcrypto.RandomHex(32)
		if err != nil {
			log.Printf("auth: import claim token gen failed: %v", err)
			return
		}
		tokenHash := vaultcrypto.SHA256Hex(token)
		// Same keys the password ResetConfirm handler consumes.
		if err := s.cache.Set(ctx, "reset:"+tokenHash, userID, importClaimTTL); err != nil {
			log.Printf("auth: import claim token store failed: %v", err)
			return
		}
		s.cache.Set(ctx, "pwreset_user:"+userID, tokenHash, importClaimTTL) // #nosec G104 -- reverse map for invalidation, best-effort

		claimURL := s.origin + "/reset-password?token=" + token + "&import=1"
		if err := s.emailMailer().Send(ctx, app, vaultemail.TemplatePasswordReset, emailAddr, vaultemail.TemplateData{
			URL: claimURL,
		}); err != nil {
			log.Printf("auth: failed to send import claim email to %s: %v", maskEmail(emailAddr), err)
		}
	})
}

// LoginInput is the login request payload.
type LoginInput struct {
	Email       string `json:"email"`
	Password    string `json:"password"` // #nosec G117 -- password field in request DTO, not stored
	RememberMe  bool   `json:"remember_me"`
	ClientID    string `json:"client_id"`
	Fingerprint vaultcrypto.FingerprintInput
}

// LoginResult is the login response.
type LoginResult struct {
	AccessToken      string   `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	TokenType        string   `json:"token_type"`
	ExpiresIn        int      `json:"expires_in"`
	RefreshToken     string   `json:"-"` // set via cookie, not in body
	CookieMaxAge     int      `json:"-"` // refresh cookie maxage in seconds
	Requires2FA      bool     `json:"requires_2fa,omitempty"`
	ChallengeToken   string   `json:"challenge_token,omitempty"`
	AvailableMethods []string `json:"available_methods,omitempty"`
	// ImportClaimRequired is never set. It signaled an unclaimed imported account
	// on its first login, which made that account distinguishable from every other
	// login failure to an unauthenticated caller; Login now answers
	// ErrInvalidCredentials there and mails the claim link out of band. The field
	// is retained so the transport layer keeps compiling until its 202 branch is
	// removed, and `omitempty` keeps it off the wire.
	ImportClaimRequired bool `json:"import_claim_required,omitempty"`
}

// loginResultWire is the serialized form of LoginResult.
//
// The MFA challenge is emitted under both spellings, for the same reason
// mfaStatusWire does it. mfa_required and mfa_methods are the canonical names:
// they match ProfileResponse.mfa_methods and the MFAStatus response, and the
// product has more than two factors, so "2fa" only survives in the URL paths
// BeOn3 is live on. requires_2fa and available_methods are the pre-1.0.0 names,
// kept as deprecated aliases for clients written against them; remove both at
// the next major version.
//
// The alias was added to MFAStatus and not here, which left the two responses
// of one login flow disagreeing about what the field is called. GET /mfa/status
// answered a client reading mfa_methods and POST /auth/login did not, and the
// login response is the one whose factor list changes what the client must do
// next, so a client that had migrated saw an empty list exactly when it
// mattered.
type loginResultWire struct {
	AccessToken         string   `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	TokenType           string   `json:"token_type"`
	ExpiresIn           int      `json:"expires_in"`
	Requires2FA         bool     `json:"requires_2fa,omitempty"`
	MFARequired         bool     `json:"mfa_required,omitempty"`
	ChallengeToken      string   `json:"challenge_token,omitempty"`
	AvailableMethods    []string `json:"available_methods,omitempty"`
	MFAMethods          []string `json:"mfa_methods,omitempty"`
	ImportClaimRequired bool     `json:"import_claim_required,omitempty"`
}

// MarshalJSON emits both spellings of the MFA challenge.
//
// Both stay omitempty and therefore appear and disappear together. The ordinary
// single-step login is the overwhelming majority of responses, and adding
// mfa_required:false plus an empty mfa_methods to every one of them would change
// the shape of the common case for a client that tests for the key rather than
// its value.
//
// RefreshToken and CookieMaxAge are absent by construction rather than by tag:
// the refresh credential travels in a Set-Cookie header, and a wire type that
// simply has no field for it cannot leak it into a response body.
func (r LoginResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(loginResultWire{
		AccessToken:         r.AccessToken,
		TokenType:           r.TokenType,
		ExpiresIn:           r.ExpiresIn,
		Requires2FA:         r.Requires2FA,
		MFARequired:         r.Requires2FA,
		ChallengeToken:      r.ChallengeToken,
		AvailableMethods:    r.AvailableMethods,
		MFAMethods:          r.AvailableMethods,
		ImportClaimRequired: r.ImportClaimRequired,
	})
}

// Login authenticates a user and issues tokens.
//
//nolint:gocognit,gocyclo // login owns user-lockout, ip-lockout, anti-enumeration burns, MFA challenge, family rotation, audit, metrics — all coupled to one state machine
func (s *AuthService) Login(ctx context.Context, input LoginInput, ip, ua string) (result *LoginResult, err error) {
	if s.metrics != nil {
		s.metrics.RecordLoginAttempt()
	}
	email := strings.ToLower(strings.TrimSpace(input.Email))

	// Every non-success outcome advances the identity throttle counter, in one
	// place, for the same reason recordLoginFailure exists: the paths must not
	// drift apart into distinguishable side effects. An unknown address, a
	// wrong password, a locked account and a soft-deleted account all accrue the
	// delay at the same rate, so the delay cannot be read as an oracle.
	//
	// ErrArgon2Overloaded is excluded. That branch is a 503 that mutates nothing
	// by design, and counting it would let anyone who can push the semaphore
	// over the edge throttle every address they know.
	defer func() {
		if err != nil && !errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			s.recordIdentityFailure(ctx, email)
		}
	}()
	// White-label tenant for any auth email sent during this login (verification
	// resend, import claim, lockout alert, email-OTP). Empty => global branding.
	app := vaultemail.AppFromContext(ctx)

	// Honeypot: does this address match a planted trap credential?
	//
	// The answer is computed here but acted on below, because the branch used to
	// sit above the IP-lockout gate and above the address lookup and return from
	// there. That made the trap the one address in the deployment that still
	// answered 200 from a locked-out IP, which an attacker reaches by burning the
	// lockout and then walking their candidate list. It also meant the trap
	// answered a successful login with no database round trips at all, so success
	// came back faster than failure: the reverse of every real deployment, and an
	// oracle needing no reference host to read.
	trap := s.honeypotAlert != nil && s.honeypotAlert.IsTrapUser(email)

	// Progressive delay for an address with recent failures. Applied before any
	// lookup so success and every kind of failure pay it identically, and before
	// the argon2 burn so a throttled caller holds a sleeping goroutine rather
	// than 46 MiB of hashing memory.
	s.throttleLogin(ctx, email)

	// Check IP-wide lockout (prevents credential stuffing from a single IP)
	if s.isIPLocked(ctx, ip) {
		s.auditLog.Log(ctx, audit.LoginFailure, "", "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "ip_locked"}, 50)
		return nil, ErrAccountLocked
	}

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if trap {
		return s.trapLogin(ctx, input, email, ip, ua)
	}

	// Constant-time: verify against dummy hash even if user not found (prevent timing leak).
	// Uses VerifyPassword (not HashPassword) so the code path is identical to the found-user case:
	// parse hash → compute Argon2id → constant-time compare.
	if user == nil {
		if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return nil, err // 503 — same status as existing-user path under load
		}
		s.recordFailedIP(ctx, ip)
		if s.metrics != nil {
			s.metrics.RecordLoginFailed()
		}
		s.auditLog.Log(ctx, audit.LoginFailure, "", "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "user_not_found"}, 10)
		return nil, ErrInvalidCredentials
	}

	// Check account lock (DB-level admin lockout OR cache-based auto-lockout). A
	// locked account is answered exactly like a wrong password: only an EXISTING
	// account can reach the locked state (the per-user counter has no key for an
	// unknown email), so a distinct ErrAccountLocked/403 would tell an
	// unauthenticated caller the address is registered. Rotating the probe IP
	// slips past the per-IP login limit, turning that 403-vs-401 into a reliable
	// enumeration oracle. Return ErrInvalidCredentials instead, and burn the same
	// dummy Argon2 the user==nil path burns so neither the status nor the timing
	// distinguishes a locked account from an unknown one. The lockout still holds:
	// no password is verified and no token is issued, and the audit row keeps the
	// real reason. MFA verify and refresh may still surface the lock, because
	// reaching them already proves the caller knows the account exists.
	// Burn the dummy hash BEFORE any side effect, exactly like the user==nil and
	// user.Deleted branches: an overloaded semaphore must short-circuit to
	// ErrArgon2Overloaded (503) having mutated nothing. Then advance the per-IP
	// failure counter the same way user==nil and a wrong password do. A locked
	// branch that skipped recordFailedIP left the caller's IP counter frozen while
	// an unknown address advanced it, so a run of probes trips the per-IP lockout
	// (403 ip_locked) for an unknown address but never for a locked one: a
	// 403-vs-401 progression that re-opens the very enumeration this branch closes.
	// recordFailedIP runs after the overload check, so an overloaded semaphore
	// still mutates nothing.
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return nil, err
		}
		s.recordFailedIP(ctx, ip)
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "account_locked", "source": "admin"}, 30)
		return nil, ErrInvalidCredentials
	}
	if s.isAccountLocked(ctx, user.ID, ip) {
		if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return nil, err
		}
		s.recordFailedIP(ctx, ip)
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "account_locked", "source": "auto"}, 30)
		return nil, ErrInvalidCredentials
	}

	// Account-state gate (legacy-platform parity, migration 004). A soft-deleted
	// account is masked as "no such user" (ErrInvalidCredentials) before the
	// password is verified, so its existence never leaks. Banned and disabled are
	// administrative denials a proven-password caller is entitled to see, so they
	// are checked after VerifyPassword succeeds (below): checking them here, before
	// the password, would answer a banned or disabled address with a distinct 403
	// while an unknown address answers 401, telling an unauthenticated caller the
	// address is registered.
	if user.Deleted {
		// Masked as "no such user" (ErrInvalidCredentials) to avoid revealing the
		// soft delete. The timing must match too: the user==nil and ImportPending
		// paths both burn a dummy Argon2 (~50ms), so returning here without one
		// answered a soft-deleted address that much faster and re-revealed exactly
		// what the masked error hides. Burn the same dummy hash, honoring overload.
		if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return nil, err
		}
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "account_deleted"}, 20)
		return nil, ErrInvalidCredentials
	}
	// Imported account, first login: no credential was ever imported, so there is
	// no password to verify and no session to issue.
	//
	// SECURITY INVARIANT (anti-enumeration, ASVS V2.1.1): this outcome must be
	// indistinguishable from a wrong password. It previously answered with a
	// distinct success-shaped result, which told an unauthenticated caller both
	// that the address was registered and that the account was an unclaimed
	// import, and mailed the account holder on demand. It now burns the same dummy
	// Argon2id, runs the same failure bookkeeping (so lockout progresses at the
	// same rate and locks with the same error), and returns the same
	// ErrInvalidCredentials — the same choice already made for an unverified email
	// below. The claim link travels out of band and throttled, so it is not a
	// signal to the caller and not a mail-bomb primitive.
	if user.ImportPending {
		if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return nil, err
		}
		s.sendImportClaimLink(user.ID, user.Email, app)
		s.recordLoginFailure(ctx, user, ip, ua, app, "import_claim_required", 20)
		return nil, ErrInvalidCredentials
	}

	// Verify password
	valid, err := vaultcrypto.VerifyPassword(input.Password, user.PasswordHash, s.pepper)
	if errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
		return nil, err // 503 — propagate before recording failure (consistent with dummy hash path)
	}
	if err != nil || !valid {
		s.recordLoginFailure(ctx, user, ip, ua, app, "wrong_password", 20)
		return nil, ErrInvalidCredentials
	}

	// Administrative-denial gate, after password proof. A banned or disabled
	// account reaches here only by proving it owns the account, so revealing the
	// denial is not an enumeration signal; a wrong password or an unknown address
	// stayed masked as ErrInvalidCredentials above and never arrives. No failure is
	// recorded and lockout does not progress: this refuses a valid credential by
	// policy, it is not a credential failure.
	if user.Banned {
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "account_banned"}, 30)
		return nil, ErrAccountBanned
	}
	if user.Disabled {
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "account_disabled"}, 30)
		return nil, ErrAccountDisabled
	}

	// Check email verified — return ErrInvalidCredentials (not ErrEmailNotVerified)
	// to prevent user enumeration: an attacker cannot distinguish "unverified" from
	// "wrong password" or "no such user".
	//
	// The failure bookkeeping runs too, and that is not hygiene, it is the
	// anti-enumeration property itself. Returning early with the right error and
	// none of the side effects left the lockout counter advancing only on WRONG
	// passwords: a wrong guess reached lockoutThreshold and the endpoint started
	// answering 403 account_locked, while the correct password answered 401
	// forever because it incremented nothing. Six attempts therefore told an
	// attacker whether their candidate was the real password, which is exactly
	// the distinction the paragraph above claims cannot be made. It also let
	// anyone holding the correct password of an unverified account guess against
	// it indefinitely without ever locking out, writing no audit rows and
	// leaving vault_login_failed_total flat.
	if !user.EmailVerified {
		s.recordLoginFailure(ctx, user, ip, ua, app, "email_not_verified", 20)
		return nil, ErrInvalidCredentials
	}

	// Reset the durable failed-login count now the password is proven. Only the
	// password path writes that column, so clearing it here cannot erase a
	// second-factor failure. The cache lockout counter is NOT cleared yet: it is
	// shared with the MFA path (RecordMFAFailure feeds the same key), and a first
	// factor that still owes a second one must not reset the second factor's
	// brute-force budget. Clearing it early let an attacker holding the password
	// re-login between guesses to zero the counter, so the H2 lockout never
	// tripped. It is cleared below on the single-step path, and by
	// CompleteMFALogin once the second factor also succeeds.
	if err := s.users.ResetFailedLogin(ctx, user.ID); err != nil {
		log.Printf("auth: failed to reset login count for %s: %v", user.ID, err)
	}

	// Compute fingerprint
	input.Fingerprint.IP = ip
	input.Fingerprint.UserAgent = ua
	fp := vaultcrypto.ComputeFingerprint(input.Fingerprint)

	// Check if user has MFA enabled
	if s.mfaSvc != nil {
		status, err := s.mfaSvc.GetStatus(ctx, user.ID)
		if err != nil {
			// Fail closed: an undetermined MFA status must not fall through to the
			// no-methods branch, which issues real tokens or downgrades to the
			// email-OTP fallback. Refuse the login rather than skip a factor the
			// account may hold but that a failed read could not see.
			log.Printf("auth: MFA status check failed for %s: %v", user.ID, err)
			return nil, fmt.Errorf("mfa status unavailable: %w", err)
		}
		hasMethods := status != nil && len(status.Methods) > 0
		if hasMethods {
			// Issue a short-lived challenge token instead of real tokens
			challengePair, err := s.tokenSvc.IssueChallengeToken(ctx, user.ID, fp, MethodPassword)
			if err != nil {
				return nil, fmt.Errorf("issue 2FA challenge: %w", err)
			}
			s.auditLog.Log(ctx, audit.LoginSuccess, user.ID, input.ClientID, ip, ua, fp, "", // #nosec G104 -- audit is best-effort, never blocks auth flow
				map[string]interface{}{"mfa_required": true}, 0)
			return &LoginResult{
				Requires2FA:      true,
				ChallengeToken:   challengePair,
				AvailableMethods: status.Methods,
			}, nil
		} else if s.mfaSvc.IsRequired() {
			// No MFA methods configured but MFA is required — email OTP fallback
			deferwork.Go(func(context.Context) { s.sendEmailOTP(user.ID, user.Email, app) })
			challengePair, err := s.tokenSvc.IssueChallengeToken(ctx, user.ID, fp, MethodPassword)
			if err != nil {
				return nil, fmt.Errorf("issue 2FA challenge: %w", err)
			}
			s.auditLog.Log(ctx, audit.LoginSuccess, user.ID, input.ClientID, ip, ua, fp, "", // #nosec G104 -- audit is best-effort, never blocks auth flow
				map[string]interface{}{"mfa_required": true, "fallback": "email_otp"}, 0)
			return &LoginResult{
				Requires2FA:      true,
				ChallengeToken:   challengePair,
				AvailableMethods: []string{"email_otp"},
			}, nil
		}
	}

	// Single-step login: no second factor is owed, so the login is complete and
	// the shared lockout counter can be cleared (the MFA path defers this to
	// CompleteMFALogin). The identity throttle goes too: a user who mistyped six
	// times and then got in should not keep paying the delay.
	s.clearLockout(ctx, user.ID, ip)
	s.clearIdentityFailures(ctx, email)

	// Enforce session count limit (new family only)
	if err := s.checkSessionLimit(ctx, user.ID); err != nil {
		return nil, err
	}

	// Find or create device (non-critical — log but don't fail)
	deviceID := s.findOrCreateDevice(ctx, user.ID, fp, ip, ua)

	// Issue tokens — use the user's persisted Roles, admin-filtered and
	// catalog-validated, falling back to the historical default ["user"].
	jwtRoles := s.effectiveRoles(ctx, user.Roles)
	// A single-step login completed on the memorized secret alone, so the token
	// says AAL1 and names the one factor it saw (OIDC Core §2).
	pair, err := s.tokenSvc.IssueTokenPairWithAuth(
		ctx, user.ID, jwtRoles, []string{"read", "write"},
		input.ClientID, fp, "", input.RememberMe,
		NewAuthContext(time.Now(), []string{MethodPassword}, false),
	)
	if err != nil {
		return nil, err
	}

	if err := s.storeRefreshToken(ctx, user.ID, input.ClientID, deviceID, fp, pair); err != nil {
		return nil, err
	}

	// Stamp last successful login (legacy-platform parity); best-effort.
	if err := s.users.SetLastLogin(ctx, user.ID); err != nil {
		log.Printf("auth: failed to set last_login for %s: %v", user.ID, err)
	}

	if s.metrics != nil {
		s.metrics.RecordLoginSuccess()
		s.metrics.RecordTokenIssued()
	}
	s.auditLog.Log(ctx, audit.LoginSuccess, user.ID, input.ClientID, ip, ua, fp, deviceID, nil, 0) // #nosec G104 -- audit is best-effort, never blocks auth flow

	// New-location notice (AR-18): out of band, country granularity only, so it
	// never blocks or fails the login.
	deferwork.Go(func(context.Context) { s.notifyNewCountry(user.ID, user.Email, ip, app) })

	return &LoginResult{
		AccessToken:  pair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokenSvc.accessTokenTTL.Seconds()),
		RefreshToken: pair.RefreshToken,
		CookieMaxAge: int(time.Until(pair.RefreshExpAt).Seconds()),
	}, nil
}

// trapLogin answers a planted credential the way a successful login answers a
// real one.
//
// It repeats the round trips a success makes, because an attacker measures the
// endpoint as well as reading it. The reads it repeats are the ones the
// honeypot's own database can answer for a user id that is not in it, so none of
// them writes a row or trips a foreign key. The two writes a real success makes
// that would need the row to exist, the refresh-token insert and the device
// insert, are left out; that residual is the one part of the timing gap this
// path does not close.
//
// Every lookup is keyed by the same id the token's sub carries, so the honeypot
// queries the account it claims to have authenticated.
func (s *AuthService) trapLogin(ctx context.Context, input LoginInput, email, ip, ua string) (*LoginResult, error) {
	// The dummy Argon2id burn every non-authenticating path shares.
	if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
		return nil, err // 503, the same status the real-user path answers with under load
	}

	// Fire the alert asynchronously: the request context is canceled once the
	// response is written, and the caller must not be able to time the alert.
	//
	// On the bounded pool rather than a bare goroutine. A trap login is
	// unauthenticated and attacker-triggered, and Alert opens an outbound
	// connection to the operator's alerting endpoint, so a bare `go` let the
	// attacker choose how many of those this process holds open at once.
	event := honeypot.HoneypotEvent{
		Timestamp: time.Now(),
		EventType: "trap_login",
		IP:        ip,
		UserAgent: ua,
		Email:     email,
		RiskScore: 100,
	}
	deferwork.Go(func(ctx context.Context) { s.honeypotAlert.Alert(ctx, event) })

	// The user id this address is answered with, on every login for the life of
	// the process. It is both the token's subject and the key of the lookups
	// below, so the two cannot drift apart.
	sub, err := honeypot.TrapSubject(email)
	if err != nil {
		return nil, fmt.Errorf("honeypot: trap subject: %w", err)
	}

	// The counter reset and lockout clear a success does. Every repository call
	// on this path is issued for its round trip and its result is deliberately
	// not consulted: there is no user row behind this id, so there is nothing a
	// caller or an operator could do with the answer, and a log line per trap
	// login would hand the attacker the honeypot's disk.
	_ = s.users.ResetFailedLogin(ctx, sub)
	s.clearLockout(ctx, sub, ip)
	s.clearIdentityFailures(ctx, email)

	input.Fingerprint.IP = ip
	input.Fingerprint.UserAgent = ua
	fp := vaultcrypto.ComputeFingerprint(input.Fingerprint)

	// The second-factor gate. With VAULT_MFA_REQUIRED=true every login in the
	// deployment answers with a challenge and no tokens, so a trap login that
	// handed tokens straight back was the only login in the system that did not,
	// and the attacker learns the deployment's policy from any other account.
	//
	// The email OTP a real fallback sends is deliberately not sent. The trap
	// address is operator-configured and usually has no mailbox, the attacker
	// cannot observe whether mail went out, and the real send is asynchronous, so
	// omitting it costs neither realism nor time and avoids turning a login loop
	// into a mail amplifier pointed at the operator.
	if s.mfaSvc != nil {
		status, _ := s.mfaSvc.GetStatus(ctx, sub)
		hasMethods := status != nil && len(status.Methods) > 0
		if hasMethods || s.mfaSvc.IsRequired() {
			methods := []string{"email_otp"}
			if hasMethods {
				methods = status.Methods
			}
			challengePair, err := s.tokenSvc.IssueChallengeToken(ctx, sub, fp, MethodPassword)
			if err != nil {
				return nil, fmt.Errorf("issue 2FA challenge: %w", err)
			}
			s.auditLog.Log(ctx, audit.LoginSuccess, sub, input.ClientID, ip, ua, fp, "", // #nosec G104 -- audit is best-effort, never blocks auth flow
				map[string]interface{}{"mfa_required": true}, 0)
			return &LoginResult{
				Requires2FA:      true,
				ChallengeToken:   challengePair,
				AvailableMethods: methods,
			}, nil
		}
	}

	if err := s.checkSessionLimit(ctx, sub); err != nil {
		return nil, err
	}
	// The device lookup a success makes. The insert that follows it on a real
	// success needs the user row to exist, so only the read is repeated.
	_, _ = s.devices.GetByFingerprint(ctx, sub, fp)

	fakeJWT, err := honeypot.GenerateFakeJWTForIdentity(honeypot.TrapCaller{
		Identity:    email,
		ClientID:    input.ClientID,
		Fingerprint: fp,
	})
	if err != nil {
		return nil, fmt.Errorf("honeypot: fake JWT: %w", err)
	}
	fakeRefresh, err := honeypot.GenerateFakeRefresh()
	if err != nil {
		return nil, fmt.Errorf("honeypot: fake refresh: %w", err)
	}

	_ = s.users.SetLastLogin(ctx, sub)

	// /metrics is unauthenticated. Counting the attempt and not the success let
	// an attacker scrape before and after a login they had just been handed
	// tokens for and watch vault_login_success_total stand still, which says the
	// endpoint did not consider it a login.
	if s.metrics != nil {
		s.metrics.RecordLoginSuccess()
		s.metrics.RecordTokenIssued()
	}
	s.auditLog.Log(ctx, audit.LoginSuccess, sub, input.ClientID, ip, ua, fp, "", nil, 0) // #nosec G104 -- audit is best-effort, never blocks auth flow

	return &LoginResult{
		AccessToken:  fakeJWT,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokenSvc.accessTokenTTL.Seconds()),
		RefreshToken: fakeRefresh,
		CookieMaxAge: s.trapCookieMaxAge(input.RememberMe),
	}, nil
}

// trapCookieMaxAge is the refresh-cookie lifetime a real login would have
// answered this caller with, remember-me and the absolute session bound
// included.
//
// The trap used to answer with the ordinary refresh TTL whatever the caller
// asked for. The two lifetimes are days apart and arrive in a Set-Cookie header,
// so a remember_me login that comes back with the short cookie is read off one
// response.
func (s *AuthService) trapCookieMaxAge(rememberMe bool) int {
	ttl := s.tokenSvc.refreshTokenTTL
	if rememberMe {
		ttl = s.tokenSvc.rememberMeTTL
	}
	// The same clamp IssueTokenPair applies to a new family.
	if bound := s.tokenSvc.MaxSessionLifetime(); bound > 0 && bound < ttl {
		ttl = bound
	}
	return int(ttl.Seconds())
}

// recordLoginFailure applies the bookkeeping every rejected login shares: the DB
// and cache failure counters, the per-IP counter, the metric, an audit entry, and
// the once-per-window account-locked notification.
//
// SECURITY INVARIANT (anti-enumeration): every post-lookup outcome that is not a
// successful authentication goes through this one function, so the paths cannot
// drift apart into distinguishable side effects — lockout advances at the same
// rate and trips at the same threshold whatever the reason was. Only the audit
// reason differs, and the audit log is not visible to the caller.
func (s *AuthService) recordLoginFailure(ctx context.Context, user *model.User, ip, ua, app, reason string, riskScore int) {
	// Failed-login counter is best-effort; lockout is enforced by isAccountLocked.
	_ = s.users.IncrementFailedLogin(ctx, user.ID)
	s.recordFailedAttempt(ctx, user.ID, ip)
	s.recordFailedIP(ctx, ip)
	if s.metrics != nil {
		s.metrics.RecordLoginFailed()
	}
	s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
		map[string]interface{}{"reason": reason}, riskScore)

	// Send lock notification email once per lockout window
	if s.isAccountLocked(ctx, user.ID, ip) && s.cache != nil && s.emailSender != nil {
		lockNotifyKey := fmt.Sprintf("lock_notified:%s", user.ID)
		if sent, _ := s.cache.SetIfNotExists(ctx, lockNotifyKey, "1", lockoutDuration); sent {
			deferwork.Go(func(ctx context.Context) {
				// Email is best-effort.
				_ = s.emailMailer().Send(ctx, app, vaultemail.TemplateAccountLocked, user.Email, vaultemail.TemplateData{
					IP: ip,
				})
			})
		}
	}
}

// RefreshResult is the token refresh response.
type RefreshResult struct {
	AccessToken  string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"-"` // new refresh token (cookie)
	CookieMaxAge int    `json:"-"` // refresh cookie maxage in seconds
}

// Refresh exchanges a refresh token for a new token pair.
func (s *AuthService) Refresh(ctx context.Context, refreshToken, ip, ua string, fpInput vaultcrypto.FingerprintInput) (*RefreshResult, error) {
	tokenHash := vaultcrypto.SHA256Hex(refreshToken)

	stored, err := s.tokens.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, ErrTokenInvalid
	}

	// Check revoked
	if stored.Revoked {
		return nil, ErrTokenInvalid
	}

	// Replay detection: if already used → revoke entire family
	if stored.Used {
		s.tokens.RevokeFamily(ctx, stored.FamilyID)                                            // #nosec G104 -- best-effort revocation; returning ErrReplayDetected regardless
		s.auditLog.Log(ctx, audit.TokenRevoke, stored.UserID, stored.ClientID, ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "replay_detected", "family_id": stored.FamilyID}, 90)
		return nil, ErrReplayDetected
	}

	// Check expired
	if time.Now().After(stored.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Absolute session lifetime: reject before the presented token is consumed,
	// so an over-age family is terminated rather than rotated.
	familyOrigin, err := s.enforceSessionLifetime(ctx, stored, ip, ua)
	if err != nil {
		return nil, err
	}

	// Verify fingerprint
	fpInput.IP = ip
	fpInput.UserAgent = ua
	fp := vaultcrypto.ComputeFingerprint(fpInput)
	if stored.FingerprintHash != "" && !vaultcrypto.CompareFingerprints(stored.FingerprintHash, fp) {
		s.tokens.RevokeFamily(ctx, stored.FamilyID)                                                   // #nosec G104 -- best-effort revocation; returning ErrTokenInvalid regardless
		s.auditLog.Log(ctx, audit.FingerprintAnomaly, stored.UserID, stored.ClientID, ip, ua, fp, "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"expected": stored.FingerprintHash}, 70)
		return nil, ErrTokenInvalid
	}

	// Atomically mark old token as used (CAS: only succeeds if not already used)
	updated, err := s.tokens.MarkUsed(ctx, stored.ID)
	if err != nil {
		return nil, err
	}
	if !updated {
		// Concurrent request already consumed this token — treat as replay
		s.tokens.RevokeFamily(ctx, stored.FamilyID)                                            // #nosec G104 -- best-effort revocation; returning ErrReplayDetected regardless
		s.auditLog.Log(ctx, audit.TokenRevoke, stored.UserID, stored.ClientID, ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "concurrent_replay_detected", "family_id": stored.FamilyID}, 90)
		return nil, ErrReplayDetected
	}

	// Issue new pair in same family — re-fetch the user to pick up the
	// latest persisted Roles (refresh path must reflect role changes
	// since the original login).
	refreshUser, _ := s.users.GetByID(ctx, stored.UserID)
	// Account state can change between login and refresh — a banned, disabled,
	// deleted (or vanished) account must not mint new tokens. Revoke the whole
	// family so the session is fully terminated, not just this rotation.
	//
	// A lock counts, and its absence here made the documented response to a
	// suspected takeover ineffective. An operator locks the account; the attacker
	// keeps rotating a refresh token they already hold; the session survives for
	// the absolute session lifetime (720h by default, unbounded when
	// VAULT_MAX_SESSION_LIFETIME is 0) rather than the remaining access-token TTL
	// that docs/security.md AR-5 promised. Login has always rejected a lock, so
	// locking stopped exactly the sessions that had not started yet.
	refreshLocked := refreshUser != nil && refreshUser.LockedUntil != nil &&
		time.Now().Before(*refreshUser.LockedUntil)
	if refreshUser == nil || refreshUser.Deleted || refreshUser.Banned || refreshUser.Disabled || refreshLocked {
		s.tokens.RevokeFamily(ctx, stored.FamilyID) // #nosec G104 -- best-effort; reject regardless
		switch {
		case refreshUser != nil && refreshUser.Banned:
			return nil, ErrAccountBanned
		case refreshUser != nil && refreshUser.Disabled:
			return nil, ErrAccountDisabled
		case refreshLocked:
			return nil, ErrAccountLocked
		default:
			return nil, ErrTokenInvalid
		}
	}
	refreshRoles := s.effectiveRoles(ctx, refreshUser.Roles)
	pair, err := s.issueRotatedPair(ctx, stored, refreshRoles, fp, familyOrigin, ip, ua)
	if err != nil {
		return nil, err
	}

	if s.metrics != nil {
		s.metrics.RecordTokenRefreshed()
	}
	s.auditLog.Log(ctx, audit.TokenRefresh, stored.UserID, stored.ClientID, ip, ua, fp, stored.DeviceID, nil, 0) // #nosec G104 -- audit is best-effort, never blocks auth flow

	return &RefreshResult{
		AccessToken:  pair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokenSvc.accessTokenTTL.Seconds()),
		RefreshToken: pair.RefreshToken,
		CookieMaxAge: int(time.Until(pair.RefreshExpAt).Seconds()),
	}, nil
}

// issueRotatedPair mints the successor of a consumed refresh token and persists
// it in the same family.
//
// SECURITY INVARIANT (reuse detection): the store refuses to insert into a family
// that has been revoked, and that refusal is reported as the replay it is. Two
// requests presenting one stolen token both pass every check on the row they
// read; one consumes it and the other, having lost that race, revokes the family.
// The revocation only covers the rows that exist at that instant, so the winner's
// successor is a token nothing has ever revoked. Treating the refused insert as a
// successful rotation is what let the winner keep a rotating session for the rest
// of the absolute session lifetime while the loser was told replay_detected and
// the operator read the same in the audit log.
func (s *AuthService) issueRotatedPair(ctx context.Context, stored *model.RefreshToken, roles []string, fp string, familyOrigin time.Time, ip, ua string) (*TokenPair, error) {
	pair, err := s.tokenSvc.IssueRotatedPair(
		ctx, stored.UserID, roles, []string{"read", "write"},
		stored.ClientID, fp, stored.FamilyID, familyOrigin,
	)
	if err != nil {
		return nil, err
	}

	newID, err := vaultcrypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token ID: %w", err)
	}
	if err := s.tokens.Create(ctx, &model.RefreshToken{
		ID: newID, UserID: stored.UserID, ClientID: stored.ClientID,
		TokenHash: vaultcrypto.SHA256Hex(pair.RefreshToken), FamilyID: stored.FamilyID,
		DeviceID: stored.DeviceID, FingerprintHash: fp,
		ExpiresAt: pair.RefreshExpAt, CreatedAt: time.Now(),
	}); err != nil {
		if errors.Is(err, repository.ErrFamilyRevoked) {
			s.tokens.RevokeFamily(ctx, stored.FamilyID)                                            // #nosec G104 -- best-effort revocation; returning ErrReplayDetected regardless
			s.auditLog.Log(ctx, audit.TokenRevoke, stored.UserID, stored.ClientID, ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
				map[string]interface{}{"reason": "family_revoked_during_rotation", "family_id": stored.FamilyID}, 90)
			return nil, ErrReplayDetected
		}
		return nil, err
	}
	return pair, nil
}

// Logout revokes all refresh tokens for a user.
func (s *AuthService) Logout(ctx context.Context, userID, ip, ua string) error {
	if err := s.tokens.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}
	s.auditLog.Log(ctx, audit.TokenRevoke, userID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
		map[string]interface{}{"reason": "logout"}, 0)
	return nil
}

// RevokeAllTokensForUser nukes every active refresh-token family for the
// given user. Used by post-incident security paths (e.g. WebAuthn clone-warning,
// administrative lock) where the SDK suspects a credential has been compromised.
// Caller is responsible for emitting any incident-specific audit log; this
// method does not.
func (s *AuthService) RevokeAllTokensForUser(ctx context.Context, userID string) error {
	return s.tokens.RevokeAllForUser(ctx, userID)
}

// MFACompletion describes the second factor that finished an MFA login and the
// factors that preceded it, so the issued token can state the combination
// rather than assume one.
type MFACompletion struct {
	// Method is the authenticator just verified.
	Method string
	// UserVerified is the WebAuthn user-verification flag from the assertion.
	// It is false for every other authenticator, and it is what separates AAL3
	// from AAL2 on the WebAuthn path.
	UserVerified bool
	// Prior lists the factors completed before the challenge was minted, read
	// off the challenge token. Empty derives AAL1 rather than assuming a
	// password: a federated login reaches this path too.
	Prior []string
}

// methods is the full factor list the completed login presented.
func (c MFACompletion) methods() []string {
	return append(append([]string{}, c.Prior...), c.Method)
}

// CompleteMFALogin issues tokens after successful MFA verification.
// Called by TOTP verify and WebAuthn verify handlers when a 2fa_challenge token is presented.
// The jti parameter enforces single-use: once consumed, the same challenge token is rejected.
func (s *AuthService) CompleteMFALogin(ctx context.Context, userID, fingerprint, ip, ua, jti string, completion MFACompletion) (*LoginResult, error) {
	// Enforce challenge token single-use via cache.
	// SECURITY: fail closed — if cache is unavailable, reject the request.
	if s.cache != nil && jti != "" {
		set, err := s.cache.SetIfNotExists(ctx, "challenge_used:"+jti, "1", 5*time.Minute)
		if err != nil {
			log.Printf("auth: challenge token single-use check failed (rejecting): %v", err)
			return nil, fmt.Errorf("mfa verification unavailable: %w", err)
		}
		if !set {
			return nil, ErrChallengeConsumed
		}
	}
	// Successful second factor clears this source's failure counter (audit H2).
	// The account-wide counter is left to expire: it exists to see the other
	// sources still guessing, and one success must not erase them.
	s.clearLockout(ctx, userID, ip)
	// Enforce session count limit (new family only)
	if err := s.checkSessionLimit(ctx, userID); err != nil {
		return nil, err
	}

	// Find or create device (non-critical — log but don't fail)
	deviceID := s.findOrCreateDevice(ctx, userID, fingerprint, ip, ua)

	// Issue tokens — same per-user roles flow as the password login
	// path; 2FA verify shares the post-auth shape.
	mfaUser, mfaErr := s.users.GetByID(ctx, userID)

	// Account state is re-read here rather than trusted from the password step.
	// Minutes pass between the two: the challenge TTL is the window, and it is
	// exactly the window in which an operator reacting to a compromise bans,
	// disables or locks the account. Without this gate the second factor issued a
	// full session to a subject the platform had already cut off, and Login,
	// Refresh and the OAuth callback all gate here, so its absence was an
	// oversight rather than a policy.
	//
	// Fail closed when the subject cannot be resolved to a live account. A read
	// fault (mfaErr) previously fell through as a nil user, skipping the gate
	// below and minting a session with default roles for an account the fault hid
	// the banned/disabled state of; a genuine no-row means the subject was deleted
	// inside the challenge window. Refresh rejects both the same way. Issuing a
	// second-factor session for an unresolvable subject is never correct.
	if mfaErr != nil || mfaUser == nil {
		return nil, ErrTokenInvalid
	}
	switch {
	case mfaUser.Deleted:
		return nil, ErrTokenInvalid
	case mfaUser.Banned:
		return nil, ErrAccountBanned
	case mfaUser.Disabled:
		return nil, ErrAccountDisabled
	case mfaUser.LockedUntil != nil && time.Now().Before(*mfaUser.LockedUntil):
		return nil, ErrAccountLocked
	}

	mfaRoles := s.effectiveRoles(ctx, mfaUser.Roles)
	pair, err := s.tokenSvc.IssueTokenPairWithAuth(
		ctx, userID, mfaRoles, []string{"read", "write"},
		"", fingerprint, "", false,
		NewAuthContext(time.Now(), completion.methods(), completion.UserVerified),
	)
	if err != nil {
		return nil, err
	}

	if err := s.storeRefreshToken(ctx, userID, "", deviceID, fingerprint, pair); err != nil {
		return nil, err
	}

	// Stamp last successful login (legacy-platform parity); best-effort.
	if err := s.users.SetLastLogin(ctx, userID); err != nil {
		log.Printf("auth: failed to set last_login for %s: %v", userID, err)
	}

	if s.metrics != nil {
		s.metrics.RecordLoginSuccess()
		s.metrics.RecordTokenIssued()
	}
	s.auditLog.Log(ctx, audit.LoginSuccess, userID, "", ip, ua, fingerprint, deviceID, // #nosec G104 -- audit is best-effort, never blocks auth flow
		map[string]interface{}{"mfa_completed": true}, 0)

	// New-location notice (AR-18) also fires on the MFA-completion path, so a
	// login that finishes via a second factor gets the same country signal as a
	// single-step one. Out of band, country granularity only. mfaUser is the
	// re-read account resolved above (non-nil past the account-state gate).
	app := vaultemail.AppFromContext(ctx)
	deferwork.Go(func(context.Context) { s.notifyNewCountry(userID, mfaUser.Email, ip, app) })

	return &LoginResult{
		AccessToken:  pair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokenSvc.accessTokenTTL.Seconds()),
		RefreshToken: pair.RefreshToken,
		CookieMaxAge: int(time.Until(pair.RefreshExpAt).Seconds()),
	}, nil
}

// SendEmailOTP generates a 6-digit code, HMACs it, caches the signature, and sends the code via email.
func (s *AuthService) SendEmailOTP(ctx context.Context, userID, emailAddr string) error {
	return s.doSendEmailOTP(ctx, userID, emailAddr, vaultemail.AppFromContext(ctx))
}

// sendEmailOTP is the fire-and-forget version called from the login flow goroutine.
func (s *AuthService) sendEmailOTP(userID, emailAddr, app string) {
	ctx := context.Background()
	if err := s.doSendEmailOTP(ctx, userID, emailAddr, app); err != nil {
		log.Printf("auth: failed to send email OTP to %s: %v", userID, err)
	}
}

// emailOTPAllowed reports whether email-OTP is a permitted second factor for
// this user. It mirrors the Login gate (see Login ~"No MFA methods configured
// but MFA is required"): email-OTP is only a fallback for users with NO stronger
// enrolled factor (TOTP/WebAuthn/backup) when MFA is required. Without this gate
// a challenge-token holder could downgrade a hardware/TOTP factor to a 6-digit
// email code (security audit H1). Fails closed on error.
func (s *AuthService) emailOTPAllowed(ctx context.Context, userID string) bool {
	if s.mfaSvc == nil {
		return false
	}
	status, err := s.mfaSvc.GetStatus(ctx, userID)
	if err != nil {
		log.Printf("auth: MFA status check failed for %s: %v", userID, err)
		return false
	}
	hasStrongMethod := status != nil && len(status.Methods) > 0
	return !hasStrongMethod && s.mfaSvc.IsRequired()
}

func (s *AuthService) doSendEmailOTP(ctx context.Context, userID, emailAddr, app string) error {
	if !s.emailOTPAllowed(ctx, userID) {
		return ErrEmailOTPNotAllowed
	}
	if s.cache == nil || s.emailSender == nil {
		return fmt.Errorf("email OTP requires cache and email sender")
	}

	b, err := vaultcrypto.RandomBytes(4)
	if err != nil {
		return fmt.Errorf("generate OTP: %w", err)
	}
	// The buffer is the OTP before it is decimalised, so it is the code. Clear it
	// once the code is derived; the code itself is a Go string and cannot be
	// cleared (AR-4), which is why its cache TTL is five minutes.
	defer config.ZeroBytes(b)
	code := fmt.Sprintf("%06d", binary.BigEndian.Uint32(b)%1000000)

	sig := vaultcrypto.HMACSign([]byte(code), s.hmacSecret)
	cacheKey := "email_otp:" + userID
	if err := s.cache.Set(ctx, cacheKey, sig, 5*time.Minute); err != nil {
		return fmt.Errorf("cache OTP: %w", err)
	}

	if err := s.emailMailer().Send(ctx, app, vaultemail.TemplateEmailOTP, emailAddr, vaultemail.TemplateData{
		Code: code,
	}); err != nil {
		return fmt.Errorf("send OTP email: %w", err)
	}
	return nil
}

// VerifyEmailOTP verifies a 6-digit email OTP code. Single-use via atomic GetAndDelete.
func (s *AuthService) VerifyEmailOTP(ctx context.Context, userID, code string) error {
	// Defense-in-depth against MFA downgrade (audit H1): even if a code exists in
	// the cache, refuse to accept email-OTP as a factor for a user who has a
	// stronger enrolled method. Consume nothing on the gated path.
	if !s.emailOTPAllowed(ctx, userID) {
		return ErrInvalidCredentials
	}
	if s.cache == nil {
		return ErrInvalidCredentials
	}
	cacheKey := "email_otp:" + userID
	sig, err := s.cache.GetAndDelete(ctx, cacheKey)
	if err != nil || sig == "" {
		return ErrInvalidCredentials
	}
	if !vaultcrypto.HMACVerify([]byte(code), s.hmacSecret, sig) {
		return ErrInvalidCredentials
	}
	return nil
}

// FindOrCreateDevice resolves the device a session belongs to on behalf of a
// login path that mints its refresh-token family outside Login and
// CompleteMFALogin.
//
// The OAuth/social callback writes the refresh-token row itself, so it needs the
// same device binding the password path applies. Without it the row carries a
// NULL device_id, the session never shows in GET /user/sessions (which lists
// devices), and RevokeByDeviceID cannot reach it because its WHERE device_id =
// $1 never matches a NULL. Semantics match the password path, including the
// non-critical, log-but-do-not-fail behavior of findOrCreateDevice.
func (s *AuthService) FindOrCreateDevice(ctx context.Context, userID, fp, ip, ua string) string {
	return s.findOrCreateDevice(ctx, userID, fp, ip, ua)
}

// findOrCreateDevice looks up a device by fingerprint or creates a new one.
// This is non-critical — errors are logged but do not fail the auth flow.
func (s *AuthService) findOrCreateDevice(ctx context.Context, userID, fp, ip, ua string) string {
	device, err := s.devices.GetByFingerprint(ctx, userID, fp)
	if err != nil {
		log.Printf("auth: failed to lookup device for %s: %v", userID, err)
	}
	if device == nil {
		deviceID, err := vaultcrypto.RandomUUID()
		if err != nil {
			log.Printf("auth: failed to generate device ID: %v", err)
			return ""
		}
		now := time.Now()
		if err := s.devices.Create(ctx, &model.Device{
			ID: deviceID, UserID: userID, FingerprintHash: fp,
			FriendlyName: useragent.FriendlyName(ua),
			IP:           ip, UserAgent: ua, FirstSeenAt: now, LastSeenAt: &now, CreatedAt: now,
		}); err != nil {
			// Handle TOCTOU race: another request may have created the device
			// between our lookup and insert (unique constraint violation).
			if isUniqueViolation(err) {
				device, _ = s.devices.GetByFingerprint(ctx, userID, fp)
				if device != nil {
					return device.ID
				}
			}
			log.Printf("auth: failed to create device: %v", err)
		}
		return deviceID
	}
	if err := s.devices.UpdateLastSeen(ctx, device.ID, ip); err != nil {
		log.Printf("auth: failed to update device last seen: %v", err)
	}
	return device.ID
}

// lockedByStoredCount enforces the lockout threshold from the durable
// failed_login_count column.
//
// It is coarser than the cache counter, because nothing expires it by TTL, and
// that is the trade: it never auto-resets, but it cannot be erased by losing a
// cache. A read failure here answers "not locked", since refusing every login
// because the user table is unreachable would turn a database blip into a total
// outage, and the caller cannot authenticate without that table anyway.
func (s *AuthService) lockedByStoredCount(ctx context.Context, userID string) bool {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return false
	}
	if user.FailedLoginCount >= lockoutThreshold {
		log.Printf("auth: lockout enforced from the stored count for user %s (cache unavailable)", userID)
		return true
	}
	return false
}

// accountLockoutKey is the account-wide failure counter: every source, one key.
// It is what the distributed threshold reads.
func accountLockoutKey(userID string) string {
	return fmt.Sprintf("lockout:%s", userID)
}

// sourceLockoutKey is the per-(account, source address) failure counter, and the
// one the hard lock is enforced from.
//
// An unknown source ("" — a CLI call, a background task, a request that did not
// come through the HTTP edge) gets its own shared bucket rather than being
// silently exempted. Exempting it would let anyone who can reach the service
// without a resolvable address bypass the lock entirely.
func sourceLockoutKey(userID, ip string) string {
	return fmt.Sprintf("lockout:%s|%s", userID, ip)
}

// cachedCount reads a counter key, reporting whether the cache could answer at
// all.
//
// A key that is absent is a successful read of zero, not a failure. That is what
// an account with no recent failures looks like, and it is the overwhelming
// majority of logins: treating it as a failure would put a database read in
// front of nearly every one of them to learn what the cache just answered
// correctly. Only a real error — a refused connection, a timeout — falls back to
// the durable count.
func (s *AuthService) cachedCount(ctx context.Context, key string) (n int, ok bool) {
	val, err := s.cache.Get(ctx, key)
	if errors.Is(err, cache.ErrNotFound) {
		return 0, true
	}
	if err != nil {
		return 0, false
	}
	if val == "" {
		return 0, true
	}
	fmt.Sscanf(val, "%d", &n) // #nosec G104 -- parse failure returns 0, which means not locked
	return n, true
}

// isAccountLocked reports whether this account is locked to this source.
//
// Two counters, two thresholds. The per-source counter is the ordinary
// brute-force control and trips at lockoutThreshold exactly as before, but it
// only ever locks the address that earned it. The account-wide counter trips at
// distributedLockoutThreshold, which no single source can reach on its own.
//
// Both fall back to the durable failed_login_count when the cache cannot answer,
// because a lockout that stops holding the moment the cache breaks is not a
// lockout — and a degraded cache still reports ready, so the pods stay in
// rotation while it is down.
func (s *AuthService) isAccountLocked(ctx context.Context, userID, ip string) bool {
	if s.cache == nil {
		return s.lockedByStoredCount(ctx, userID)
	}
	perSource, ok := s.cachedCount(ctx, sourceLockoutKey(userID, ip))
	if !ok {
		return s.lockedByStoredCount(ctx, userID)
	}
	if perSource >= lockoutThreshold {
		return true
	}
	account, ok := s.cachedCount(ctx, accountLockoutKey(userID))
	if !ok {
		return s.lockedByStoredCount(ctx, userID)
	}
	return account >= distributedLockoutThreshold
}

// recordFailedAttempt advances both lockout counters for the user: the one for
// the source that failed, and the account-wide one the distributed threshold
// reads.
func (s *AuthService) recordFailedAttempt(ctx context.Context, userID, ip string) {
	if s.cache == nil {
		return
	}
	s.cache.Increment(ctx, sourceLockoutKey(userID, ip), lockoutDuration) // #nosec G104 -- best-effort lockout counter
	s.cache.Increment(ctx, accountLockoutKey(userID), lockoutDuration)    // #nosec G104 -- best-effort lockout counter
}

// clearLockout resets this source's lockout counter on successful login.
//
// The account-wide counter is deliberately NOT cleared. It exists to see a
// distributed attack, and one successful login — which an attacker who has
// guessed a password can produce — must not erase the evidence of the other
// sources still guessing. It expires on its own after lockoutDuration.
func (s *AuthService) clearLockout(ctx context.Context, userID, ip string) {
	if s.cache == nil {
		return
	}
	s.cache.Delete(ctx, sourceLockoutKey(userID, ip)) // #nosec G104 -- best-effort counter reset
}

// identityThrottleKey is the failure counter behind the progressive login delay.
//
// Keyed on the submitted address, not on a user id, so an address with no
// account accrues it identically — a throttle only real accounts pay would tell
// an unauthenticated caller which addresses are registered. Peppered and hashed
// so a reader of the cache cannot enumerate the addresses that have been tried.
func (s *AuthService) identityThrottleKey(email string) string {
	return "auththrottle:" + vaultcrypto.SHA256Hex(s.pepper+"|auththrottle|"+email)
}

// loginThrottleDelay is the delay owed for a given number of recent failures.
// Zero up to lockoutThreshold, then doubling from loginThrottleBase, capped at
// loginThrottleMax.
func loginThrottleDelay(failures int) time.Duration {
	if failures <= lockoutThreshold {
		return 0
	}
	d := loginThrottleBase
	for i := lockoutThreshold + 1; i < failures; i++ {
		d *= 2
		if d >= loginThrottleMax {
			return loginThrottleMax
		}
	}
	return d
}

// throttleLogin sleeps the delay this identity's recent failures have earned.
//
// Interruptible: a client that hangs up frees the goroutine immediately, so the
// throttle cannot be turned into a way to pin server goroutines.
func (s *AuthService) throttleLogin(ctx context.Context, email string) {
	if s.cache == nil {
		return
	}
	n, ok := s.cachedCount(ctx, s.identityThrottleKey(email))
	if !ok {
		return
	}
	d := loginThrottleDelay(n)
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// recordIdentityFailure advances the throttle counter for a submitted address.
func (s *AuthService) recordIdentityFailure(ctx context.Context, email string) {
	if s.cache == nil {
		return
	}
	s.cache.Increment(ctx, s.identityThrottleKey(email), lockoutDuration) // #nosec G104 -- best-effort throttle counter
}

// clearIdentityFailures drops the throttle counter once the address has proven
// the password, so a user who mistyped six times is not still paying for it.
func (s *AuthService) clearIdentityFailures(ctx context.Context, email string) {
	if s.cache == nil {
		return
	}
	s.cache.Delete(ctx, s.identityThrottleKey(email)) // #nosec G104 -- best-effort counter reset
}

// MFAVerifyLocked reports whether the account is locked out from further auth
// attempts by the caller's source. MFA verify endpoints MUST call this before
// checking a second factor: the per-IP rate limit alone is defeated by IP
// rotation, so without a per-account gate the second factor is brute-forceable
// within the challenge window (audit H2).
//
// The source address comes from the request context rather than the signature,
// so the four MFA handlers did not have to change. A context with no address
// (a CLI call, a test) still gets a gate: it reads the shared unknown-source
// bucket, never an exemption.
func (s *AuthService) MFAVerifyLocked(ctx context.Context, userID string) bool {
	return s.isAccountLocked(ctx, userID, httputil.ClientIPFromContext(ctx))
}

// RecordMFAFailure counts a failed second-factor attempt toward the lockout for
// this (account, source) pair and toward the account-wide distributed counter,
// so password and MFA failures from one address still trip the same
// lockoutThreshold within lockoutDuration. Reset on success via clearLockout in
// CompleteMFALogin (audit H2).
func (s *AuthService) RecordMFAFailure(ctx context.Context, userID, ip, ua string) {
	s.recordFailedAttempt(ctx, userID, ip)
	if s.auditLog != nil {
		s.auditLog.Log(ctx, audit.LoginFailure, userID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort
			map[string]interface{}{"reason": "mfa_failed"}, 30)
	}
}

// isIPLocked checks the IP-based lockout counter. This limits credential
// stuffing and password spraying from a single source IP.
// When the cache is unavailable, falls back to the rate limit repository
// (PostgreSQL-backed) to maintain IP lockout protection.
func (s *AuthService) isIPLocked(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	if s.cache == nil {
		if s.rateLimits != nil {
			window := time.Now().Truncate(lockoutDuration)
			count, err := s.rateLimits.Get(ctx, "lockout_ip:"+ip, window)
			if err != nil {
				log.Printf("auth: IP lockout DB fallback failed for %s: %v", httputil.ObfuscatedIP(ip), err)
				return false
			}
			return count >= ipLockoutThreshold
		}
		log.Printf("auth: WARNING: IP lockout check unavailable (cache nil)")
		return false
	}
	key := "lockout_ip:" + ip
	val, err := s.cache.Get(ctx, key)
	if err != nil || val == "" {
		return false
	}
	var n int
	fmt.Sscanf(val, "%d", &n) // #nosec G104 -- parse failure returns 0, which means not locked
	return n >= ipLockoutThreshold
}

// recordFailedIP increments the IP-based lockout counter.
// Falls back to the rate limit repository when cache is unavailable.
func (s *AuthService) recordFailedIP(ctx context.Context, ip string) {
	if ip == "" {
		return
	}
	if s.cache == nil {
		if s.rateLimits != nil {
			window := time.Now().Truncate(lockoutDuration)
			if _, err := s.rateLimits.Increment(ctx, "lockout_ip:"+ip, window); err != nil {
				log.Printf("auth: IP lockout DB fallback increment failed for %s: %v", httputil.ObfuscatedIP(ip), err)
			}
			return
		}
		log.Printf("auth: WARNING: IP lockout unavailable (cache nil), brute-force protection degraded for IP %s", httputil.ObfuscatedIP(ip))
		return
	}
	key := "lockout_ip:" + ip
	s.cache.Increment(ctx, key, lockoutDuration) // #nosec G104 -- best-effort IP lockout counter
}

// CheckSessionLimit applies the concurrent-session-family cap on behalf of a
// login path that mints a family outside Login and CompleteMFALogin.
//
// The OAuth/social callback issues a pair and writes the refresh-token row
// itself, so without this call the cap is enforced on the password path and not
// on the social one, and a user is capped or uncapped depending on how they chose
// to sign in. The client-credentials grant is deliberately not a caller: it
// returns an access token only and never writes a refresh-token row, so it
// creates no family for CountActiveFamilies to count.
//
// This is the same soft pre-check Login runs before storeRefreshToken. The
// hard bound is CreateWithinCap on the insert, which the OAuth callback must
// also use: a pre-check alone is the race documented on checkSessionLimit.
func (s *AuthService) CheckSessionLimit(ctx context.Context, userID string) error {
	return s.checkSessionLimit(ctx, userID)
}

// enforceSessionLifetime applies the absolute session lifetime to a rotation and
// returns the family's origin so the reissued token can be clamped to it.
//
// SECURITY INVARIANT (NIST SP 800-63B-4 §2.2.3, NIST SP 800-53 Rev 5 AC-12):
// a refresh-token family is terminated once it reaches maxSessionLifetime,
// measured from the family's creation and unaffected by how often it was
// refreshed. Rotation issues a fresh refresh TTL every time, so without this the
// TTL is a sliding window and a continuously-refreshing client is never asked to
// reauthenticate.
//
// Every branch that cannot prove the family is inside the bound fails closed. The
// bound is off (zero origin, no error) only when it is not configured at all.
func (s *AuthService) enforceSessionLifetime(ctx context.Context, stored *model.RefreshToken, ip, ua string) (time.Time, error) {
	if s.tokenSvc == nil {
		return time.Time{}, nil
	}
	maxLifetime := s.tokenSvc.MaxSessionLifetime()
	if maxLifetime <= 0 {
		return time.Time{}, nil
	}

	reader, ok := s.tokens.(familyOriginReader)
	if !ok {
		// A bound was configured against a store that cannot date a family.
		// Refusing is the only outcome that is not a silent no-op.
		log.Printf("auth: refresh token store cannot report family origin; absolute session lifetime unenforceable")
		s.auditLog.Log(ctx, audit.TokenRevoke, stored.UserID, stored.ClientID, ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "session_age_unavailable", "cause": "store_unsupported"}, 80)
		return time.Time{}, ErrSessionAgeUnknown
	}

	origin, err := reader.FamilyOrigin(ctx, stored.FamilyID)
	if err != nil || origin.IsZero() {
		log.Printf("auth: family origin lookup failed for family %s: %v", stored.FamilyID, err)
		s.auditLog.Log(ctx, audit.TokenRevoke, stored.UserID, stored.ClientID, ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "session_age_unavailable", "cause": "lookup_failed"}, 80)
		return time.Time{}, ErrSessionAgeUnknown
	}

	if !time.Now().Before(origin.Add(maxLifetime)) {
		s.tokens.RevokeFamily(ctx, stored.FamilyID)                                            // #nosec G104 -- best-effort revocation; rejecting regardless
		s.auditLog.Log(ctx, audit.TokenRevoke, stored.UserID, stored.ClientID, ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{
				"reason":    "session_lifetime_exceeded",
				"family_id": stored.FamilyID,
				"age":       time.Since(origin).String(),
			}, 40)
		return time.Time{}, ErrSessionExpired
	}

	return origin, nil
}

// checkSessionLimit verifies that the user has not exceeded the maximum number of
// concurrent refresh token families. Returns ErrTooManySessions if the limit is reached.
// A maxSessionsPerUser of 0 disables the check.
//
// checkSessionLimit is a soft, best-effort cap on concurrent session families.
// It is intentionally NOT atomic with the subsequent token insert: concurrent
// logins by the SAME user can each pass this check and then insert, briefly
// exceeding the cap by the number of racing attempts. This is an accepted
// trade-off — making it strict would require serializing the login hot path
// (per-user advisory lock) or a count-conditional INSERT, adding latency/lock
// contention for every login to prevent a user marginally exceeding their own
// session cap (no auth bypass, bounded over-count). The cap converges as old
// families expire/revoke. Revisit only if the limit becomes a hard security
// boundary rather than a resource control.
func (s *AuthService) checkSessionLimit(ctx context.Context, userID string) error {
	if s.maxSessionsPerUser <= 0 {
		return nil
	}
	count, err := s.tokens.CountActiveFamilies(ctx, userID)
	if err != nil {
		log.Printf("auth: session count check failed for user %s: %v", userID, err)
		if s.strictSessionLimit {
			// Fail closed (audit L1): a count error must not silently disable the cap.
			s.auditLog.Log(ctx, audit.RateLimit, userID, "", "", "", "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
				map[string]interface{}{"reason": "session_limit_count_failed"}, 80)
			return ErrTooManySessions
		}
		return nil // fail open (default) — don't block login if the count query fails
	}
	if count >= s.maxSessionsPerUser {
		return ErrTooManySessions
	}
	return nil
}

// storeRefreshToken hashes and persists a refresh token in the database.
func (s *AuthService) storeRefreshToken(ctx context.Context, userID, clientID, deviceID, fp string, pair *TokenPair) error {
	tokenHash := vaultcrypto.SHA256Hex(pair.RefreshToken)
	rtID, err := vaultcrypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("generate refresh token ID: %w", err)
	}
	// The concurrent-session cap is enforced atomically here, not only by the
	// earlier checkSessionLimit pre-check: CreateWithinCap counts the user's
	// active families and inserts under one per-user lock, so simultaneous logins
	// cannot each pass the pre-check and overshoot the cap (ASVS V2.3.4). A cap of
	// zero disables the bound. ErrSessionLimitReached is the race-loser's outcome
	// and is the same rejection the pre-check returns.
	err = s.tokens.CreateWithinCap(ctx, &model.RefreshToken{
		ID: rtID, UserID: userID, ClientID: clientID,
		TokenHash: tokenHash, FamilyID: pair.FamilyID,
		DeviceID: deviceID, FingerprintHash: fp,
		ExpiresAt: pair.RefreshExpAt, CreatedAt: time.Now(),
	}, s.maxSessionsPerUser)
	if errors.Is(err, repository.ErrSessionLimitReached) {
		return ErrTooManySessions
	}
	return err
}
