// Package service implements the business logic layer for the Vault auth
// service, including user authentication, token issuance and rotation, MFA
// policy enforcement, and HIBP breach checking.
package service

import (
	"context"
	"encoding/binary"
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
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vaultemail "github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/httputil"
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
)

// Lockout defaults: 5 failures triggers a 15-minute lockout per user,
// 20 failures per IP triggers a 15-minute IP-wide lockout.
const (
	lockoutThreshold   = 5
	ipLockoutThreshold = 20
	lockoutDuration    = 15 * time.Minute
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
	honeypotAlert      *honeypot.Alerter
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

// SetStrictSessionLimit controls checkSessionLimit's behaviour on a count-query
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
	return &AuthService{
		users: users, tokens: tokens, devices: devices,
		pwHistory: pwHistory, tokenSvc: tokenSvc, mfaSvc: mfaSvc,
		auditLog: auditLog, hibp: hibp, cache: c, emailSender: emailSender,
		origin: origin, appName: appName, pepper: pepper,
		minPwLength: minPwLength, hibpEnabled: hibpEnabled,
		hmacSecret: hmacSecret,
	}
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

// SetRoleCatalog enables catalog-aware role validation. When set, JWT issuance
// keeps only roles present in the auth.app_roles catalog (in addition to the
// admin-reserved filter). Nil (the default) preserves the prior behaviour.
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

	// Send verification email (non-critical — log but don't fail registration)
	if s.cache != nil && s.emailSender != nil {
		go s.sendVerificationEmail(email, userID, sanitize.RedirectPath(input.RedirectTo)) // #nosec G118 -- intentionally uses Background ctx: email send outlives HTTP request
	}

	return &RegisterResult{UserID: userID, Email: email}, nil
}

// sendVerificationEmail generates a verification token, stores it, and sends the email.
func (s *AuthService) sendVerificationEmail(to, userID, redirectTo string) {
	ctx := context.Background()

	token, err := vaultcrypto.RandomHex(32)
	if err != nil {
		log.Printf("auth: failed to generate verification token: %v", err)
		return
	}

	tokenHash := vaultcrypto.SHA256Hex(token)
	if err := s.cache.Set(ctx, "verify:"+tokenHash, userID, 24*time.Hour); err != nil {
		log.Printf("auth: failed to store verification token: %v", err)
		return
	}

	verifyURL := s.origin + "/verify-email?token=" + token
	if redirectTo != "" {
		verifyURL += "&redirect=" + url.QueryEscape(redirectTo)
	}

	subject, html, text := vaultemail.RenderTemplate(vaultemail.TemplateVerification, vaultemail.TemplateData{
		AppName: s.appName,
		URL:     verifyURL,
	})
	if err := s.emailSender.Send(ctx, to, subject, html, text); err != nil {
		log.Printf("auth: failed to send verification email to %s: %v", to, err)
	}
}

// sendImportClaimLink mints a one-time reset token (compatible with the
// password reset-confirm flow) for an imported account and emails the magic
// link. Fire-and-forget; failures are logged, not surfaced (anti-enumeration).
func (s *AuthService) sendImportClaimLink(userID, emailAddr string) {
	if s.cache == nil || s.emailSender == nil {
		return
	}
	go func() { // #nosec G118 -- intentional: email send outlives the HTTP request
		ctx := context.Background()
		// Invalidate any prior outstanding claim link so only the latest is valid
		// (each login attempt issues a new one; don't leave stale tokens usable).
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
		if err := s.cache.Set(ctx, "reset:"+tokenHash, userID, time.Hour); err != nil {
			log.Printf("auth: import claim token store failed: %v", err)
			return
		}
		s.cache.Set(ctx, "pwreset_user:"+userID, tokenHash, time.Hour) // #nosec G104 -- reverse map for invalidation, best-effort

		claimURL := s.origin + "/reset-password?token=" + token + "&import=1"
		subject, html, text := vaultemail.RenderTemplate(vaultemail.TemplatePasswordReset, vaultemail.TemplateData{
			AppName: s.appName,
			URL:     claimURL,
		})
		if err := s.emailSender.Send(ctx, emailAddr, subject, html, text); err != nil {
			log.Printf("auth: failed to send import claim email to %s: %v", emailAddr, err)
		}
	}()
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
	// ImportClaimRequired is set for an imported account on its first login: no
	// password was verified; a magic reset link was emailed to claim the account.
	ImportClaimRequired bool `json:"import_claim_required,omitempty"`
}

// Login authenticates a user and issues tokens.
//
//nolint:gocognit,gocyclo // login owns user-lockout, ip-lockout, anti-enumeration burns, MFA challenge, family rotation, audit, metrics — all coupled to one state machine
func (s *AuthService) Login(ctx context.Context, input LoginInput, ip, ua string) (*LoginResult, error) {
	if s.metrics != nil {
		s.metrics.RecordLoginAttempt()
	}
	email := strings.ToLower(strings.TrimSpace(input.Email))

	// Honeypot: trap user check — return fake tokens to deceive attackers
	if s.honeypotAlert != nil && s.honeypotAlert.IsTrapUser(email) {
		// Run dummy Argon2id to maintain constant timing (identical to anti-enumeration path)
		if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return nil, err // 503 — consistent with real-user path under load
		}

		// Fire alert asynchronously (use Background — request ctx canceled after response)
		go s.honeypotAlert.Alert(context.Background(), honeypot.HoneypotEvent{ // #nosec G118 -- intentional: honeypot alert outlives HTTP request
			Timestamp: time.Now(),
			EventType: "trap_login",
			IP:        ip,
			UserAgent: ua,
			Email:     email,
			RiskScore: 100,
		})

		fakeJWT, err := honeypot.GenerateFakeJWT()
		if err != nil {
			return nil, fmt.Errorf("honeypot: fake JWT: %w", err)
		}
		fakeRefresh, err := honeypot.GenerateFakeRefresh()
		if err != nil {
			return nil, fmt.Errorf("honeypot: fake refresh: %w", err)
		}
		return &LoginResult{
			AccessToken:  fakeJWT,
			TokenType:    "Bearer",
			ExpiresIn:    int(s.tokenSvc.accessTokenTTL.Seconds()),
			RefreshToken: fakeRefresh,
			CookieMaxAge: int(s.tokenSvc.refreshTokenTTL.Seconds()),
		}, nil
	}

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

	// Check account lock (DB-level admin lockout OR cache-based auto-lockout)
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "account_locked", "source": "admin"}, 30)
		return nil, ErrAccountLocked
	}
	if s.isAccountLocked(ctx, user.ID) {
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "account_locked", "source": "auto"}, 30)
		return nil, ErrAccountLocked
	}

	// Account-state gate (BeOn3 parity, migration 004). Reject banned/disabled/
	// deleted accounts before password verification. A soft-deleted account is
	// treated as "no such user" (ErrInvalidCredentials) to avoid revealing it.
	if user.Deleted {
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "account_deleted"}, 20)
		return nil, ErrInvalidCredentials
	}
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

	// Imported account, first login: the password the user typed is meaningless
	// (we never imported their credentials). Don't verify it — run a dummy hash
	// for timing parity, email a magic reset link, and tell the client to claim
	// the account. The existing reset-confirm flow then sets the Argon2 password
	// and clears import_pending.
	if user.ImportPending {
		if _, err := vaultcrypto.VerifyPassword(input.Password, vaultcrypto.DummyHash, s.pepper); errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
			return nil, err
		}
		s.sendImportClaimLink(user.ID, user.Email)
		s.auditLog.Log(ctx, audit.LoginSuccess, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"import_claim": true}, 0)
		return &LoginResult{ImportClaimRequired: true}, nil
	}

	// Verify password
	valid, err := vaultcrypto.VerifyPassword(input.Password, user.PasswordHash, s.pepper)
	if errors.Is(err, vaultcrypto.ErrArgon2Overloaded) {
		return nil, err // 503 — propagate before recording failure (consistent with dummy hash path)
	}
	if err != nil || !valid {
		// Failed-login counter is best-effort; lockout is enforced by isAccountLocked.
		_ = s.users.IncrementFailedLogin(ctx, user.ID)
		s.recordFailedAttempt(ctx, user.ID)
		s.recordFailedIP(ctx, ip)
		if s.metrics != nil {
			s.metrics.RecordLoginFailed()
		}
		s.auditLog.Log(ctx, audit.LoginFailure, user.ID, "", ip, ua, "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
			map[string]interface{}{"reason": "wrong_password"}, 20)

		// Send lock notification email once per lockout window
		if s.isAccountLocked(ctx, user.ID) && s.cache != nil && s.emailSender != nil {
			lockNotifyKey := fmt.Sprintf("lock_notified:%s", user.ID)
			if sent, _ := s.cache.SetIfNotExists(ctx, lockNotifyKey, "1", lockoutDuration); sent {
				go func() { // #nosec G118 -- intentional: email send outlives HTTP request
					subject, html, text := vaultemail.RenderTemplate(vaultemail.TemplateAccountLocked, vaultemail.TemplateData{
						AppName: s.appName,
						IP:      ip,
					})
					// Email is best-effort.
					_ = s.emailSender.Send(context.Background(), user.Email, subject, html, text)
				}()
			}
		}

		return nil, ErrInvalidCredentials
	}

	// Check email verified — return ErrInvalidCredentials (not ErrEmailNotVerified)
	// to prevent user enumeration: an attacker cannot distinguish "unverified" from
	// "wrong password" or "no such user".
	if !user.EmailVerified {
		return nil, ErrInvalidCredentials
	}

	// Reset failed login count (both DB and cache)
	if err := s.users.ResetFailedLogin(ctx, user.ID); err != nil {
		log.Printf("auth: failed to reset login count for %s: %v", user.ID, err)
	}
	s.clearLockout(ctx, user.ID)

	// Compute fingerprint
	input.Fingerprint.IP = ip
	input.Fingerprint.UserAgent = ua
	fp := vaultcrypto.ComputeFingerprint(input.Fingerprint)

	// Check if user has MFA enabled
	if s.mfaSvc != nil {
		status, err := s.mfaSvc.GetStatus(ctx, user.ID)
		if err != nil {
			log.Printf("auth: MFA status check failed for %s: %v", user.ID, err)
		}
		hasMethods := status != nil && len(status.Methods) > 0
		if hasMethods {
			// Issue a short-lived challenge token instead of real tokens
			challengePair, err := s.tokenSvc.IssueChallengeToken(user.ID, fp)
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
			go s.sendEmailOTP(user.ID, user.Email) // #nosec G118 -- intentional: email OTP send outlives HTTP request
			challengePair, err := s.tokenSvc.IssueChallengeToken(user.ID, fp)
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

	// Enforce session count limit (new family only)
	if err := s.checkSessionLimit(ctx, user.ID); err != nil {
		return nil, err
	}

	// Find or create device (non-critical — log but don't fail)
	deviceID := s.findOrCreateDevice(ctx, user.ID, fp, ip, ua)

	// Issue tokens — use the user's persisted Roles, admin-filtered and
	// catalog-validated, falling back to the historical default ["user"].
	jwtRoles := s.effectiveRoles(ctx, user.Roles)
	pair, err := s.tokenSvc.IssueTokenPair(
		user.ID, jwtRoles, []string{"read", "write"},
		input.ClientID, fp, "", input.RememberMe,
	)
	if err != nil {
		return nil, err
	}

	if err := s.storeRefreshToken(ctx, user.ID, input.ClientID, deviceID, fp, pair); err != nil {
		return nil, err
	}

	// Stamp last successful login (BeOn3 parity); best-effort.
	if err := s.users.SetLastLogin(ctx, user.ID); err != nil {
		log.Printf("auth: failed to set last_login for %s: %v", user.ID, err)
	}

	if s.metrics != nil {
		s.metrics.RecordLoginSuccess()
		s.metrics.RecordTokenIssued()
	}
	s.auditLog.Log(ctx, audit.LoginSuccess, user.ID, input.ClientID, ip, ua, fp, deviceID, nil, 0) // #nosec G104 -- audit is best-effort, never blocks auth flow

	return &LoginResult{
		AccessToken:  pair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.tokenSvc.accessTokenTTL.Seconds()),
		RefreshToken: pair.RefreshToken,
		CookieMaxAge: int(time.Until(pair.RefreshExpAt).Seconds()),
	}, nil
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
	if refreshUser == nil || refreshUser.Deleted || refreshUser.Banned || refreshUser.Disabled {
		s.tokens.RevokeFamily(ctx, stored.FamilyID) // #nosec G104 -- best-effort; reject regardless
		switch {
		case refreshUser != nil && refreshUser.Banned:
			return nil, ErrAccountBanned
		case refreshUser != nil && refreshUser.Disabled:
			return nil, ErrAccountDisabled
		default:
			return nil, ErrTokenInvalid
		}
	}
	refreshRoles := s.effectiveRoles(ctx, refreshUser.Roles)
	pair, err := s.tokenSvc.IssueTokenPair(
		stored.UserID, refreshRoles, []string{"read", "write"},
		stored.ClientID, fp, stored.FamilyID, false,
	)
	if err != nil {
		return nil, err
	}

	// Store new refresh token
	newHash := vaultcrypto.SHA256Hex(pair.RefreshToken)
	newID, err := vaultcrypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token ID: %w", err)
	}
	if err := s.tokens.Create(ctx, &model.RefreshToken{
		ID: newID, UserID: stored.UserID, ClientID: stored.ClientID,
		TokenHash: newHash, FamilyID: stored.FamilyID,
		DeviceID: stored.DeviceID, FingerprintHash: fp,
		ExpiresAt: pair.RefreshExpAt, CreatedAt: time.Now(),
	}); err != nil {
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

// CompleteMFALogin issues tokens after successful MFA verification.
// Called by TOTP verify and WebAuthn verify handlers when a 2fa_challenge token is presented.
// The jti parameter enforces single-use: once consumed, the same challenge token is rejected.
func (s *AuthService) CompleteMFALogin(ctx context.Context, userID, fingerprint, ip, ua, jti string) (*LoginResult, error) {
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
	// Successful second factor clears the per-account failure counter (audit H2).
	s.clearLockout(ctx, userID)
	// Enforce session count limit (new family only)
	if err := s.checkSessionLimit(ctx, userID); err != nil {
		return nil, err
	}

	// Find or create device (non-critical — log but don't fail)
	deviceID := s.findOrCreateDevice(ctx, userID, fingerprint, ip, ua)

	// Issue tokens — same per-user roles flow as the password login
	// path; 2FA verify shares the post-auth shape.
	mfaUser, _ := s.users.GetByID(ctx, userID)
	var mfaRoles []string
	if mfaUser != nil {
		mfaRoles = s.effectiveRoles(ctx, mfaUser.Roles)
	} else {
		mfaRoles = []string{"user"}
	}
	pair, err := s.tokenSvc.IssueTokenPair(
		userID, mfaRoles, []string{"read", "write"},
		"", fingerprint, "", false,
	)
	if err != nil {
		return nil, err
	}

	if err := s.storeRefreshToken(ctx, userID, "", deviceID, fingerprint, pair); err != nil {
		return nil, err
	}

	// Stamp last successful login (BeOn3 parity); best-effort.
	if err := s.users.SetLastLogin(ctx, userID); err != nil {
		log.Printf("auth: failed to set last_login for %s: %v", userID, err)
	}

	if s.metrics != nil {
		s.metrics.RecordLoginSuccess()
		s.metrics.RecordTokenIssued()
	}
	s.auditLog.Log(ctx, audit.LoginSuccess, userID, "", ip, ua, fingerprint, deviceID, // #nosec G104 -- audit is best-effort, never blocks auth flow
		map[string]interface{}{"mfa_completed": true}, 0)

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
	return s.doSendEmailOTP(ctx, userID, emailAddr)
}

// sendEmailOTP is the fire-and-forget version called from the login flow goroutine.
func (s *AuthService) sendEmailOTP(userID, emailAddr string) {
	ctx := context.Background()
	if err := s.doSendEmailOTP(ctx, userID, emailAddr); err != nil {
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

func (s *AuthService) doSendEmailOTP(ctx context.Context, userID, emailAddr string) error {
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
	code := fmt.Sprintf("%06d", binary.BigEndian.Uint32(b)%1000000)

	sig := vaultcrypto.HMACSign([]byte(code), s.hmacSecret)
	cacheKey := "email_otp:" + userID
	if err := s.cache.Set(ctx, cacheKey, sig, 5*time.Minute); err != nil {
		return fmt.Errorf("cache OTP: %w", err)
	}

	subject, html, text := vaultemail.RenderTemplate(vaultemail.TemplateEmailOTP, vaultemail.TemplateData{
		AppName: s.appName,
		Code:    code,
	})
	if err := s.emailSender.Send(ctx, emailAddr, subject, html, text); err != nil {
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

// isAccountLocked checks the cache-based lockout counter.
// When cache is unavailable, falls back to the DB failed_login_count field.
func (s *AuthService) isAccountLocked(ctx context.Context, userID string) bool {
	if s.cache == nil {
		// Fallback: check DB-level failed login counter when cache is unavailable.
		// This is coarser (never auto-resets by TTL) but prevents unlimited brute force.
		user, err := s.users.GetByID(ctx, userID)
		if err != nil || user == nil {
			return false
		}
		if user.FailedLoginCount >= lockoutThreshold {
			log.Printf("auth: lockout enforced via DB fallback for user %s (cache unavailable)", userID)
			return true
		}
		return false
	}
	key := fmt.Sprintf("lockout:%s", userID)
	val, err := s.cache.Get(ctx, key)
	if err != nil || val == "" {
		return false
	}
	var n int
	fmt.Sscanf(val, "%d", &n) // #nosec G104 -- parse failure returns 0, which means not locked
	return n >= lockoutThreshold
}

// recordFailedAttempt increments the lockout counter for the user.
func (s *AuthService) recordFailedAttempt(ctx context.Context, userID string) {
	if s.cache == nil {
		return
	}
	key := fmt.Sprintf("lockout:%s", userID)
	s.cache.Increment(ctx, key, lockoutDuration) // #nosec G104 -- best-effort lockout counter
}

// clearLockout resets the lockout counter on successful login.
func (s *AuthService) clearLockout(ctx context.Context, userID string) {
	if s.cache == nil {
		return
	}
	key := fmt.Sprintf("lockout:%s", userID)
	s.cache.Delete(ctx, key) // #nosec G104 -- best-effort counter reset
}

// MFAVerifyLocked reports whether the account is locked out from further auth
// attempts. MFA verify endpoints MUST call this before checking a second factor:
// the per-IP rate limit alone is defeated by IP rotation, so without a per-account
// gate the second factor is brute-forceable within the challenge window (audit H2).
func (s *AuthService) MFAVerifyLocked(ctx context.Context, userID string) bool {
	return s.isAccountLocked(ctx, userID)
}

// RecordMFAFailure counts a failed second-factor attempt toward the per-account
// lockout (shared counter with the password path, so combined failures trip the
// same lockoutThreshold/lockoutDuration) and audits it. Reset on success via
// clearLockout in CompleteMFALogin (audit H2).
func (s *AuthService) RecordMFAFailure(ctx context.Context, userID, ip, ua string) {
	s.recordFailedAttempt(ctx, userID)
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

// storeRefreshToken hashes and persists a refresh token in the database.
// checkSessionLimit verifies that the user has not exceeded the maximum number of
// concurrent refresh token families. Returns ErrTooManySessions if the limit is reached.
// A maxSessionsPerUser of 0 disables the check.
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

func (s *AuthService) storeRefreshToken(ctx context.Context, userID, clientID, deviceID, fp string, pair *TokenPair) error {
	tokenHash := vaultcrypto.SHA256Hex(pair.RefreshToken)
	rtID, err := vaultcrypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("generate refresh token ID: %w", err)
	}
	return s.tokens.Create(ctx, &model.RefreshToken{
		ID: rtID, UserID: userID, ClientID: clientID,
		TokenHash: tokenHash, FamilyID: pair.FamilyID,
		DeviceID: deviceID, FingerprintHash: fp,
		ExpiresAt: pair.RefreshExpAt, CreatedAt: time.Now(),
	})
}
