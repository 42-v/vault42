// Package main is the entry point for the Vault JWT authentication and
// authorization server.
package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/cli"
	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/deferwork"
	"github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/ipintel"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/kms"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/migrate"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/seed"
	"github.com/42-v/vault42/internal/server"
	"github.com/42-v/vault42/internal/service"
)

// Set at build time via -ldflags.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// sanitizeDBError strips connection-URL credentials from an error before it
// reaches a log.
//
// It delegates to httputil.RedactDSN rather than carrying a pattern of its own.
// This file used to hold a private copy of that regex, as did cmd/admin-gateway, which
// is exactly the drift RedactDSN's doc comment says the helper exists to
// prevent: an improvement to the shared pattern reached cmd/recover and left
// both copies behind, silently, with the whole suite green. The name stays
// because it is what this binary's call sites and tests use; the behavior now
// has one definition. tests/spec/dsn_redaction_drift_test.go fails the build if
// a private copy reappears.
func sanitizeDBError(err error) error {
	return httputil.RedactDSN(err)
}

//nolint:gocognit,gocyclo // entry-point wires every subsystem; refactor would scatter fail-fast init across helpers
func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("vault %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		return
	}

	// `vault kms wrap` produces the wrapped-root artifact /kms/unwrap consumes.
	// Handled here — before DB/server wiring — because it only needs the KMS
	// root keyfile, no running vault.
	if len(os.Args) > 1 && os.Args[1] == "kms" {
		if err := runKMS(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "vault kms: %v\n", err)
			os.Exit(1)
		}
		return
	}

	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	log.Printf("Configuration loaded:\n%s", cfg)

	// Run migrations (using vault_mig role)
	if cfg.AutoMigrate {
		migConn, err := pgx.Connect(ctx, cfg.DatabaseURL("migration"))
		if err != nil {
			log.Fatalf("Failed to connect for migrations: %v", sanitizeDBError(err))
		}
		if err := migrate.Run(ctx, migConn, "migrations"); err != nil {
			log.Fatalf("Migration failed: %v", err)
		}
		// Closing migration connection; error is irrelevant post-migration.
		_ = migConn.Close(ctx)
		log.Println("Migrations complete")
	}

	// Working copies of the key material, taken BEFORE anything consumes it.
	//
	// Every service that is handed a key retains the slice it is given (the
	// keystore, the auth service, the identity/blob/erasure services all just
	// store the header). config.ZeroBytes below wipes the config's backing array
	// in place, so a service handed cfg.MasterKey directly would end up holding 32
	// zero bytes — still a valid AES-256 key length, so it would encrypt and
	// decrypt happily against itself while the at-rest protection was gone. Pass
	// these copies to every consumer; never cfg.MasterKey / cfg.HMACSecret.
	masterKey := append([]byte(nil), cfg.MasterKey...)
	hmacSecret := append([]byte(nil), cfg.HMACSecret...)

	// Connect to PostgreSQL (vault_app role)
	db, err := postgres.NewWithOptions(ctx, cfg.DatabaseURL("app"), postgres.Options{
		MaxConns:         cfg.DBMaxConns,
		StatementTimeout: cfg.DBStatementTimeout,
		LockTimeout:      cfg.DBLockTimeout,
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", sanitizeDBError(err))
	}
	defer db.Close()

	// Initialize cache.
	//
	// cacheDegraded is remembered rather than only logged, because the fallback
	// changes what this process can enforce. The shared cache holds the login
	// and password-reset limiters, the KMS unwrap budget, the OAuth state
	// written on /authorize and read back on the callback, the email OTP codes,
	// and the TOTP replay guard. On the memory fallback all of them become
	// per-pod: with four replicas the login limiter admits four times its
	// configured attempts and an OAuth callback routed to another pod cannot
	// find its own state. /readyz reports this, so the condition is visible for
	// as long as it lasts rather than in one line at startup that has scrolled
	// away by the time anyone looks.
	cacheDegraded := false
	appCache, err := cache.NewCache(cfg.CacheBackend, cfg.RedisAddr, cfg.RedisPass, db.Pool)
	if err != nil {
		log.Printf("WARNING: cache init failed, falling back to per-process memory: %v. "+
			"Cross-replica rate limiting, OAuth state and TOTP replay protection are degraded "+
			"until the cache returns; /readyz reports cache=degraded.", err)
		appCache = cache.NewMemoryCache()
		cacheDegraded = true
	}
	defer func() { _ = appCache.Close() }()

	// Initialize repositories
	userRepo := postgres.NewUserRepo(db)
	refreshTokenRepo := postgres.NewRefreshTokenRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	clientRepo := postgres.NewClientRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	adminConfigRepo := postgres.NewAdminConfigRepo(db)
	totpRepo := postgres.NewTOTPRepo(db)
	webauthnRepo := postgres.NewWebAuthnRepo(db)
	backupCodeRepo := postgres.NewBackupCodeRepo(db)
	pwHistoryRepo := postgres.NewPasswordHistoryRepo(db)
	socialAccountRepo := postgres.NewSocialAccountRepo(db)
	identityRepo := postgres.NewIdentityRepo(db)
	blobRepo := postgres.NewBlobRepo(db)
	serviceDocRepo := postgres.NewServiceDocumentRepo(db)
	recoveryRepo := postgres.NewAccountRecoveryRepo(db)
	rateLimitRepo := postgres.NewRateLimitRepo(db)
	loginCountryRepo := postgres.NewLoginCountryRepo(db)

	// Initialize audit logger
	auditLogger := audit.NewLoggerWithBufferSize(auditRepo, cfg.AuditFlushInterval, cfg.AuditBufferSize)
	defer auditLogger.Close(ctx)
	// Registered LAST of the four shutdown defers, so LIFO drains the pool FIRST.
	// A job still running needs the audit logger (notifyNewCountry writes a row),
	// the cache (a deferred send writes its token, then mails the link) and the pool
	// behind both. deferwork.Close stated that rule for the cache and the pool and
	// left the logger out, so the logger closed first and a job's row went into a
	// buffer nothing would flush. TestShutdownDefersRunInDependencyOrder gates it.
	defer func() {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer drainCancel()
		if err := deferwork.Close(drainCtx); err != nil {
			log.Printf("WARNING: deferred email drain incomplete: %v", err)
		}
	}()

	// CLI commands (check before starting server)
	cliHandler := cli.New(clientRepo, userRepo, refreshTokenRepo, adminConfigRepo, auditRepo, cfg.Pepper).
		WithRecoveryPruner(recoveryRepo)

	// Initialize admin token on first boot
	if err := cliHandler.InitAdminToken(ctx); err != nil {
		log.Printf("Admin token init error: %v", err)
	}

	// Check if this is a CLI invocation
	if cliHandler.Run(ctx, os.Args) {
		return
	}

	// Cross-plane agreement on HMAC_SECRET, before this process serves anything.
	//
	// The admin gateway derives the same subject pseudonyms from the same secret
	// and erases by them. Two planes holding different secrets produce different
	// pseudonyms, so an admin erasure clears zero rows from identity.profiles,
	// objects.blobs and objects.service_documents and reports success anyway.
	// Nothing downstream can notice: clearing no rows is also what erasing an
	// account that held no profile looks like.
	//
	// Placed after the CLI branch so a subcommand an operator runs to diagnose
	// the disagreement still works, and fatal rather than degraded because every
	// pseudonym this server writes from here on would be unreachable by the other
	// plane. A store that cannot answer is a different matter: this process is
	// about to depend on that same pool for everything and its own errors will
	// say so, so an unanswered check is reported rather than made fatal.
	if err := config.VerifyHMACPlaneAgreement(ctx, adminConfigRepo, hmacSecret); err != nil {
		if errors.Is(err, config.ErrHMACPlaneMismatch) {
			_ = auditLogger.Close(ctx)
			log.Fatalf("%v", err) //nolint:gocritic // exitAfterDefer is intentional; we drained on the line above
		}
		log.Printf("WARNING: %v; erasure agreement with the admin gateway is unverified", err)
	}

	// Declarative seeding from VAULT_SEED_FILE (idempotent).
	//
	// Applied only once we know this is the server and not a CLI invocation:
	// running it above the CLI check made every `vault list-clients` create
	// the declared clients and users as a side effect, and a broken seed file
	// killed an unrelated admin subcommand with log.Fatalf. The retention
	// sweepers sit below for the same reason.
	if cfg.File != "" {
		sf, err := seed.Load(cfg.File)
		if err != nil {
			_ = auditLogger.Close(ctx)
			log.Fatalf("Failed to load seed file: %v", err) //nolint:gocritic // exitAfterDefer is intentional; we drained on the line above
		}
		if err := seed.Run(ctx, sf, seed.Deps{Users: userRepo, Clients: clientRepo}, cfg.Pepper); err != nil {
			log.Fatalf("Seeding failed: %v", err)
		}
	}

	// Audit retention sweeper (Art. 5(1)(e)). No-op unless
	// VAULT_AUDIT_RETENTION_DAYS is set.
	//
	// Started only once we know this is the server and not a CLI invocation:
	// the sweep runs immediately on start, so starting it above would make every
	// `vault add-client`, `vault rotate-jwks`, … silently purge the audit log as a
	// side effect of running an unrelated subcommand.
	auditRetention := audit.NewRetention(auditRepo, cfg.AuditRetentionPeriod)
	if auditRetention.Enabled() {
		auditRetention.Start(ctx)
		defer auditRetention.Stop()
		log.Printf("audit retention: purging entries older than %s", cfg.AuditRetentionPeriod)
	}

	// Refresh-token reaping. Nothing on the server path ran it before: the only
	// caller of DeleteExpired was the CLI, so the table grew until an operator
	// remembered a subcommand.
	refreshRetention := service.NewRefreshTokenRetention(refreshTokenRepo)
	refreshRetention.Start(ctx)
	defer refreshRetention.Stop()

	// Account-recovery escrow retention (Art. 5(1)(e)). No-op unless
	// VAULT_RECOVERY_RETENTION_DAYS is set. Started here for the same reason as
	// the audit sweeper: it sweeps immediately, so starting it before the CLI
	// check would make every unrelated subcommand purge escrow records.
	recoveryRetention := service.NewRecoveryRetention(recoveryRepo, cfg.RecoveryRetentionPeriod)
	if recoveryRetention.Enabled() {
		recoveryRetention.Start(ctx)
		defer recoveryRetention.Stop()
		log.Printf("recovery retention: purging escrow records older than %s", cfg.RecoveryRetentionPeriod)
	}

	// Signing key initialization — two modes:
	// 1. DB-backed keystore (VAULT_KEY_ROTATION_DB=true): keys encrypted in PostgreSQL,
	//    auto-refreshed across pods, admin-rotatable at runtime.
	// 2. File-based (default): SIGNING_KEY_FILE or ephemeral in-memory key.
	var signingKey *rsa.PrivateKey
	var kid string
	var keys map[string]*rsa.PublicKey
	var ks *keystore.KeyStore

	if cfg.KeyRotationDB {
		if len(masterKey) != 32 {
			log.Fatal("VAULT_KEY_ROTATION_DB=true requires MASTER_KEY_FILE (32 bytes)")
		}
		// masterKey, not cfg.MasterKey: the keystore retains the slice and the
		// config array is zeroed below. It encrypts the JWT signing keys at rest,
		// so an all-zero key here would nullify that protection silently.
		ks, err = keystore.New(db.Pool, masterKey, cfg.KeyRetentionPeriod)
		if err != nil {
			log.Fatalf("Failed to create keystore: %v", err)
		}

		// Import file-based key if present, otherwise let keystore generate one
		var importKey *rsa.PrivateKey
		if skPEM, skErr := config.LoadSecret("SIGNING_KEY"); skErr == nil {
			importKey, _, err = vaultcrypto.LoadSigningKeyPEM([]byte(skPEM))
			if err != nil {
				log.Fatalf("Failed to load signing key for import: %v", err)
			}
		}

		if err := ks.EnsureKey(ctx, importKey); err != nil {
			log.Fatalf("Failed to initialize keystore: %v", err)
		}

		signingKey, kid = ks.ActiveKey()
		keys = ks.AllPublicKeys()
		log.Printf("DB-backed keystore active (kid=%s, %d keys in JWKS)", kid, len(keys))
	} else {
		// File-based signing key (original behavior)
		if skPEM, skErr := config.LoadSecret("SIGNING_KEY"); skErr == nil {
			signingKey, kid, err = vaultcrypto.LoadSigningKeyPEM([]byte(skPEM))
			if err != nil {
				log.Fatalf("Failed to load signing key: %v", err)
			}
			log.Printf("Signing key loaded from file (kid=%s)", kid)
		} else {
			signingKey, err = vaultcrypto.GenerateRSAKeyPair()
			if err != nil {
				log.Fatalf("Failed to generate signing key: %v", err)
			}
			kid, err = vaultcrypto.RandomUUID()
			if err != nil {
				log.Fatalf("Failed to generate key ID: %v", err)
			}
			log.Printf("WARNING: No SIGNING_KEY_FILE — signing key is ephemeral, multi-pod will fail (kid=%s)", kid)
		}
		keys = map[string]*rsa.PublicKey{kid: &signingKey.PublicKey}
	}

	// Initialize services
	tokenSvc := service.NewTokenService(
		signingKey, kid, cfg.Origin, cfg.Origin,
		cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.RememberMeTTL,
	)

	hibpClient := service.NewHIBPClient()
	mfaSvc := service.NewMFAService(totpRepo, webauthnRepo, backupCodeRepo, cfg.MFARequired)
	// Initialize email template renderer with optional overrides
	tmplRenderer, err := email.NewTemplateRenderer(cfg.EmailTemplatesDir)
	if err != nil {
		log.Fatalf("Failed to initialize email templates: %v", err)
	}
	tmplRenderer.SetDefaults(email.TemplateData{
		LogoURL:      cfg.LogoURL,
		PrimaryColor: cfg.PrimaryColor,
	})
	email.SetRenderer(tmplRenderer)

	// Initialize email sender
	var emailSender email.Sender
	switch {
	case cfg.EmailProvider == "sendgrid" && cfg.SendGridAPIKey != "":
		emailSender = email.NewSendGridSender(cfg.SendGridAPIKey, cfg.EmailFrom)
		log.Println("Email: SendGrid provider configured")
	case cfg.SMTPHost != "":
		emailSender = email.NewSMTPSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.EmailFrom,
			email.AllowPlaintext(cfg.SMTPAllowPlaintext))
		log.Println("Email: SMTP provider configured")
	case cfg.SendGridAPIKey != "":
		// Fallback: SMTP not configured but SendGrid API key is available
		emailSender = email.NewSendGridSender(cfg.SendGridAPIKey, cfg.EmailFrom)
		log.Println("Email: SendGrid provider configured (fallback, SMTP_HOST empty)")
	}

	authSvc := service.NewAuthService(
		userRepo, refreshTokenRepo, deviceRepo, pwHistoryRepo,
		tokenSvc, mfaSvc, auditLogger, hibpClient,
		appCache, emailSender, cfg.Origin, cfg.AppName, cfg.Pepper,
		cfg.PasswordMinLength, cfg.HIBPCheck, hmacSecret,
	)

	// White-label email: resolve per-app branding + template overrides on the
	// send path. The app pool holds SELECT on the email tables (writes go through
	// the admin gateway). One mailer is shared by the auth service and the
	// password handler.
	emailBrandingRepo := postgres.NewEmailBrandingRepo(db)
	emailTemplateRepo := postgres.NewEmailTemplateRepo(db)
	mailer := email.NewMailer(tmplRenderer, emailSender,
		service.NewEmailOverrideStore(emailBrandingRepo, emailTemplateRepo),
		email.Branding{
			AppName:      cfg.AppName,
			LogoURL:      cfg.LogoURL,
			PrimaryColor: cfg.PrimaryColor,
			FromName:     cfg.EmailFromName,
		},
		cfg.EmailFromAllowedDomains,
	)
	authSvc.SetMailer(mailer)

	authSvc.SetRateLimitRepo(rateLimitRepo)
	authSvc.SetMaxSessionsPerUser(cfg.MaxSessionsPerUser)
	authSvc.SetStrictSessionLimit(cfg.StrictSessionLimit)
	tokenSvc.SetMaxSessionLifetime(cfg.MaxSessionLifetime)

	// IP-intelligence: prefers VAULT_IPINTEL_DATA, else the embedded blob. Load
	// is fail-open — a corrupt embedded blob (a build-time defect) must not stop
	// the service, so degrade to an empty table and continue. The empty table
	// makes both dependent features (the new-location notice and VPN rate-limit
	// scrutiny) inert rather than erroring. Wired into the auth service for the
	// new-location notice and into the server (deps below) for rate-limit weight.
	ipIntelDB, err := ipintel.Default()
	if err != nil {
		log.Printf("WARNING: ipintel load failed (%v); continuing with an empty table (new-location notice and VPN scrutiny inert)", err)
		ipIntelDB = ipintel.NewEmpty()
	}
	authSvc.SetIPIntel(ipIntelDB)
	authSvc.SetLoginCountryRepo(loginCountryRepo)
	// Catalog-aware role validation: JWT issuance keeps only roles defined in
	// auth.app_roles (in addition to the admin-reserved filter).
	authSvc.SetRoleCatalog(service.NewRoleCatalog(postgres.NewAppRoleRepo(db), 60*time.Second))

	// Parse the optional recovery public key used to escrow account-erasure
	// records. Absent → recovery logging disabled (deletion still works).
	var recoveryPub *rsa.PublicKey
	if len(cfg.RecoveryPublicKeyPEM) > 0 {
		recoveryPub, err = vaultcrypto.LoadRSAPublicKeyPEM(cfg.RecoveryPublicKeyPEM)
		if err != nil {
			log.Fatalf("Failed to load recovery public key: %v", err)
		}
		log.Println("Account-recovery escrow enabled (records encrypted to the offline recovery key)")
	}

	// Zero the config-held originals. Every consumer above was handed masterKey /
	// hmacSecret (the copies made at the top of main), never cfg.*, so this cannot
	// blank a key that something is still holding.
	//
	// Note: string secrets (Pepper, DB passwords) can't be zeroed in Go — accepted limitation.
	config.ZeroBytes(cfg.MasterKey)
	config.ZeroBytes(cfg.HMACSecret)

	// KMS envelope-unwrap oracle (POST /kms/unwrap): only built when a KMS root
	// key is provisioned. The service holds its own copy of the root; zero the
	// config-held original once it is constructed.
	var kmsSvc *kms.Service
	if len(cfg.KMSRootKey) > 0 {
		kmsSvc, err = kms.New(cfg.KMSRootKey)
		if err != nil {
			log.Fatalf("KMS_ROOT_KEY invalid: %v", err)
		}
		defer kmsSvc.Close()
		log.Println("KMS unwrap oracle enabled at POST /kms/unwrap (scope kms:unwrap required)")
	}
	config.ZeroBytes(cfg.KMSRootKey)

	// Initialize honeypot alerter (only for honeypot profile)
	var honeypotAlerter *honeypot.Alerter
	if cfg.Profile == config.ProfileHoneypot {
		honeypotAlerter = honeypot.NewAlerter(cfg.HoneypotWebhookURL, cfg.HoneypotTrapUsers, auditLogger)
		authSvc.SetHoneypotAlerter(honeypotAlerter)
		// iss, aud and the access-token lifetime all come from this deployment's
		// own configuration. The lifetime is here because the login body quotes
		// it as expires_in while the token carries its own exp: a trap minting
		// against a hardcoded default disagreed with its own response on every
		// deployment that had set VAULT_ACCESS_TOKEN_TTL.
		honeypot.ConfigureFakeJWT(cfg.Origin, cfg.Origin, cfg.AccessTokenTTL)

		// Publish the trap's signing key in the JWKS this instance serves.
		//
		// The trap token has to verify against the document its own issuer
		// publishes, or the first relying party the attacker feeds it to reports
		// the forgery for them. The key is generated in this process, is never
		// persisted, and is not the deployment's signing key: signing trap tokens
		// with the real key would make them valid on any instance sharing it,
		// which under the bridge topology is the production vault.
		//
		// Generating it here rather than on the first trap login also keeps that
		// login from being several hundred milliseconds slower than every one
		// after it.
		trapKID, trapPub, err := honeypot.TrapSigningKey()
		if err != nil {
			log.Fatalf("Failed to generate the honeypot signing key: %v", err)
		}
		keys[trapKID] = trapPub
		if ks != nil {
			// The keystore serves JWKS from its own table, so the map above is
			// not what this instance publishes and the trap key would be absent
			// from the document. Honeypot deployments run with
			// VAULT_KEY_ROTATION_DB unset, which is why this is a warning rather
			// than a fatal.
			log.Printf("WARNING: honeypot profile with VAULT_KEY_ROTATION_DB=true: the trap signing key (kid=%s) "+
				"is not published in the keystore-backed JWKS, so trap tokens will not verify against it", trapKID)
		}
		log.Printf("Honeypot mode active: %d trap users configured (trap kid=%s)", len(cfg.HoneypotTrapUsers), trapKID)
	}

	// Initialize metrics collector (if enabled)
	var metricsCollector *metrics.Collector
	if cfg.MetricsEnabled {
		metricsCollector = metrics.NewCollector(
			vaultcrypto.Argon2ActiveCount,
			vaultcrypto.Argon2RejectedCount,
			vaultcrypto.Argon2MaxConcurrent,
		)
		metricsCollector.SetArgon2Queue(
			vaultcrypto.Argon2WaitingCount,
			vaultcrypto.Argon2WaitNanos,
		)
		authSvc.SetMetrics(metricsCollector)
		// The address is announced by the server when the listener binds. Saying
		// "at GET /metrics" alone would now be misleading: the collector is not
		// on the public listener, and an operator reading this line needs to
		// know it is looking for a different port.
		log.Println("Prometheus metrics enabled on the dedicated metrics listener (VAULT_METRICS_ADDR)")
	}

	// Mint is built here rather than in setupRoutes because an unsafe mint policy
	// must abort startup and setupRoutes cannot return an error. When minting is
	// off this stays nil and the route is never registered.
	var mintSvc *service.MintService
	if cfg.MintEnabled {
		signer := func() (*rsa.PrivateKey, string) { return signingKey, kid }
		if ks != nil {
			signer = ks.ActiveKey
		}
		// A nil *metrics.Collector must be passed as a nil interface, not as a
		// typed nil: the latter is non-nil at the interface and panics on first
		// use, so a deployment with metrics off would crash on its first mint.
		var mintMetrics service.MintMetrics
		if metricsCollector != nil {
			mintMetrics = metricsCollector
		}
		mintSvc, err = service.NewMintService(signer, service.MintConfig{
			Issuer:        cfg.Origin,
			Audience:      cfg.MintAudience,
			DefaultTTL:    cfg.MintTokenTTL,
			MaxTTL:        cfg.MintMaxTTL,
			AllowedRoles:  cfg.MintAllowedRoles,
			AllowedScopes: cfg.MintAllowedScopes,
		}, mintMetrics)
		if err != nil {
			log.Fatalf("Failed to initialize mint service: %v", err)
		}
		log.Printf("Mint enabled: signing for audience %q", cfg.MintAudience)
	}

	// Initialize OAuth2 providers
	oauthProviders := make(map[string]oauth2.Provider)
	if cfg.OAuthGoogleClientID != "" && cfg.OAuthGoogleClientSecret != "" {
		oauthProviders["google"] = oauth2.NewGoogleProvider(
			cfg.OAuthGoogleClientID, cfg.OAuthGoogleClientSecret,
			cfg.Origin+"/auth/oauth2/callback/google",
		)
	}
	if cfg.OAuthGitHubClientID != "" && cfg.OAuthGitHubClientSecret != "" {
		oauthProviders["github"] = oauth2.NewGitHubProvider(
			cfg.OAuthGitHubClientID, cfg.OAuthGitHubClientSecret,
			cfg.Origin+"/auth/oauth2/callback/github",
		)
	}
	if cfg.OAuthFacebookClientID != "" && cfg.OAuthFacebookClientSecret != "" {
		oauthProviders["facebook"] = oauth2.NewFacebookProvider(
			cfg.OAuthFacebookClientID, cfg.OAuthFacebookClientSecret,
			cfg.Origin+"/auth/oauth2/callback/facebook",
		)
	}
	// Generic OpenID Connect providers (Okta, Auth0, Keycloak, Entra, …).
	for _, op := range cfg.OIDCProviders {
		oauthProviders[op.Name] = oauth2.NewOIDCProvider(
			op.Name, op.Issuer, op.ClientID, op.ClientSecret,
			cfg.Origin+"/auth/oauth2/callback/"+op.Name, op.Scopes,
		)
		log.Printf("oauth: registered OIDC provider %q (issuer=%s)", op.Name, op.Issuer)
	}

	// Set up keystore callbacks and refresh loop
	if ks != nil {
		// OnKeyChange: update TokenService signing key and public key set
		// (WellKnownHandler is updated in server.setupRoutes via the keystore's KeyProvider)
		ks.SetOnKeyChange(func(activeKey *rsa.PrivateKey, newKID string, allPublicKeys map[string]*rsa.PublicKey) {
			tokenSvc.UpdateSigningKey(activeKey, newKID)
			log.Printf("keystore: active key rotated to kid=%s (%d keys in JWKS)", newKID, len(allPublicKeys))
		})
		ks.StartRefreshLoop(ctx, cfg.KeyRefreshInterval)
		defer ks.Stop()

		// Expired-key sweeper. Retired keys leave the verification set at their
		// expiry and stayed in the table forever afterwards, each one holding the
		// encrypted private half of a key that no longer verifies anything.
		//
		// Below the CLI check for the same reason as the audit and recovery
		// sweepers: the sweep runs immediately on start, so above it every
		// `vault list-clients` would reap signing key rows as a side effect of
		// listing clients.
		keyRetention := keystore.NewRetention(ks)
		keyRetention.Start(ctx)
		defer keyRetention.Stop()

		// Scheduled rotation. Nothing rotated the signing key before this: the
		// draft spec called for every 30 days, the shipped spec redefined rotation
		// as an admin endpoint plus a CLI command, and a default install therefore
		// signed every token it ever issued under one key. Below the CLI check for
		// the same reason as the three sweepers above it — the first check runs
		// immediately, so above it every `vault list-clients` would be a chance to
		// rotate the signing key as a side effect of listing clients.
		//
		// Stop is deferred above the pool's Close and blocks until the loop has
		// exited, so a rotation cannot still be inside its transaction when the
		// pool goes.
		keyRotation := keystore.NewRotation(ks, config.KeyRotationInterval())
		if keyRotation.Enabled() {
			keyRotation.Start(ctx)
			defer keyRotation.Stop()
			log.Printf("keystore rotation: rotating the signing key once it is older than %s", config.KeyRotationInterval())
		} else {
			log.Printf("WARNING: VAULT_KEY_ROTATION_INTERVAL is not positive; the signing key will never rotate on its own, " +
				"so every token this deployment issues stays verifiable under one private key for the life of the install")
		}

		// A retention period shorter than the access token TTL strands tokens on
		// every rotation: the key stops verifying while tokens it signed are still
		// inside their lifetime. That was survivable while the row lingered, since
		// an operator could push expires_at back out and recover. Reaping makes it
		// permanent, so the misconfiguration has to be visible before it bites.
		if cfg.KeyRetentionPeriod < cfg.AccessTokenTTL {
			log.Printf("WARNING: VAULT_KEY_RETENTION_PERIOD (%s) is shorter than the access token TTL (%s); "+
				"rotation will strand tokens that are still within their lifetime",
				cfg.KeyRetentionPeriod, cfg.AccessTokenTTL)
		}
	}

	// Readiness dependencies
	readyDeps := &handler.ReadyzDeps{
		PingDB: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return db.Pool.Ping(ctx)
		},
		// The cache probe reports two different losses through one signal.
		//
		// cacheDegraded is set when NewCache failed at startup and this process
		// is running on the per-process memory fallback. Nothing else announces
		// that: the fallback is one log line, and every cross-replica control
		// silently becomes per-pod, so the login and password-reset limiters
		// multiply by the replica count, OAuth state written on one pod cannot
		// be read on another, and the TOTP replay guard only blocks a replay
		// that lands on the pod that saw the first use.
		//
		// The round trip below catches the other case, where the cache was fine
		// at boot and has since gone away. It writes and reads its own key so a
		// backend that accepts writes and returns nothing is not reported
		// healthy.
		//
		// A failing probe reports "degraded" and deliberately still answers 200,
		// which is pinned in internal/handler. Taking every replica out of
		// rotation the moment Redis blinks is worse for an auth service than
		// running degraded and saying so.
		PingCache: func() error {
			if cacheDegraded {
				return errors.New("cache fell back to per-process memory at startup")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			const probeKey = "readyz:probe"
			if err := appCache.Set(ctx, probeKey, "1", 10*time.Second); err != nil {
				return fmt.Errorf("cache write: %w", err)
			}
			if _, err := appCache.Get(ctx, probeKey); err != nil {
				return fmt.Errorf("cache read back: %w", err)
			}
			return nil
		},
	}

	// Start server
	deps := &server.Deps{
		Config:            cfg,
		AuthSvc:           authSvc,
		TokenSvc:          tokenSvc,
		MFASvc:            mfaSvc,
		Keys:              keys,
		Cache:             appCache,
		AuditLog:          auditLogger,
		Users:             userRepo,
		Devices:           deviceRepo,
		Tokens:            refreshTokenRepo,
		Clients:           clientRepo,
		TOTP:              totpRepo,
		WebAuthn:          webauthnRepo,
		BackupCodes:       backupCodeRepo,
		PwHistory:         pwHistoryRepo,
		Social:            socialAccountRepo,
		EmailSender:       emailSender,
		Mailer:            mailer,
		OAuthProviders:    oauthProviders,
		MasterKey:         masterKey,
		HMACSecret:        hmacSecret,
		Pepper:            cfg.Pepper,
		HIBP:              hibpClient,
		HIBPEnabled:       cfg.HIBPCheck,
		ReadyDeps:         readyDeps,
		HoneypotAlerter:   honeypotAlerter,
		IPIntel:           ipIntelDB,
		Metrics:           metricsCollector,
		KeyStore:          ks,
		KMS:               kmsSvc,
		Identity:          identityRepo,
		Blobs:             blobRepo,
		Recovery:          recoveryRepo,
		RecoveryPublicKey: recoveryPub,
		AuditEvents:       auditRepo,
		ServiceDocs:       serviceDocRepo,
		LoginCountries:    loginCountryRepo,
		Mint:              mintSvc,
	}

	srv := server.New(deps)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
