// Package main is the entry point for the Vault JWT authentication and
// authorization server.
package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/cli"
	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/keystore"
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

// sanitizeDBError strips connection URLs (which may contain passwords) from error messages.
var dbURLPattern = regexp.MustCompile(`postgres://[^\s]+@`)

func sanitizeDBError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", dbURLPattern.ReplaceAllString(err.Error(), "postgres://***@"))
}

//nolint:gocognit,gocyclo // entry-point wires every subsystem; refactor would scatter fail-fast init across helpers
func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("vault %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		return
	}

	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
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

	// Connect to PostgreSQL (vault_app role)
	db, err := postgres.New(ctx, cfg.DatabaseURL("app"), cfg.DBMaxConns)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", sanitizeDBError(err))
	}
	defer db.Close()

	// Initialize cache
	appCache, err := cache.NewCache(cfg.CacheBackend, cfg.RedisAddr, cfg.RedisPass, db.Pool)
	if err != nil {
		log.Printf("Cache init failed, falling back to memory: %v", err)
		appCache = cache.NewMemoryCache()
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
	rateLimitRepo := postgres.NewRateLimitRepo(db)

	// Initialize audit logger
	auditLogger := audit.NewLoggerWithBufferSize(auditRepo, cfg.AuditFlushInterval, cfg.AuditBufferSize)
	defer auditLogger.Close(ctx)

	// CLI commands (check before starting server)
	cliHandler := cli.New(clientRepo, userRepo, refreshTokenRepo, adminConfigRepo, auditRepo, cfg.Pepper)

	// Initialize admin token on first boot
	if err := cliHandler.InitAdminToken(ctx); err != nil {
		log.Printf("Admin token init error: %v", err)
	}

	// Declarative seeding from VAULT_SEED_FILE (idempotent)
	if cfg.SeedFile != "" {
		sf, err := seed.Load(cfg.SeedFile)
		if err != nil {
			auditLogger.Close(ctx)
			log.Fatalf("Failed to load seed file: %v", err) //nolint:gocritic // exitAfterDefer is intentional; we drained on the line above
		}
		if err := seed.Run(ctx, sf, seed.Deps{Users: userRepo, Clients: clientRepo}); err != nil {
			log.Fatalf("Seeding failed: %v", err)
		}
	}

	// Check if this is a CLI invocation
	if cliHandler.Run(ctx, os.Args) {
		return
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
		if len(cfg.MasterKey) != 32 {
			log.Fatal("VAULT_KEY_ROTATION_DB=true requires MASTER_KEY_FILE (32 bytes)")
		}
		ks, err = keystore.New(db.Pool, cfg.MasterKey, cfg.KeyRetentionPeriod)
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
		emailSender = email.NewSMTPSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.EmailFrom)
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
		cfg.PasswordMinLength, cfg.HIBPCheck, cfg.HMACSecret,
	)

	authSvc.SetRateLimitRepo(rateLimitRepo)
	authSvc.SetMaxSessionsPerUser(cfg.MaxSessionsPerUser)

	// Zero master key and HMAC secret from config after passing to services.
	// Note: string secrets (Pepper, DB passwords) can't be zeroed in Go — accepted limitation.
	config.ZeroBytes(cfg.MasterKey)
	config.ZeroBytes(cfg.HMACSecret)

	// Initialize honeypot alerter (only for honeypot profile)
	var honeypotAlerter *honeypot.Alerter
	if cfg.Profile == config.ProfileHoneypot {
		honeypotAlerter = honeypot.NewAlerter(cfg.HoneypotWebhookURL, cfg.HoneypotTrapUsers, auditLogger)
		authSvc.SetHoneypotAlerter(honeypotAlerter)
		// Set fake JWT claims to match real server config so honeypot tokens
		// are indistinguishable from real ones in their iss/aud fields.
		honeypot.ConfigureFakeJWT(cfg.Origin, cfg.Origin)
		log.Printf("Honeypot mode active: %d trap users configured", len(cfg.HoneypotTrapUsers))
	}

	// Initialize metrics collector (if enabled)
	var metricsCollector *metrics.Collector
	if cfg.MetricsEnabled {
		metricsCollector = metrics.NewCollector(
			vaultcrypto.Argon2ActiveCount,
			vaultcrypto.Argon2RejectedCount,
			vaultcrypto.Argon2MaxConcurrent,
		)
		authSvc.SetMetrics(metricsCollector)
		log.Println("Prometheus metrics enabled at GET /metrics")
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
	}

	// Readiness dependencies
	readyDeps := &handler.ReadyzDeps{
		PingDB: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return db.Pool.Ping(ctx)
		},
	}

	// Start server
	deps := &server.Deps{
		Config:          cfg,
		AuthSvc:         authSvc,
		TokenSvc:        tokenSvc,
		MFASvc:          mfaSvc,
		Keys:            keys,
		Cache:           appCache,
		AuditLog:        auditLogger,
		Users:           userRepo,
		Devices:         deviceRepo,
		Tokens:          refreshTokenRepo,
		Clients:         clientRepo,
		TOTP:            totpRepo,
		WebAuthn:        webauthnRepo,
		BackupCodes:     backupCodeRepo,
		PwHistory:       pwHistoryRepo,
		Social:          socialAccountRepo,
		EmailSender:     emailSender,
		OAuthProviders:  oauthProviders,
		MasterKey:       cfg.MasterKey,
		HMACSecret:      cfg.HMACSecret,
		Pepper:          cfg.Pepper,
		HIBP:            hibpClient,
		HIBPEnabled:     cfg.HIBPCheck,
		ReadyDeps:       readyDeps,
		HoneypotAlerter: honeypotAlerter,
		Metrics:         metricsCollector,
		KeyStore:        ks,
		Identity:        identityRepo,
		Blobs:           blobRepo,
	}

	srv := server.New(deps)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
