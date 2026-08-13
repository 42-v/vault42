// Package main is the entry point for the Vault Admin Gateway — a local-only
// mTLS binary for RBAC-protected admin operations. It binds to loopback,
// requires client certificates, and enforces role-based permissions.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/migrate"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/seed"
	"github.com/42-v/vault42/internal/service"
)

// Build stamps, set at link time with -ldflags -X. The defaults below are what
// an unstamped local build reports, so a binary claiming "dev" did not come off
// the release pipeline. They are printed by --version and nowhere else.
var (
	// Version is the release version this binary was built from.
	Version = "dev"
	// GitCommit is the commit SHA this binary was built from.
	GitCommit = "unknown"
	// BuildTime is the UTC timestamp of the build.
	BuildTime = "unknown"
)

var dbURLPattern = regexp.MustCompile(`postgres://[^\s]+@`)

func sanitizeDBError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", dbURLPattern.ReplaceAllString(err.Error(), "postgres://***@"))
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("vault-admin-gateway %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		return
	}

	ctx := context.Background()

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("admin-gateway: config error: %v", err)
	}

	log.Printf("admin-gateway: listen=%s tls=mTLS db=%s:%s/%s",
		cfg.ListenAddr, cfg.DBHost, cfg.DBPort, cfg.DBName)

	// Run migrations if enabled (using vault_mig role for DDL)
	if cfg.AutoMigrate {
		migPassword := ""
		if pw, err := loadSecret("DB_MIG_PASSWORD"); err == nil {
			migPassword = pw
		}
		migURL := postgresURL("vault_mig", migPassword, cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBSSLMode)
		migConn, err := pgx.Connect(ctx, migURL)
		if err != nil {
			log.Fatalf("admin-gateway: migration connect error: %v", sanitizeDBError(err))
		}
		if err := migrate.Run(ctx, migConn, "migrations"); err != nil {
			log.Fatalf("admin-gateway: migration error: %v", err)
		}
		_ = migConn.Close(ctx)
		log.Println("admin-gateway: migrations complete")
	}

	// Connect to PostgreSQL (vault_admin role)
	db, err := postgres.New(ctx, cfg.DatabaseURL(), cfg.DBMaxConns)
	if err != nil {
		log.Fatalf("admin-gateway: database error: %v", sanitizeDBError(err))
	}
	defer db.Close()

	// Initialize repositories
	adminUserRepo := postgres.NewAdminUserRepo(db)
	adminSessionRepo := postgres.NewAdminSessionRepo(db)
	userRepo := postgres.NewUserRepo(db)
	clientRepo := postgres.NewClientRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	adminConfigRepo := postgres.NewAdminConfigRepo(db)
	// Repositories used by the account-erasure cascade (DELETE /admin/users/{id}).
	refreshTokenRepo := postgres.NewRefreshTokenRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	socialAccountRepo := postgres.NewSocialAccountRepo(db)
	pwHistoryRepo := postgres.NewPasswordHistoryRepo(db)
	totpRepo := postgres.NewTOTPRepo(db)
	webauthnRepo := postgres.NewWebAuthnRepo(db)
	backupCodeRepo := postgres.NewBackupCodeRepo(db)
	identityRepo := postgres.NewIdentityRepo(db)
	blobRepo := postgres.NewBlobRepo(db)
	recoveryRepo := postgres.NewAccountRecoveryRepo(db)

	// Initialize audit logger
	auditLogger := audit.NewLogger(auditRepo, 0)
	defer auditLogger.Close(ctx)

	// First boot: create super_admin if none exist
	if err := adminapi.EnsureFirstAdmin(ctx, adminUserRepo, cfg.Pepper); err != nil {
		log.Printf("admin-gateway: first admin creation error: %v", err)
	}

	// Seed admin users from JSON file (idempotent — skips existing)
	if cfg.SeedFile != "" {
		sf, err := seed.Load(cfg.SeedFile)
		if err != nil {
			log.Printf("admin-gateway: seed load error: %v", err)
		} else {
			if err := seed.RunAdmins(ctx, sf, adminUserRepo, cfg.Pepper); err != nil {
				log.Printf("admin-gateway: seed error: %v", err)
			}
		}
	}

	// Working copies of the key material, taken BEFORE anything consumes it.
	//
	// Every consumer below retains the slice it is handed (keystore.New, the auth
	// handler, the API handler, the identity service all just store the header),
	// and config.ZeroBytes(cfg.MasterKey) wipes the config's backing array in place
	// at the end of setup. A consumer handed cfg.MasterKey directly would be left
	// holding 32 zero bytes — still a valid AES-256 key length, so it would encrypt
	// and decrypt consistently against itself while the at-rest protection was
	// silently gone: admin TOTP secrets, and the JWT signing keys the gateway wraps
	// on rotation. Pass these copies; never cfg.MasterKey.
	masterKey := append([]byte(nil), cfg.MasterKey...)

	// LoadConfig already refused a non-32-byte key and keystore.New errors only
	// on that length check, so this cannot fail today. The error is still read
	// rather than discarded, because discarding it means that a second error
	// path added to keystore.New later arrives here as a nil dereference on the
	// following line, which is a crash reported from the wrong place. The branch
	// is unreachable by construction and is excluded from coverage rather than
	// reached by a test.
	ks, err := keystore.New(db.Pool, masterKey, time.Hour)
	if err != nil {
		log.Fatalf("admin-gateway: keystore init: %v", err)
	}
	if err := ks.EnsureKey(ctx, nil); err != nil {
		log.Printf("admin-gateway: keystore ensure key error: %v", err)
	}
	ks.StartRefreshLoop(ctx, 60*time.Second)
	defer ks.Stop()

	// Create handlers
	authHandler := adminapi.NewAuthHandler(
		adminUserRepo, adminSessionRepo, auditLogger,
		masterKey, cfg.Pepper, cfg.SessionTTL, cfg.MaxFailed, cfg.LockoutDur,
	)

	apiHandler := adminapi.NewHandler(
		userRepo, clientRepo, nil, auditRepo,
		adminUserRepo, adminSessionRepo, adminConfigRepo,
		ks, auditLogger, masterKey, cfg.Pepper,
	)
	apiHandler.SetAppRoleRepo(postgres.NewAppRoleRepo(db))
	apiHandler.SetEmailRepos(
		postgres.NewEmailBrandingRepo(db),
		postgres.NewEmailTemplateRepo(db),
		envInt("VAULT_MAX_EMAIL_TEMPLATE_SIZE", 65536),
	)

	// Wire the account-erasure service (DELETE /admin/users/{id}). It needs the
	// HMAC secret to derive identity/blob pseudonyms; without it the endpoint
	// stays disabled (returns 503). The recovery public key is optional — absent
	// means erasure proceeds but is not recoverable.
	if len(cfg.HMACSecret) > 0 {
		var recoveryPub *rsa.PublicKey
		if len(cfg.RecoveryPublicKeyPEM) > 0 {
			recoveryPub, err = vaultcrypto.LoadRSAPublicKeyPEM(cfg.RecoveryPublicKeyPEM)
			if err != nil {
				_ = auditLogger.Close(ctx)
				log.Fatalf("admin-gateway: failed to load recovery public key: %v", err) //nolint:gocritic // exitAfterDefer is intentional; we drained on the line above
			}
		}
		erasureSvc := service.NewErasureService(
			userRepo, identityRepo, blobRepo, deviceRepo, socialAccountRepo,
			pwHistoryRepo, refreshTokenRepo, totpRepo, webauthnRepo, backupCodeRepo,
			recoveryRepo, auditLogger, recoveryPub, cfg.HMACSecret,
		)
		// Documents other services filed about the user are personal data under
		// Art. 4(1) whoever authored them, so the cascade has to reach them. This
		// call was missing, and its absence was invisible from here: the erasure
		// returned success and wrote an AccountErased audit row while every
		// service document survived. migrations/014_service_documents.sql grants
		// vault_admin SELECT and DELETE on the table for this exact cascade, so
		// the privilege was provisioned for a wiring that did not exist.
		//
		// DELETE /admin/users/{id} is how an Art. 17 request is normally actioned,
		// which made this the path that mattered most.
		erasureSvc.SetServiceDocs(postgres.NewServiceDocumentRepo(db))
		apiHandler.SetErasureService(erasureSvc)
		// Same master key + HMAC secret as vault42 itself, so the pseudonym and
		// the profile ciphertext an import writes are readable by the main server.
		//
		apiHandler.SetIdentityService(service.NewIdentityService(identityRepo, masterKey, cfg.HMACSecret))
	} else {
		log.Println("admin-gateway: HMAC_SECRET_FILE not set — account erasure endpoint disabled")
	}

	router := adminapi.NewRouter(authHandler, apiHandler, adminapi.RouterOpts{
		DevMode:    cfg.DevMode,
		Killswitch: cfg.Killswitch,
		AuditRepo:  auditRepo,
	})

	// Load mTLS configuration
	clientCA, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		_ = auditLogger.Close(ctx)
		log.Fatalf("admin-gateway: failed to read client CA: %v", err) //nolint:gocritic // exitAfterDefer is intentional; we drained on the line above
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(clientCA) {
		_ = auditLogger.Close(ctx)
		log.Fatal("admin-gateway: failed to parse client CA certificate")
	}

	// Zero master key from config after passing to handlers
	config.ZeroBytes(cfg.MasterKey)

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAPool,
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		TLSConfig:         tlsCfg,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("admin-gateway: listening on %s (mTLS, loopback-only)", cfg.ListenAddr)
		if err := srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin-gateway: listen error: %v", err)
		}
	}()

	<-done
	log.Println("admin-gateway: shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("admin-gateway: shutdown error: %v", err)
	}

	log.Println("admin-gateway: stopped")
}
