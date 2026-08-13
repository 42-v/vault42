// Package server wires together the HTTP server, TLS configuration, middleware
// chain, and route registration for The Vault. It provides graceful shutdown
// on SIGTERM/SIGINT and configures TLS 1.3 as the minimum version when enabled.
package server

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/frontend"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/kms"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// Deps holds all dependencies injected into the server, including services,
// repositories, cache, audit logger, email sender, and OAuth2 providers.
type Deps struct {
	Config   *config.Config
	AuthSvc  *service.AuthService
	TokenSvc *service.TokenService
	MFASvc   *service.MFAService
	Keys     map[string]*rsa.PublicKey
	Cache    cache.Cache
	AuditLog *audit.Logger

	// Repositories
	Users       repository.UserRepository
	Devices     repository.DeviceRepository
	Tokens      repository.RefreshTokenRepository
	Clients     repository.ClientRepository
	TOTP        repository.TOTPRepository
	WebAuthn    repository.WebAuthnRepository
	BackupCodes repository.BackupCodeRepository
	PwHistory   repository.PasswordHistoryRepository
	Social      repository.SocialAccountRepository

	// ServiceDocs backs the service-scoped JSON document store. Nil unless
	// VAULT_SVCDOC_ENABLED, in which case the routes are not mounted at all.
	ServiceDocs repository.ServiceDocumentRepository

	// Mint backs POST /mint. Built in main rather than here because
	// service.NewMintService returns an error on an unsafe mint policy and
	// setupRoutes cannot fail; nil unless minting is configured.
	Mint *service.MintService

	// Email
	EmailSender email.Sender
	// Mailer applies per-app white-label branding/templates. Optional: when nil,
	// handlers fall back to their constructor-built global mailer.
	Mailer *email.Mailer

	// OAuth2 providers
	OAuthProviders map[string]oauth2.Provider

	// Master key for TOTP encryption
	MasterKey  []byte
	HMACSecret []byte
	Pepper     string

	// HIBP breach check
	HIBP        *service.HIBPClient
	HIBPEnabled bool

	// Readiness
	ReadyDeps *handler.ReadyzDeps

	// Honeypot (nil unless profile=honeypot)
	HoneypotAlerter *honeypot.Alerter

	// Metrics (nil unless VAULT_METRICS_ENABLED=true)
	Metrics *metrics.Collector

	// KeyStore (nil unless VAULT_KEY_ROTATION_DB=true)
	KeyStore *keystore.KeyStore

	// KMS backs the POST /kms/unwrap envelope-unwrap oracle (life42 data-root
	// re-root). Nil unless a KMS root key is configured (KMS_ROOT_KEY_FILE), in
	// which case the endpoint is not mounted at all.
	KMS *kms.Service

	// Identity & Blob storage
	Identity repository.IdentityRepository
	Blobs    repository.BlobRepository

	// Account-recovery escrow log (append-only). Required to build the
	// ErasureService that backs the self-service /user/account endpoint.
	Recovery repository.AccountRecoveryRepository

	// RecoveryPublicKey is the RSA public key used to encrypt recovery records.
	// Nil disables escrow (deletion still works, but is not recoverable).
	RecoveryPublicKey *rsa.PublicKey

	// AuditEvents is the audit repository used for read-back of user-scoped
	// events in the data-export endpoint. The AuditLog logger wraps the same
	// repository for writes.
	AuditEvents repository.AuditRepository
}

// Server is the main HTTP server for The Vault. It manages the middleware
// chain, route registration, TLS configuration, and graceful shutdown.
type Server struct {
	deps    *Deps
	httpSrv *http.Server
}

// New creates a new Server with the given dependencies.
func New(deps *Deps) *Server {
	return &Server{deps: deps}
}

// Start configures the middleware chain, registers all routes, and starts the
// HTTP(S) server. It blocks until a SIGTERM or SIGINT signal triggers graceful
// shutdown. The middleware chain is: recovery, request ID, logger, security
// headers, CORS, max body (8KB), then the route handler.
func (s *Server) Start() error {
	mux := s.setupRoutes()
	cfg := s.deps.Config

	// Configure trusted proxies, real IP header, and TLS fingerprint header
	middleware.SetTrustedProxies(cfg.TrustedProxies)
	middleware.SetRealIPHeader(cfg.RealIPHeader)
	middleware.SetTLSFingerprintHeader(cfg.TLSFingerprintHeader)
	middleware.SetIPAccessLists(cfg.IPAllowlist, cfg.IPBlocklist, cfg.GeoAllowlist, cfg.GeoBlocklist, cfg.GeoIPHeader)

	// Build middleware chain: recovery -> requestid -> logger -> security_headers -> ipaccess -> cors -> maxbody -> [honeypot] -> handler
	var h http.Handler = mux
	if cfg.Profile == config.ProfileHoneypot && s.deps.HoneypotAlerter != nil {
		h = honeypot.LoggingMiddleware(s.deps.HoneypotAlerter)(h)
	}
	h = middleware.MaxBodyWithExemptions(8*1024, []string{"/user/blobs", "/service/documents"})(h) // 8KB max body; blob uploads and service documents enforce their own limit
	h = middleware.AppContext(h)                                                                   // resolve X-Vault-App tenant for white-label emails
	h = middleware.CORS(cfg.Origin, parseCORSOrigins(cfg.CORSOrigins), cfg.CORSAllowAll)(h)
	h = middleware.IPAccess()(h)
	h = middleware.SecurityHeaders(cfg.ServeFrontend)(h)
	h = middleware.Logger(h)
	h = middleware.RequestID(h)
	h = middleware.Recovery(h)

	s.httpSrv = &http.Server{
		Addr:           cfg.ListenAddr,
		Handler:        h,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB — prevents large-header DoS
	}

	if cfg.TLSEnabled && cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		s.httpSrv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	// drained closes only after Shutdown has returned, which is the difference
	// between the drain starting and the drain finishing.
	//
	// ListenAndServe returns ErrServerClosed the instant Shutdown is CALLED, so
	// returning on that alone handed control back to main while handlers were
	// still running. main's deferred kmsSvc.Close() and ks.Stop() then zeroed the
	// KMS root and the keystore master key underneath them, and the configured
	// ShutdownTimeout was waited on by nobody. That happened on every SIGTERM,
	// which is every Kubernetes rollout.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-done
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		// Shutdown errors are non-actionable during signal handler.
		_ = s.httpSrv.Shutdown(ctx)
	}()

	log.Printf("The Vault listening on %s (profile=%s)", cfg.ListenAddr, cfg.Profile)

	var err error
	if cfg.TLSEnabled && cfg.TLSCertFile != "" {
		err = s.httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		err = s.httpSrv.ListenAndServe()
	}

	if err == http.ErrServerClosed {
		// The drain is in progress, not finished. Wait for it, so that whatever
		// the caller does next happens after the last handler has returned.
		<-drained
		return nil
	}
	return fmt.Errorf("server: %w", err)
}

func (s *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	d := s.deps
	cfg := d.Config

	// Create handlers
	secureCookies := cfg.TLSEnabled || cfg.ForceSecureCookies
	authHandler := handler.NewAuthHandler(d.AuthSvc, d.Users, d.Cache, d.AuditLog, d.Pepper, secureCookies)
	userHandler := handler.NewUserHandler(d.Users, d.Devices, d.Tokens, d.MFASvc)
	passwordHandler := handler.NewPasswordHandler(d.Users, d.PwHistory, d.Tokens, d.EmailSender, d.AuditLog, d.Cache, cfg.Origin, cfg.AppName, d.Pepper, cfg.PasswordMinLength, d.HIBP, d.HIBPEnabled)
	passwordHandler.SetMailer(d.Mailer) // share the white-label mailer (nil is ignored)
	totpHandler := handler.NewTOTPHandler(d.TOTP, d.MasterKey, cfg.Origin, d.Cache, d.AuthSvc, secureCookies)
	// Initialize WebAuthn
	var webauthnHandler *handler.WebAuthnHandler
	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.AppName,
		RPID:          cfg.RPHost(),
		RPOrigins:     []string{cfg.Origin},
	})
	if err != nil {
		log.Printf("WebAuthn init failed (endpoints disabled): %v", err)
		webauthnHandler = handler.NewWebAuthnHandler(d.WebAuthn, d.Users, d.Cache, nil, d.AuthSvc, secureCookies)
	} else {
		webauthnHandler = handler.NewWebAuthnHandler(d.WebAuthn, d.Users, d.Cache, wan, d.AuthSvc, secureCookies)
	}
	emailOTPHandler := handler.NewEmailOTPHandler(d.AuthSvc, d.Users, secureCookies)
	backupCodeHandler := handler.NewBackupCodeHandler(d.BackupCodes, d.HMACSecret, d.AuthSvc, secureCookies)
	mfaHandler := handler.NewMFAHandler(d.MFASvc)
	clientHandler := handler.NewClientHandler(d.Clients, d.TokenSvc, d.AuditLog)
	var wellKnownHandler *handler.WellKnownHandler
	if d.KeyStore != nil {
		wellKnownHandler = handler.NewDynamicWellKnownHandler(d.KeyStore.KeyProvider(), cfg.Origin)
	} else {
		wellKnownHandler = handler.NewWellKnownHandler(d.Keys, cfg.Origin)
	}

	// Auth middleware — use dynamic key provider when keystore is active, static map otherwise
	var authMw, challengeMw func(http.Handler) http.Handler
	if d.KeyStore != nil {
		authMw = middleware.AuthDynamic(d.KeyStore.KeyProvider(), cfg.Origin, cfg.Origin)
		challengeMw = middleware.AuthChallengeDynamic(d.KeyStore.KeyProvider(), cfg.Origin, cfg.Origin)
	} else {
		authMw = middleware.Auth(d.Keys, cfg.Origin, cfg.Origin)
		challengeMw = middleware.AuthChallenge(d.Keys, cfg.Origin, cfg.Origin)
	}
	fingerprintMw := middleware.Fingerprint(false)

	// Confirmed middleware (requires recent password re-entry)
	confirmMw := middleware.Confirmed(d.Cache)

	// DPoP middleware (RFC 9449) — only active when configured
	var dpopMw func(http.Handler) http.Handler
	if cfg.DPoPEnabled {
		dpopMw = middleware.DPoP(d.Cache, d.Config.Origin)
	}

	// dpopWrap conditionally applies DPoP middleware when enabled. No-op when disabled.
	dpopWrap := func(h http.Handler) http.Handler {
		if dpopMw != nil {
			return dpopMw(h)
		}
		return h
	}

	// Wrap handler with auth + fingerprint
	authed := func(h http.HandlerFunc) http.Handler {
		return authMw(fingerprintMw(h))
	}
	// 2FA verify endpoints accept challenge tokens (+ DPoP when enabled)
	authedChallenge := func(h http.HandlerFunc) http.Handler {
		return challengeMw(fingerprintMw(dpopWrap(h)))
	}
	// Sensitive endpoints require auth + recent password confirmation
	confirmed := func(h http.HandlerFunc) http.Handler {
		return authMw(fingerprintMw(confirmMw(h)))
	}

	// Rate limiting middleware factories
	rlEnabled := cfg.RateLimitEnabled
	// Auth-sensitive limiters fail closed on cache outage (audit L4): the per-pod
	// in-memory fallback would multiply the effective limit across replicas.
	loginRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 5, Window: 15 * time.Minute, KeyFunc: middleware.LoginRateLimitKey, FailClosed: true,
	}, rlEnabled)
	registerRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
	}, rlEnabled)
	refreshRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 30, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
	}, rlEnabled)
	passwordResetRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
	}, rlEnabled)
	totpRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 5, Window: 5 * time.Minute, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
	}, rlEnabled)
	verifyEmailRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 10, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey,
	}, rlEnabled)
	confirmRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 5, Window: 15 * time.Minute, KeyFunc: middleware.GeneralRateLimitKey,
	}, rlEnabled)
	clientTokenRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
	}, rlEnabled)
	// Account erasure is irreversible (recoverable only via the offline key); cap
	// it tightly and fail closed so a cache outage cannot widen the limit.
	accountDeleteRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
	}, rlEnabled)

	// ===== Public endpoints (no auth) =====
	mux.HandleFunc("GET /healthz", handler.Healthz)
	mux.HandleFunc("GET /readyz", handler.Readyz(d.ReadyDeps))

	// Prometheus metrics (gated by VAULT_METRICS_ENABLED; protect with NetworkPolicy in production)
	if d.Metrics != nil {
		mux.HandleFunc("GET /metrics", d.Metrics.Handler())
	}

	// Capabilities (public, no auth — lets clients discover server config)
	oauthNames := make([]string, 0, len(d.OAuthProviders))
	for name := range d.OAuthProviders {
		oauthNames = append(oauthNames, name)
	}
	mux.HandleFunc("GET /auth/capabilities", handler.Capabilities(cfg.RegistrationEnabled, cfg.MFARequired, oauthNames))

	// Auth (rate limited, DPoP on token endpoints when enabled)
	if cfg.RegistrationEnabled {
		mux.Handle("POST /auth/register", registerRL(http.HandlerFunc(authHandler.Register)))
	} else {
		mux.HandleFunc("POST /auth/register", func(w http.ResponseWriter, r *http.Request) {
			handler.WriteError(w, http.StatusForbidden, "registration_disabled")
		})
	}
	mux.Handle("POST /auth/login", loginRL(dpopWrap(http.HandlerFunc(authHandler.Login))))
	mux.Handle("POST /auth/refresh", refreshRL(dpopWrap(http.HandlerFunc(authHandler.Refresh))))

	// Email verification (public, rate limited)
	mux.Handle("GET /auth/verify-email", verifyEmailRL(http.HandlerFunc(authHandler.VerifyEmail)))

	// Password reset (public, rate limited)
	mux.Handle("POST /auth/password/reset", passwordResetRL(http.HandlerFunc(passwordHandler.ResetRequest)))
	mux.Handle("POST /auth/password/reset/confirm", passwordResetRL(http.HandlerFunc(passwordHandler.ResetConfirm)))

	// Client credentials (public, uses Basic auth, rate limited)
	mux.Handle("POST /client/token", clientTokenRL(http.HandlerFunc(clientHandler.Token)))

	// Well-known
	mux.HandleFunc("GET /.well-known/jwks.json", wellKnownHandler.JWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", wellKnownHandler.OpenIDConfig)

	// OAuth2 (public redirects)
	if len(d.OAuthProviders) > 0 {
		oauthHandler := handler.NewOAuthHandler(d.OAuthProviders, d.HMACSecret, d.Cache, cfg.Origin, d.Users, d.Social, d.Tokens, d.AuthSvc, d.TokenSvc, d.MFASvc, d.AuditLog, secureCookies)
		oauthExchangeRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		// Authorize writes an unauthenticated per-request oauth_state cache entry;
		// rate-limit it like its siblings to avoid cache-fill eviction pressure
		// on shared lockout/OTP/reset state (audit M2).
		authorizeRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		mux.Handle("GET /auth/oauth2/authorize", authorizeRL(http.HandlerFunc(oauthHandler.Authorize)))
		mux.Handle("GET /auth/oauth2/callback/{provider}", loginRL(http.HandlerFunc(oauthHandler.Callback)))
		mux.Handle("POST /auth/oauth2/exchange", oauthExchangeRL(http.HandlerFunc(oauthHandler.Exchange)))
	}

	// ===== Authenticated endpoints =====
	mux.Handle("POST /auth/logout", authed(authHandler.Logout))
	mux.Handle("POST /auth/confirm", authMw(fingerprintMw(confirmRL(http.HandlerFunc(authHandler.ConfirmPassword)))))

	// User profile & sessions
	mux.Handle("GET /user/profile", authed(userHandler.Profile))
	mux.Handle("PUT /user/profile", authed(userHandler.UpdateProfile))
	mux.Handle("GET /user/sessions", authed(userHandler.Sessions))
	mux.Handle("DELETE /user/sessions/{id}", authed(userHandler.RevokeSession))
	mux.Handle("DELETE /user/sessions", authed(userHandler.RevokeAllSessions))
	mux.Handle("GET /user/devices", authed(userHandler.Devices))
	mux.Handle("PATCH /user/devices/{id}", authed(userHandler.RenameDevice))
	mux.Handle("DELETE /user/devices/{id}", authed(userHandler.DeleteDevice))

	// Self-service account erasure (GDPR). Requires auth + password re-confirmation
	// (verified inside the handler) behind a strict, fail-closed rate limiter. The
	// erasure service shares d.HMACSecret with the identity/blob services so it
	// derives the same pseudonyms for the cascade.
	if d.Recovery != nil {
		erasureSvc := service.NewErasureService(
			d.Users, d.Identity, d.Blobs, d.Devices, d.Social, d.PwHistory, d.Tokens,
			d.TOTP, d.WebAuthn, d.BackupCodes,
			d.Recovery, d.AuditLog, d.RecoveryPublicKey, d.HMACSecret,
		)
		erasureSvc.SetServiceDocs(d.ServiceDocs)
		accountHandler := handler.NewAccountHandler(erasureSvc, d.Users, d.AuditLog, d.Pepper)
		mux.Handle("DELETE /user/account", authMw(fingerprintMw(accountDeleteRL(http.HandlerFunc(accountHandler.Delete)))))
	}

	// Password change (authenticated, rate limited, already requires current password)
	mux.Handle("POST /user/password", authMw(fingerprintMw(confirmRL(http.HandlerFunc(passwordHandler.ChangePassword)))))

	// 2FA — Status
	mux.Handle("GET /auth/2fa/status", authed(mfaHandler.Status))

	// 2FA — TOTP (sensitive ops require confirmation)
	mux.Handle("POST /auth/2fa/totp/setup", confirmed(totpHandler.Setup))
	mux.Handle("POST /auth/2fa/totp/verify", totpRL(authedChallenge(totpHandler.Verify)))
	mux.Handle("DELETE /auth/2fa/totp", confirmed(totpHandler.Disable))

	// 2FA — WebAuthn (sensitive ops require confirmation)
	mux.Handle("POST /auth/2fa/webauthn/register/begin", confirmed(webauthnHandler.RegisterBegin))
	mux.Handle("POST /auth/2fa/webauthn/register/finish", confirmed(webauthnHandler.RegisterFinish))
	mux.Handle("POST /auth/2fa/webauthn/verify/begin", authedChallenge(webauthnHandler.VerifyBegin))
	mux.Handle("POST /auth/2fa/webauthn/verify/finish", authedChallenge(webauthnHandler.VerifyFinish))
	mux.Handle("GET /auth/2fa/webauthn/credentials", authed(webauthnHandler.ListCredentials))
	mux.Handle("DELETE /auth/2fa/webauthn/credentials/{id}", confirmed(webauthnHandler.DeleteCredential))

	// 2FA — Backup codes (sensitive)
	mux.Handle("POST /auth/2fa/backup-codes", confirmed(backupCodeHandler.Generate))
	mux.Handle("POST /auth/2fa/backup-code/verify", totpRL(authedChallenge(backupCodeHandler.Verify)))

	// 2FA — Email OTP (fallback when no TOTP/WebAuthn configured)
	mux.Handle("POST /auth/2fa/email-otp/verify", totpRL(authedChallenge(emailOTPHandler.Verify)))
	mux.Handle("POST /auth/2fa/email-otp/resend", totpRL(authedChallenge(emailOTPHandler.Resend)))

	// Identity & blob services are built once here so both their own endpoints
	// and the data-export aggregate can share a single instance. Either may
	// remain nil when the corresponding store is disabled.
	var identitySvc *service.IdentityService
	var blobSvc *service.BlobService

	// Identity store (encrypted PII)
	if d.Identity != nil {
		identitySvc = service.NewIdentityService(d.Identity, d.MasterKey, d.HMACSecret)
		identityHandler := handler.NewIdentityHandler(identitySvc, d.AuditLog)
		identityReadRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 30, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		identityWriteRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		mux.Handle("GET /user/identity", identityReadRL(authed(identityHandler.Get)))
		mux.Handle("PUT /user/identity", identityWriteRL(authed(identityHandler.Put)))
		mux.Handle("DELETE /user/identity", authMw(fingerprintMw(confirmMw(confirmRL(http.HandlerFunc(identityHandler.Delete))))))
		// Withdrawal must be no harder than granting (Art. 7(3)), so this carries
		// the read rate limit and no confirmation step — unlike identity deletion.
		mux.Handle("POST /user/marketing/unsubscribe", identityReadRL(authed(identityHandler.Unsubscribe)))
	}

	// Blob storage (encrypted objects) — disabled when BlobQuotaBytes == 0
	if d.Blobs != nil && cfg.BlobQuotaBytes > 0 {
		blobSvc = service.NewBlobService(d.Blobs, d.MasterKey, d.HMACSecret, service.BlobConfig{
			MinBlobSize:     cfg.BlobMinSize,
			MaxBlobSize:     cfg.BlobMaxSize,
			MaxBlobsPerUser: cfg.BlobMaxPerUser,
			QuotaBytes:      cfg.BlobQuotaBytes,
		})
		blobHandler := handler.NewBlobHandler(blobSvc, d.AuditLog, cfg.BlobMinSize, cfg.BlobMaxSize)
		blobUploadRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		blobReadRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 30, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		mux.Handle("POST /user/blobs", blobUploadRL(authed(blobHandler.Upload)))
		mux.Handle("GET /user/blobs", blobReadRL(authed(blobHandler.List)))
		mux.Handle("GET /user/blobs/{id}", blobReadRL(authed(blobHandler.Download)))
		mux.Handle("DELETE /user/blobs/{id}", authMw(fingerprintMw(confirmMw(confirmRL(http.HandlerFunc(blobHandler.Delete))))))
		mux.Handle("PUT /user/blobs/named/{name}", blobUploadRL(authed(blobHandler.UploadNamed)))
		mux.Handle("GET /user/blobs/named/{name}", blobReadRL(authed(blobHandler.DownloadNamed)))
		mux.Handle("DELETE /user/blobs/named/{name}", authMw(fingerprintMw(confirmMw(confirmRL(http.HandlerFunc(blobHandler.DeleteNamed))))))
	}

	// Service-scoped JSON document store. Off by default: unlike blobs this is new
	// surface reachable by every existing client-credentials holder, so enabling it
	// is an explicit operator decision rather than a consequence of upgrading.
	var svcDocSvc *service.ServiceDocumentService
	if d.ServiceDocs != nil && cfg.SvcDocEnabled {
		// A nil *metrics.Collector must reach the service as a nil interface. Passing
		// the typed nil gives a non-nil interface that panics on first use, so a
		// deployment with metrics off would crash on its first document write.
		var svcDocMetrics service.ServiceDocumentMetrics
		if d.Metrics != nil {
			svcDocMetrics = d.Metrics
		}
		svcDocSvc = service.NewServiceDocumentService(
			d.ServiceDocs, d.Clients, d.MasterKey, d.HMACSecret,
			service.ServiceDocumentConfig{
				MaxDocumentBytes:     cfg.SvcDocMaxSize,
				MaxDocsPerSubject:    cfg.SvcDocMaxPerSubject,
				QuotaBytesPerSubject: cfg.SvcDocQuotaBytes,
				SharedEnabled:        cfg.SvcDocSharedEnabled,
			}, svcDocMetrics)
		svcDocHandler := handler.NewServiceDocumentHandler(svcDocSvc, d.AuditLog)

		// Keyed by client, not IP: the caller is one in-cluster pod, so an IP bucket
		// would throttle its whole fleet as a single tenant. Not fail-closed — this
		// releases only what the caller itself wrote, and a cache blip must not take
		// profile reads down across every consuming service.
		//
		// The limiter has to sit INSIDE authMw. ClientRateLimitKey reads the client
		// id out of the request's claims, and claims are put there by authMw, so a
		// limiter mounted outside it saw a nil context every time and silently fell
		// back to the IP bucket this comment exists to avoid. That is the failure
		// mode where the configuration reads correctly and does nothing.
		//
		// An unauthenticated request is therefore rejected by authMw before it
		// reaches this bucket, which is the right order anyway: refusing a bad token
		// is cheap, and what needs bounding is the authenticated work behind it.
		svcDocWriteRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 60, Window: time.Minute, KeyFunc: handler.ClientRateLimitKey,
		}, rlEnabled)
		svcDocReadRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 300, Window: time.Minute, KeyFunc: handler.ClientRateLimitKey,
		}, rlEnabled)
		docWrite := func(h http.HandlerFunc) http.Handler {
			return authMw(svcDocWriteRL(middleware.RequireScope("svcdoc:write")(h)))
		}
		docRead := func(h http.HandlerFunc) http.Handler {
			return authMw(svcDocReadRL(middleware.RequireScope("svcdoc:read")(h)))
		}
		mux.Handle("PUT /service/documents/{subject}/{key}", docWrite(svcDocHandler.Put))
		mux.Handle("GET /service/documents/{subject}/{key}", docRead(svcDocHandler.Get))
		mux.Handle("DELETE /service/documents/{subject}/{key}", docWrite(svcDocHandler.Delete))
		mux.Handle("GET /service/documents/{subject}", docRead(svcDocHandler.List))
	}

	// Data portability (GDPR Articles 15/20) — aggregates all personal data
	// held for the requesting user. Reuses the existing services/repositories.
	dataExportHandler := handler.NewDataExportHandler(d.Users, d.Devices, d.Social, d.AuditEvents, identitySvc, blobSvc, svcDocSvc, d.AuditLog)
	dataExportRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Limit: 5, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
	}, rlEnabled)
	mux.Handle("GET /user/data-export", dataExportRL(authed(dataExportHandler.Export)))

	// Federated identity links. Unlinking is the only way to remove a provider's
	// stored OAuth tokens without erasing the whole account.
	socialHandler := handler.NewSocialHandler(d.Social, d.AuditLog)
	mux.Handle("GET /user/social", authed(socialHandler.List))
	mux.Handle("DELETE /user/social/{id}", authMw(fingerprintMw(confirmRL(http.HandlerFunc(socialHandler.Unlink)))))

	// KMS envelope-unwrap oracle (POST /kms/unwrap) — only mounted when a KMS
	// root key is configured. Requires an authenticated client-credential token
	// carrying the "kms:unwrap" scope; rate limited per-IP as a machine endpoint.
	//
	// This is a key-release oracle: every reachable request unwraps a data-root.
	// Fail closed on a cache outage (like login/register/reset/TOTP) so the per-pod
	// in-memory fallback cannot multiply the effective limit across replicas and
	// widen the release rate under a Redis failure (audit L4).
	//
	// dpopWrap is applied INSIDE authMw+RequireScope so the DPoP middleware sees
	// the resolved client claims. Note what it does NOT buy today: no issuance path
	// populates cnf.jkt, so no token is sender-constrained and the thumbprint
	// comparison never runs. A presented proof is validated against nothing. Replay
	// protection on this oracle therefore rests entirely on the short access-token
	// TTL, TLS, and the fail-closed per-IP rate limit above. Sender-constraint
	// arrives when issuance binds cnf.jkt, not when VAULT_DPOP_ENABLED is set.
	if d.KMS != nil {
		kmsHandler := handler.NewKMSHandler(d.KMS, d.AuditLog)
		kmsUnwrapRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 30, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
		}, rlEnabled)
		mux.Handle("POST /kms/unwrap", kmsUnwrapRL(authMw(middleware.RequireScope("kms:unwrap")(dpopWrap(http.HandlerFunc(kmsHandler.Unwrap))))))
	}

	// Subject-assertion signing oracle (POST /mint). Not mounted at all unless
	// minting is configured: it signs subjects vault42 never authenticated, so a
	// misconfiguration is an authentication bypass rather than a weakened control,
	// and a vanilla vault42 must have no mint. Its own scope, never the KMS one.
	// Fail closed on a cache outage like every other credential-release path.
	if d.Mint != nil {
		mintHandler := handler.NewMintHandler(d.Mint, d.AuditLog)
		mintRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Limit: 60, Window: time.Minute, KeyFunc: handler.ClientRateLimitKey, FailClosed: true,
		}, rlEnabled)
		// Inside authMw for the same reason as the document routes: mintRL is keyed
		// by client and the claims that carry the client id do not exist until
		// authMw has run.
		mux.Handle("POST /mint", authMw(mintRL(middleware.RequireScope(handler.MintScope)(dpopWrap(http.HandlerFunc(mintHandler.Mint))))))
	}

	// Embedded frontend (SPA catch-all) — off by default, enabled via VAULT_SERVE_FRONTEND or honeypot profile
	if cfg.ServeFrontend {
		mux.Handle("/", frontend.Handler())
	}

	return mux
}

// parseCORSOrigins splits a comma-separated CORS_ORIGINS string into a slice.
func parseCORSOrigins(raw string) []string {
	if raw == "" {
		return nil
	}
	var origins []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			origins = append(origins, s)
		}
	}
	return origins
}
