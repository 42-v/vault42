// Package server wires together the HTTP server, TLS configuration, middleware
// chain, and route registration for The Vault. It provides graceful shutdown
// on SIGTERM/SIGINT and configures TLS 1.3 as the minimum version when enabled.
package server

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
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
	"github.com/42-v/vault42/internal/ipintel"
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

	// LoginCountries backs the new-location notice and, because that data is
	// location data about a person, the erasure cascade. The auth service takes it
	// directly from main; erasure needs it here.
	LoginCountries repository.LoginCountryRepository

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

	// IPIntel is the IP-intelligence table used to raise rate-limit scrutiny on
	// VPN/hosting/Tor addresses (never to block them). Nil leaves the auth
	// limiters at their default weight, so the feature is opt-in.
	IPIntel *ipintel.DB

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

// metricsAddrEnv names the address the Prometheus collector binds to, and
// defaultMetricsAddr is where it goes when nothing says otherwise.
//
// Loopback by default because the alternative is worse than the finding this
// closes: a pod-IP-reachable scrape port that no chart change is required to
// expose. An operator who wants Prometheus to reach it sets this to ":9090" and
// fences the port with a NetworkPolicy, which is a decision they make rather
// than one they inherit.
//
// Read from the environment here rather than from config.Config because the
// address is a property of this listener and nothing else consumes it. Promoting
// it to a config field is the tidier home and is left to the config owner.
const (
	metricsAddrEnv     = "VAULT_METRICS_ADDR"
	defaultMetricsAddr = "127.0.0.1:9090"
)

// Server is the main HTTP server for The Vault. It manages the middleware
// chain, route registration, TLS configuration, and graceful shutdown.
type Server struct {
	deps    *Deps
	httpSrv *http.Server
	// metricsSrv serves the Prometheus collector on its own listener. Nil when
	// metrics are disabled or the metrics port could not be bound.
	metricsSrv *http.Server
}

// New creates a new Server with the given dependencies.
func New(deps *Deps) *Server {
	return &Server{deps: deps}
}

// Chain wraps inner in the middleware every request to the API passes through,
// in the order the listener applies it: recovery, request ID, logger, security
// headers, IP access, CORS, app context, client IP, the body cap, and the
// honeypot logger on a honeypot deployment.
//
// Start serves Chain(setupRoutes()), and this is the only place the chain is
// assembled. That matters more than the tidiness: the body cap and its exemption
// list were certified by a suite that built its own middleware.MaxBody with its
// own limit, so exempting every path here left the certification green. Evidence
// that drives this method reads the arguments the deployment actually installs.
func (s *Server) Chain(inner http.Handler) http.Handler {
	cfg := s.deps.Config
	h := inner
	if cfg.Profile == config.ProfileHoneypot && s.deps.HoneypotAlerter != nil {
		h = honeypot.LoggingMiddleware(s.deps.HoneypotAlerter)(h)
	}
	h = middleware.MaxBodyWithExemptions(8*1024, []string{"/user/blobs", "/service/documents"})(h) // 8KB max body; blob uploads and service documents enforce their own limit
	h = middleware.ClientIPContext(h)                                                              // resolve the client address once, for the rate limiter and the per-source lockout
	h = middleware.AppContext(h)                                                                   // resolve X-Vault-App tenant for white-label emails
	h = middleware.CORS(cfg.Origin, parseCORSOrigins(cfg.CORSOrigins), cfg.CORSAllowAll)(h)
	h = middleware.IPAccess()(h)
	h = middleware.SecurityHeaders(cfg.ServeFrontend)(h)
	h = middleware.Logger(h)
	h = middleware.RequestID(h)
	h = middleware.Recovery(h)
	return h
}

// Start applies the process-wide middleware configuration, registers all
// routes, wraps them in [Server.Chain], and starts the HTTP(S) server. It blocks
// until a SIGTERM or SIGINT signal triggers graceful shutdown.
func (s *Server) Start() error {
	mux := s.setupRoutes()
	cfg := s.deps.Config

	// Configure trusted proxies, real IP header, and TLS fingerprint header
	middleware.SetTrustedProxies(cfg.TrustedProxies)
	middleware.SetRealIPHeader(cfg.RealIPHeader)
	middleware.SetTLSFingerprintHeader(cfg.TLSFingerprintHeader)
	middleware.SetIPAccessLists(cfg.IPAllowlist, cfg.IPBlocklist, cfg.GeoAllowlist, cfg.GeoBlocklist, cfg.GeoIPHeader)

	h := s.Chain(mux)

	s.httpSrv = &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: h,
		// The only one of the three servers in this tree without a header
		// deadline of its own. Go falls back to ReadTimeout when this is zero,
		// so a slowloris header trickle got ten seconds per connection instead
		// of five, and gosec G112 flags exactly this shape.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Thirty seconds, matching bridge and admin-gateway.
		//
		// Ten was reachable on the argon2 path under exactly the load where a
		// login failing is worst: acquireArgon2 alone waits up to five seconds
		// before hashing begins, and the hash is another 50-200ms depending on
		// the host. A write deadline shorter than the work the handler is
		// allowed to do turns queueing into 502s.
		WriteTimeout:   30 * time.Second,
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
		if s.metricsSrv != nil {
			_ = s.metricsSrv.Shutdown(ctx)
		}
	}()

	// The API listener is bound before the metrics one, and the order is the
	// control rather than a style choice.
	//
	// A bind failure on the metrics port is deliberately non-fatal, so that
	// losing a scrape never costs the service. Started first, that leniency runs
	// the other way: VAULT_METRICS_ADDR naming the API port — ":8080" is the
	// documented public port and a plausible typo — meant the collector won the
	// race, the API's own bind then failed fatally, and for the width of the
	// crash loop the port the Ingress routes to served an unauthenticated
	// collector instead of the authentication service. Binding the API first
	// makes that same typo cost only the scrape it was always allowed to cost.
	apiLn, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	s.startMetrics(cfg.ListenAddr)

	log.Printf("The Vault listening on %s (profile=%s)", cfg.ListenAddr, cfg.Profile)

	if cfg.TLSEnabled && cfg.TLSCertFile != "" {
		err = s.httpSrv.ServeTLS(apiLn, cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		err = s.httpSrv.Serve(apiLn)
	}

	if errors.Is(err, http.ErrServerClosed) {
		// The drain is in progress, not finished. Wait for it, so that whatever
		// the caller does next happens after the last handler has returned.
		<-drained
		return nil
	}
	return fmt.Errorf("server: %w", err)
}

// startMetrics binds the Prometheus collector to a listener of its own.
//
// A bind failure is logged and nothing else. The metrics port is separate now,
// so something else can hold it, and an authentication service that refuses to
// start because Prometheus's port is busy turns an observability problem into an
// outage. The deployment loses its scrape and keeps serving, which is the right
// way round.
func (s *Server) startMetrics(apiAddr string) {
	if s.deps.Metrics == nil {
		return
	}
	addr := metricsAddr()
	// Named the same as the API, the collector would be publishing on the port
	// the Ingress routes to. Refusing by name as well as by bind failure is what
	// turns a puzzling "address already in use" into a sentence that says which
	// variable is wrong.
	if sameListenAddress(addr, apiAddr) {
		log.Printf("WARNING: metrics listener not started, %s names the API listen address %s; "+
			"set %s to a different port", metricsAddrEnv, apiAddr, metricsAddrEnv)
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("WARNING: metrics listener not started, %s is unavailable: %v", addr, err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", s.deps.Metrics.Handler())
	s.metricsSrv = &http.Server{
		Handler: mux,
		// Five seconds, matching the vault, bridge and admin-gateway listeners.
		// Left unset, Go falls back to ReadTimeout, so a slowloris header trickle
		// got twice as long here as anywhere else — on the one listener of the
		// four that has no authentication in front of it.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("metrics listening on %s", addr)
	// Serve returns ErrServerClosed on the shutdown path and nothing actionable
	// otherwise: the listener is already bound, so the remaining failures are
	// the process going away.
	go func() { _ = s.metricsSrv.Serve(ln) }()
}

// metricsAddr resolves where the collector listens.
// sameListenAddress reports whether two listen addresses would contend for the
// same port. A bare ":9090" and an explicit "0.0.0.0:9090" are the same
// listener, and either collides with a loopback-only bind on that port, so the
// port alone decides — which is conservative in the only direction that matters:
// it refuses a metrics address that might have been fine rather than serving the
// collector where the API belongs.
func sameListenAddress(a, b string) bool {
	_, portA, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	_, portB, err := net.SplitHostPort(b)
	if err != nil {
		return false
	}
	return portA == portB
}

func metricsAddr() string {
	if addr := os.Getenv(metricsAddrEnv); addr != "" {
		return addr
	}
	return defaultMetricsAddr
}

func (s *Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	d := s.deps
	cfg := d.Config

	// Create handlers
	secureCookies := cfg.TLSEnabled || cfg.ForceSecureCookies
	authHandler := handler.NewAuthHandler(d.AuthSvc, d.Users, d.Cache, d.AuditLog, d.Pepper, secureCookies, d.Clients)
	userHandler := handler.NewUserHandler(d.Users, d.Devices, d.Tokens, d.MFASvc)
	passwordHandler := handler.NewPasswordHandler(d.Users, d.PwHistory, d.Tokens, d.EmailSender, d.AuditLog, d.Cache, cfg.Origin, cfg.AppName, d.Pepper, cfg.PasswordMinLength, d.HIBP, d.HIBPEnabled)
	passwordHandler.SetMailer(d.Mailer) // share the white-label mailer (nil is ignored)
	totpHandler := handler.NewTOTPHandler(d.TOTP, d.MasterKey, cfg.Origin, d.Cache, d.AuthSvc, secureCookies)
	// Initialize WebAuthn
	var webauthnHandler *handler.WebAuthnHandler
	wan, err := webauthn.New(webAuthnConfig(cfg))
	if err != nil {
		log.Printf("WebAuthn init failed (endpoints disabled): %v", err)
		webauthnHandler = handler.NewWebAuthnHandler(d.WebAuthn, d.Users, d.Cache, nil, d.AuthSvc, secureCookies)
	} else {
		webauthnHandler = handler.NewWebAuthnHandler(d.WebAuthn, d.Users, d.Cache, wan, d.AuthSvc, secureCookies)
	}
	emailOTPHandler := handler.NewEmailOTPHandler(d.AuthSvc, d.Users, secureCookies)
	backupCodeHandler := handler.NewBackupCodeHandler(d.BackupCodes, d.HMACSecret, d.AuthSvc, secureCookies)
	// Second-factor enrollment, verification and removal, and session
	// revocation, are the moves an account takeover makes. These four handlers
	// shipped without a logger, so every one of them was invisible: an attacker
	// on a stolen session could bind their own authenticator and sign the owner
	// out, and the trail ran straight from the owner's last login to silence.
	// Anything constructed here that can change a factor or end a session owes
	// the trail a row.
	totpHandler.SetAuditLog(d.AuditLog)
	webauthnHandler.SetAuditLog(d.AuditLog)
	backupCodeHandler.SetAuditLog(d.AuditLog)
	userHandler.SetAuditLog(d.AuditLog)
	mfaHandler := handler.NewMFAHandler(d.MFASvc)
	clientHandler := handler.NewClientHandler(d.Clients, d.TokenSvc, d.AuditLog)
	var wellKnownHandler *handler.WellKnownHandler
	if d.KeyStore != nil {
		wellKnownHandler = handler.NewDynamicWellKnownHandler(d.KeyStore.KeyProvider(), cfg.Origin)
	} else {
		wellKnownHandler = handler.NewWellKnownHandler(d.Keys, cfg.Origin)
	}

	// Auth middleware — use dynamic key provider when keystore is active, static map otherwise.
	//
	// WithDPoPScheme is what lets a sender-constrained token be presented the way
	// RFC 9449 §7.1 requires, under the DPoP authorization scheme rather than
	// Bearer. It had no production caller at all, so the scheme was rejected
	// unconditionally and the flag changed nothing; with issuance now binding
	// cnf.jkt, refusing the scheme would make a bound token unusable.
	dpopScheme := middleware.WithDPoPScheme(cfg.DPoPEnabled)
	var authMw, challengeMw func(http.Handler) http.Handler
	if d.KeyStore != nil {
		authMw = middleware.AuthDynamic(d.KeyStore.KeyProvider(), cfg.Origin, cfg.Origin, dpopScheme)
		challengeMw = middleware.AuthChallengeDynamic(d.KeyStore.KeyProvider(), cfg.Origin, cfg.Origin, dpopScheme)
	} else {
		authMw = middleware.Auth(d.Keys, cfg.Origin, cfg.Origin, dpopScheme)
		challengeMw = middleware.AuthChallenge(d.Keys, cfg.Origin, cfg.Origin, dpopScheme)
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

	// Wrap handler with auth + fingerprint.
	//
	// dpopWrap goes INSIDE authMw on every authenticated route, not just on the
	// two oracles. The sender-constraint check reads cnf.jkt off the resolved
	// claims, so a route that skips it accepts a bound token as an ordinary
	// bearer token — and one such route is enough to make the binding decorative,
	// because a stolen token is simply replayed there instead.
	authed := func(h http.HandlerFunc) http.Handler {
		return authMw(fingerprintMw(dpopWrap(h)))
	}
	// 2FA verify endpoints accept challenge tokens (+ DPoP when enabled)
	authedChallenge := func(h http.HandlerFunc) http.Handler {
		return challengeMw(fingerprintMw(dpopWrap(h)))
	}
	// Sensitive endpoints require auth + recent password confirmation
	confirmed := func(h http.HandlerFunc) http.Handler {
		return authMw(fingerprintMw(dpopWrap(confirmMw(h))))
	}
	// liveMw refuses a write whose subject has since been erased. The account
	// state lives in the database and the access token does not carry it, so a
	// token minted before DELETE /user/account keeps working for the rest of its
	// TTL; see middleware.LiveAccount for why that is a write-path concern and
	// not something Auth should be doing on every read.
	liveMw := middleware.LiveAccount(func(ctx context.Context, userID string) (bool, error) {
		// The error is returned beside the verdict rather than branched on:
		// LiveAccount refuses on either, so a lookup that failed and a lookup
		// that found a tombstone reach the same answer by the same path.
		u, err := d.Users.GetByID(ctx, userID)
		return u != nil && !u.Deleted, err
	})
	// authedWrite and confirmedWrite are authed and confirmed with that check in
	// front of the handler. A route that can put personal data back onto a
	// tombstoned row uses these; a read-only route does not pay for the lookup.
	// tests/spec/erasure_write_guard_test.go fails the build when a route that
	// writes personal data is wired with the plain wrapper instead.
	authedWrite := func(h http.HandlerFunc) http.Handler {
		return authMw(fingerprintMw(dpopWrap(liveMw(h))))
	}
	confirmedWrite := func(h http.HandlerFunc) http.Handler {
		return authMw(fingerprintMw(dpopWrap(confirmMw(liveMw(h)))))
	}

	// Rate limiting middleware factories
	rlEnabled := cfg.RateLimitEnabled
	// VPN/hosting/Tor scrutiny: a flagged IP consumes the credential-guessing
	// buckets (login, register, password reset) 3x faster, so those callers meet
	// the ordinary 429 sooner. It never blocks a VPN — that is the whole point of
	// putting it here and not in ipaccess.go. nil when ipintel is not configured,
	// leaving every limiter at its default weight (feature is opt-in).
	vpnScrutiny := middleware.IPIntelWeight(d.IPIntel, 3)
	// Auth-sensitive limiters fail closed on cache outage (audit L4): the per-pod
	// in-memory fallback would multiply the effective limit across replicas.
	loginRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "login", Limit: 5, Window: 15 * time.Minute, KeyFunc: middleware.LoginRateLimitKey, FailClosed: true, Weight: vpnScrutiny,
	}, rlEnabled)
	registerRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "register", Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey, FailClosed: true, Weight: vpnScrutiny,
	}, rlEnabled)
	refreshRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "refresh", Limit: 30, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
	}, rlEnabled)
	passwordResetRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "pwreset", Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey, FailClosed: true, Weight: vpnScrutiny,
	}, rlEnabled)
	totpRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "totp", Limit: 5, Window: 5 * time.Minute, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
	}, rlEnabled)
	verifyEmailRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "verifyemail", Limit: 10, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey,
	}, rlEnabled)
	confirmRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "pwconfirm", Limit: 5, Window: 15 * time.Minute, KeyFunc: middleware.GeneralRateLimitKey,
	}, rlEnabled)
	// FailClosed because this route verifies a client secret with Argon2, which
	// makes it a guessing surface exactly like login. Without it a cache outage
	// drops each pod to its own in-memory counter, so the budget multiplies by
	// the replica count (three by chart default, ten at the HPA ceiling) while
	// the pods stay in rotation, since a degraded cache still reports ready.
	clientTokenRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "clienttoken", Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
	}, rlEnabled)
	// Account erasure is irreversible (recoverable only via the offline key); cap
	// it tightly and fail closed so a cache outage cannot widen the limit.
	accountDeleteRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
		Name: "acctdelete", Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
	}, rlEnabled)

	// ===== Public endpoints (no auth) =====
	mux.HandleFunc("GET /healthz", handler.Healthz)
	mux.HandleFunc("GET /readyz", handler.Readyz(d.ReadyDeps))

	// Prometheus metrics are deliberately NOT mounted here. They live on their
	// own listener (startMetrics), because the mitigation this route used to
	// carry in a comment — "protect with NetworkPolicy in production" — cannot
	// work on a shared listener: a NetworkPolicy selects on namespace, pod and
	// port and has no path awareness, so it cannot admit /auth/login and refuse
	// /metrics through the same port. The counters are process-global document
	// read and write rates, which is a coarse cross-client volume oracle to any
	// in-cluster caller, so the port has to be the boundary.

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
	//
	// dpopWrap for the same reason as the two routes above, and with more riding
	// on it: POST /kms/unwrap and POST /mint are gated on scopes only a
	// client-credentials token can hold, because every user issuance path
	// hardcodes read/write. Left unwrapped, this route made the sender-constraint
	// on both credential-release oracles unreachable — a presented proof was
	// validated as a proof and then compared against an empty cnf.jkt.
	mux.Handle("POST /client/token", clientTokenRL(dpopWrap(http.HandlerFunc(clientHandler.Token))))

	// Well-known
	mux.HandleFunc("GET /.well-known/jwks.json", wellKnownHandler.JWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", wellKnownHandler.OpenIDConfig)

	// OAuth2 (public redirects)
	if len(d.OAuthProviders) > 0 {
		oauthHandler := handler.NewOAuthHandler(d.OAuthProviders, d.HMACSecret, d.Cache, cfg.Origin, d.Users, d.Social, d.Tokens, d.AuthSvc, d.TokenSvc, d.MFASvc, d.AuditLog, secureCookies)
		oauthExchangeRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Name: "oauthexchange", Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		// Authorize writes an unauthenticated per-request oauth_state cache entry;
		// rate-limit it like its siblings to avoid cache-fill eviction pressure
		// on shared lockout/OTP/reset state (audit M2).
		authorizeRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Name: "oauthauthorize", Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		// The callback used to share loginRL with POST /auth/login. That bucket
		// exists to slow credential guessing, and the callback is not a guessing
		// surface: reaching its body already takes an HMAC-valid state, a matching
		// __Host-oauth_state cookie, an unconsumed server-side PKCE verifier and a
		// code the provider will honor. Sharing it meant a caller on a VPN got one
		// login-or-callback per quarter hour across both endpoints (5 per 15
		// minutes, counted at triple weight for a flagged address), and that anyone
		// on the same egress — office, CGNAT pool, VPN exit — could spend the
		// bucket with five garbage login bodies and take social login down for
		// everyone behind it. It is limited like its two siblings instead, which is
		// the budget the rest of the social-login flow already draws on.
		oauthCallbackRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Name: "oauthcallback", Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		mux.Handle("GET /auth/oauth2/authorize", authorizeRL(http.HandlerFunc(oauthHandler.Authorize)))
		mux.Handle("GET /auth/oauth2/callback/{provider}", oauthCallbackRL(http.HandlerFunc(oauthHandler.Callback)))
		mux.Handle("POST /auth/oauth2/exchange", oauthExchangeRL(http.HandlerFunc(oauthHandler.Exchange)))
	}

	// ===== Authenticated endpoints =====
	mux.Handle("POST /auth/logout", authed(authHandler.Logout))
	mux.Handle("POST /auth/confirm", authMw(fingerprintMw(dpopWrap(confirmRL(http.HandlerFunc(authHandler.ConfirmPassword))))))

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
		erasureSvc.SetLoginCountries(d.LoginCountries)
		accountHandler := handler.NewAccountHandler(erasureSvc, d.Users, d.AuditLog, d.Pepper)
		mux.Handle("DELETE /user/account", authMw(fingerprintMw(dpopWrap(accountDeleteRL(http.HandlerFunc(accountHandler.Delete))))))
	}

	// Password change (authenticated, rate limited, already requires current password)
	mux.Handle("POST /user/password", authMw(fingerprintMw(dpopWrap(confirmRL(liveMw(http.HandlerFunc(passwordHandler.ChangePassword)))))))

	// 2FA — Status
	mux.Handle("GET /auth/2fa/status", authed(mfaHandler.Status))

	// 2FA — TOTP (sensitive ops require confirmation)
	mux.Handle("POST /auth/2fa/totp/setup", confirmedWrite(totpHandler.Setup))
	mux.Handle("POST /auth/2fa/totp/verify", totpRL(authedChallenge(totpHandler.Verify)))
	mux.Handle("DELETE /auth/2fa/totp", confirmed(totpHandler.Disable))

	// 2FA — WebAuthn (sensitive ops require confirmation)
	mux.Handle("POST /auth/2fa/webauthn/register/begin", confirmedWrite(webauthnHandler.RegisterBegin))
	mux.Handle("POST /auth/2fa/webauthn/register/finish", confirmedWrite(webauthnHandler.RegisterFinish))
	// The verify pair carries no limiter, unlike its TOTP, backup-code and
	// email-OTP siblings on totpRL, and that asymmetry is deliberate rather than
	// an oversight. Those three cap a guessing budget: a six-digit code falls to
	// 10^6 tries, so the limit is the control that makes the factor worth
	// anything. An assertion is a signature over a server-chosen challenge and has
	// no budget to cap. What is left is one signature check on finish and one
	// cache entry per user that the next begin overwrites rather than adds to,
	// both reached only by a caller already holding a signed challenge or access
	// token.
	//
	// Adding one would cost the owner more than it costs an attacker. A ceremony
	// is two requests, so totpRL's five per five minutes leaves a user two
	// attempts to land a touch, and its key is the IP everyone behind one NAT
	// shares. Any per-IP budget small enough to bound the work here signs a whole
	// office out of its own second factor; any budget loose enough to leave them
	// alone bounds nothing.
	mux.Handle("POST /auth/2fa/webauthn/verify/begin", authedChallenge(webauthnHandler.VerifyBegin))
	mux.Handle("POST /auth/2fa/webauthn/verify/finish", authedChallenge(webauthnHandler.VerifyFinish))
	mux.Handle("GET /auth/2fa/webauthn/credentials", authed(webauthnHandler.ListCredentials))
	mux.Handle("DELETE /auth/2fa/webauthn/credentials/{id}", confirmed(webauthnHandler.DeleteCredential))

	// 2FA — Backup codes (sensitive)
	mux.Handle("POST /auth/2fa/backup-codes", confirmedWrite(backupCodeHandler.Generate))
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
			Name: "identityread", Limit: 30, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		identityWriteRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Name: "identitywrite", Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		mux.Handle("GET /user/identity", identityReadRL(authed(identityHandler.Get)))
		mux.Handle("PUT /user/identity", identityWriteRL(authedWrite(identityHandler.Put)))
		mux.Handle("DELETE /user/identity", authMw(fingerprintMw(dpopWrap(confirmMw(confirmRL(http.HandlerFunc(identityHandler.Delete)))))))
		// Withdrawal must be no harder than granting (Art. 7(3)), so this carries
		// the read rate limit and no confirmation step — unlike identity deletion.
		mux.Handle("POST /user/marketing/unsubscribe", identityReadRL(authedWrite(identityHandler.Unsubscribe)))
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
			Name: "blobupload", Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		blobReadRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Name: "blobread", Limit: 30, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
		}, rlEnabled)
		mux.Handle("POST /user/blobs", blobUploadRL(authedWrite(blobHandler.Upload)))
		mux.Handle("GET /user/blobs", blobReadRL(authed(blobHandler.List)))
		mux.Handle("GET /user/blobs/{id}", blobReadRL(authed(blobHandler.Download)))
		mux.Handle("DELETE /user/blobs/{id}", authMw(fingerprintMw(dpopWrap(confirmMw(confirmRL(http.HandlerFunc(blobHandler.Delete)))))))
		mux.Handle("PUT /user/blobs/named/{name}", blobUploadRL(authedWrite(blobHandler.UploadNamed)))
		mux.Handle("GET /user/blobs/named/{name}", blobReadRL(authed(blobHandler.DownloadNamed)))
		mux.Handle("DELETE /user/blobs/named/{name}", authMw(fingerprintMw(dpopWrap(confirmMw(confirmRL(http.HandlerFunc(blobHandler.DeleteNamed)))))))
	}

	// Service-scoped JSON document store. Off by default: unlike blobs this is new
	// surface reachable by every existing client-credentials holder, so enabling it
	// is an explicit operator decision rather than a consequence of upgrading.
	var svcDocSvc *service.DocumentService
	if d.ServiceDocs != nil && cfg.SvcDocEnabled {
		// A nil *metrics.Collector must reach the service as a nil interface. Passing
		// the typed nil gives a non-nil interface that panics on first use, so a
		// deployment with metrics off would crash on its first document write.
		var svcDocMetrics service.DocumentMetrics
		if d.Metrics != nil {
			svcDocMetrics = d.Metrics
		}
		svcDocSvc = service.NewDocumentService(
			d.ServiceDocs, d.Clients, d.MasterKey, d.HMACSecret,
			service.DocumentConfig{
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
			Name: "svcdocwrite", Limit: 60, Window: time.Minute, KeyFunc: handler.ClientRateLimitKey,
		}, rlEnabled)
		svcDocReadRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Name: "svcdocread", Limit: 300, Window: time.Minute, KeyFunc: handler.ClientRateLimitKey,
		}, rlEnabled)
		docWrite := func(h http.HandlerFunc) http.Handler {
			return authMw(svcDocWriteRL(middleware.RequireScope("svcdoc:write")(dpopWrap(h))))
		}
		docRead := func(h http.HandlerFunc) http.Handler {
			return authMw(svcDocReadRL(middleware.RequireScope("svcdoc:read")(dpopWrap(h))))
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
		Name: "dataexport", Limit: 5, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
	}, rlEnabled)
	mux.Handle("GET /user/data-export", dataExportRL(authed(dataExportHandler.Export)))

	// Federated identity links. Unlinking is the only way to remove a provider's
	// stored OAuth tokens without erasing the whole account.
	socialHandler := handler.NewSocialHandler(d.Social, d.AuditLog)
	mux.Handle("GET /user/social", authed(socialHandler.List))
	mux.Handle("DELETE /user/social/{id}", authMw(fingerprintMw(dpopWrap(confirmRL(http.HandlerFunc(socialHandler.Unlink))))))

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
	// the resolved client claims. What that buys depends on the token presented:
	// a client-credentials token minted at POST /client/token with a proof carries
	// cnf.jkt, and the thumbprint comparison in middleware.DPoP then refuses it to
	// anyone who cannot prove the same key. A token minted without a proof stays an
	// ordinary bearer token, so replay protection for that caller still rests on
	// the short access-token TTL, TLS, and the fail-closed per-IP rate limit above.
	// Which of the two a deployment gets is decided at issuance, not here.
	if d.KMS != nil {
		kmsHandler := handler.NewKMSHandler(d.KMS, d.AuditLog)
		kmsUnwrapRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Name: "kmsunwrap", Limit: 30, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
		}, rlEnabled)
		// Inside authMw, but not for the reason mint and svcDoc are: those two
		// have no choice, because ClientRateLimitKey reads a client id from
		// claims that do not exist until auth has run. This limiter is IP-keyed
		// and would work in either position. It sits inside because it is
		// FailClosed, and a fail-closed bucket in front of authentication is a
		// denial-of-service primitive: an unauthenticated flood from one egress
		// address exhausts the budget, and the legitimate machine client behind
		// the same NAT is then refused the key-release path outright. That is the
		// same defect shape as the DPoP replay entry written for tokens it could
		// not protect. Refusing a bad token is cheap; what needs bounding is the
		// authenticated key-release work behind it.
		mux.Handle("POST /kms/unwrap", authMw(kmsUnwrapRL(middleware.RequireScope("kms:unwrap")(dpopWrap(http.HandlerFunc(kmsHandler.Unwrap))))))
	}

	// Subject-assertion signing oracle (POST /mint). Not mounted at all unless
	// minting is configured: it signs subjects vault42 never authenticated, so a
	// misconfiguration is an authentication bypass rather than a weakened control,
	// and a vanilla vault42 must have no mint. Its own scope, never the KMS one.
	// Fail closed on a cache outage like every other credential-release path.
	if d.Mint != nil {
		mintHandler := handler.NewMintHandler(d.Mint, d.AuditLog)
		mintRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
			Name: "mint", Limit: 60, Window: time.Minute, KeyFunc: handler.ClientRateLimitKey, FailClosed: true,
		}, rlEnabled)
		// Inside authMw for the same reason as the document routes: mintRL is keyed
		// by client and the claims that carry the client id do not exist until
		// authMw has run.
		//
		// The scope gate audits its refusals. A request refused here never
		// reaches MintHandler.Mint, so the handler's own audit call cannot see
		// it, and probing the delegated-signing endpoint with a stolen non-mint
		// client token produced no record at all. Both halves of a refused mint
		// score the same because the score is a property of token_minted now,
		// not of the branch that wrote the row.
		mintRefusal := middleware.WithScopeRefusalAudit(d.AuditLog, audit.TokenMinted)
		mux.Handle("POST /mint", authMw(mintRL(middleware.RequireScope(handler.MintScope, mintRefusal)(dpopWrap(http.HandlerFunc(mintHandler.Mint))))))
	}

	// Embedded frontend (SPA catch-all) — off by default, enabled via VAULT_SERVE_FRONTEND or honeypot profile
	if cfg.ServeFrontend {
		mux.Handle("/", frontend.Handler())
	}

	return mux
}

// webAuthnConfig is the relying-party configuration both WebAuthn ceremonies
// run under.
//
// Timeouts are set because go-webauthn only stamps SessionData.Expires when
// Enforce is true, and only compares it when it is non-zero. Left at the
// library default both halves are skipped: the timeout handed to the browser is
// advisory, the server keeps none of its own, and the only thing retiring a
// challenge is the TTL on the cache entry holding it. That is a live control
// today, so this closes no hole by itself; what it buys is a second, independent
// deadline, so a cache backend that outlives its own TTL cannot quietly extend
// how long a challenge stays answerable.
//
// Both durations are handler.WebAuthnCeremonyTTL, the lifetime of that cache
// entry, so the two deadlines cannot disagree. TimeoutUVD carries the same value
// as Timeout rather than the library's shorter default: it is the branch taken
// when user verification is discouraged, and a ceremony window that changes with
// the verification requirement would put the cache entry and the enforced
// deadline back out of step.
func webAuthnConfig(cfg *config.Config) *webauthn.Config {
	ceremony := webauthn.TimeoutConfig{
		Enforce:    true,
		Timeout:    handler.WebAuthnCeremonyTTL,
		TimeoutUVD: handler.WebAuthnCeremonyTTL,
	}
	return &webauthn.Config{
		RPDisplayName: cfg.AppName,
		RPID:          cfg.RPHost(),
		RPOrigins:     []string{cfg.Origin},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        ceremony,
			Registration: ceremony,
		},
	}
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
