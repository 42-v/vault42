package multireplica_test

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/email"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/redis"
	pgrepo "github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/server"
	"github.com/42-v/vault42/internal/service"
)

// skipIfNoContainerRuntime skips if env flags set.
func skipIfNoContainerRuntime(t *testing.T) {
	t.Helper()
	if os.Getenv("SKIP_E2E") == "1" || os.Getenv("SKIP_INTEGRATION") == "1" {
		t.Skip("SKIP_E2E or SKIP_INTEGRATION set")
	}
}

// probeContainerRuntime probes DOCKER_HOST and does a quick docker availability check
// (testcontainers-go start will further skip if unreachable).
func probeContainerRuntime(t *testing.T) {
	t.Helper()
	skipIfNoContainerRuntime(t)
	if dh := os.Getenv("DOCKER_HOST"); dh != "" {
		return
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("no container runtime reachable (no docker in PATH and DOCKER_HOST unset): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	if err := cmd.Run(); err != nil {
		t.Skipf("no container runtime reachable (docker probe failed): %v", err)
	}
}

// findMigrationsDir walks up from the test's working directory to locate the
// repo's migrations/ dir, so the suite works regardless of its package depth.
func findMigrationsDir() string {
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "migrations" // fall back; ReadDir will surface a clear error
}

// setupContainers starts ONE postgres + ONE redis. Reads the repo migrations/*.sql sorted and applies full
// (grants included so vault_app can connect). Prepares vault_app DSN for replicas.
func setupContainers(t *testing.T) (pool *pgxpool.Pool, redisAddr, appDSN string, cleanup func()) {
	t.Helper()
	probeContainerRuntime(t)

	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("vault_test"),
		tcpostgres.WithUsername("vault_test"),
		tcpostgres.WithPassword("vault_test"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(120*time.Second),
				wait.ForListeningPort("5432/tcp").
					WithStartupTimeout(120*time.Second),
			),
		),
	)
	if err != nil {
		t.Skipf("no container runtime reachable (postgres): %v", err)
		return nil, "", "", nil
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("postgres connstr: %v", err)
	}

	migConn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("mig connect: %v", err)
	}

	migDir := findMigrationsDir()
	entries, err := os.ReadDir(migDir)
	if err != nil {
		migConn.Close(ctx)
		pgContainer.Terminate(ctx)
		t.Fatalf("read migrations: %v", err)
	}
	var migFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			migFiles = append(migFiles, e.Name())
		}
	}
	sort.Strings(migFiles)
	for _, f := range migFiles {
		sqlBytes, err := os.ReadFile(filepath.Join(migDir, f))
		if err != nil {
			migConn.Close(ctx)
			pgContainer.Terminate(ctx)
			t.Fatalf("read mig %s: %v", f, err)
		}
		// Apply raw SQL (including GRANTs to vault_app) so that replicas using
		// the vault_app DSN can access tables. (strip is only for direct test-user
		// connections in other integration suites.)
		sqlStr := string(sqlBytes)
		if _, err := migConn.Exec(ctx, sqlStr); err != nil {
			if !strings.Contains(err.Error(), "already exists") && !strings.Contains(err.Error(), "duplicate key") {
				migConn.Close(ctx)
				pgContainer.Terminate(ctx)
				t.Fatalf("apply mig %s: %v", f, err)
			}
		}
	}

	_, _ = migConn.Exec(ctx, `ALTER ROLE vault_app WITH PASSWORD 'apppass'`)
	_, _ = migConn.Exec(ctx, `ALTER ROLE vault_mig WITH PASSWORD 'migpass'`)

	poolCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		migConn.Close(ctx)
		pgContainer.Terminate(ctx)
		t.Fatalf("pool cfg: %v", err)
	}
	poolCfg.MaxConns = 10
	pool, err = pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		migConn.Close(ctx)
		pgContainer.Terminate(ctx)
		t.Fatalf("pool: %v", err)
	}

	redisContainer, err := testcontainers.Run(ctx,
		"redis:7-alpine",
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("Ready to accept connections").WithStartupTimeout(60*time.Second),
				wait.ForListeningPort("6379/tcp").WithStartupTimeout(60*time.Second),
			),
		),
	)
	if err != nil {
		pool.Close()
		migConn.Close(ctx)
		pgContainer.Terminate(ctx)
		t.Skipf("no container runtime reachable (redis): %v", err)
		return nil, "", "", nil
	}
	rhost, err := redisContainer.Endpoint(ctx, "")
	if err != nil {
		redisContainer.Terminate(ctx)
		pool.Close()
		migConn.Close(ctx)
		pgContainer.Terminate(ctx)
		t.Fatalf("redis endpoint: %v", err)
	}
	redisAddr = rhost

	cleanup = func() {
		migConn.Close(ctx)
		pool.Close()
		redisContainer.Terminate(ctx)
		pgContainer.Terminate(ctx)
	}

	appDSN = strings.Replace(connStr, "vault_test:vault_test@", "vault_app:apppass@", 1)
	return pool, redisAddr, appDSN, cleanup
}

// capturingEmailSender records codes and tokens.
type capturingEmailSender struct {
	mu         sync.Mutex
	lastCode   map[string]string
	lastTokens map[string]map[string]string
}

func newCapturingEmailSender() *capturingEmailSender {
	return &capturingEmailSender{
		lastCode:   make(map[string]string),
		lastTokens: make(map[string]map[string]string),
	}
}

func (c *capturingEmailSender) Send(ctx context.Context, _ email.Address, to, subject, htmlBody, textBody string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	body := textBody
	if body == "" {
		body = htmlBody
	}
	if m := regexp.MustCompile(`\b(\d{6})\b`).FindStringSubmatch(body); len(m) > 1 {
		c.lastCode[to] = m[1]
	}
	if c.lastTokens[to] == nil {
		c.lastTokens[to] = make(map[string]string)
	}
	if m := regexp.MustCompile(`verify-email\?token=([A-Za-z0-9._-]+)`).FindStringSubmatch(body); len(m) > 1 {
		c.lastTokens[to]["verify"] = m[1]
	}
	if strings.Contains(strings.ToLower(subject), "reset") {
		if m := regexp.MustCompile(`token=([A-Za-z0-9._-]+)`).FindStringSubmatch(body); len(m) > 1 {
			c.lastTokens[to]["reset"] = m[1]
		}
	}
	return nil
}

func (c *capturingEmailSender) getOTP(email string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastCode[email]
}

func (c *capturingEmailSender) getVerifyToken(email string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := c.lastTokens[email]; t != nil {
		return t["verify"]
	}
	return ""
}

func (c *capturingEmailSender) getResetToken(email string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := c.lastTokens[email]; t != nil {
		return t["reset"]
	}
	return ""
}

// testReplica is in-process server replica.
type testReplica struct {
	URL     string
	email   *capturingEmailSender
	ks      *keystore.KeyStore
	cache   cache.Cache
	closeFn func()
}

// startReplica constructs replica using same pattern as internal/server + cmd wiring for full fidelity.
// sharedMasterKey is fixed (32 bytes) so BOTH replicas decrypt the same
// at-rest-encrypted signing keys from the shared DB — a real multi-replica
// deployment shares MASTER_KEY/HMAC_SECRET/pepper across instances.
var sharedMasterKey = []byte("multireplica-shared-master-key!!")

func startReplica(t *testing.T, port int, redisAddr, connectDSN, cacheBackend, prof string) *testReplica {
	t.Helper()

	masterKey := sharedMasterKey

	cfg := &config.Config{
		Profile:             config.Profile(prof),
		ListenAddr:          fmt.Sprintf("127.0.0.1:%d", port),
		Origin:              "http://127.0.0.1",
		TLSEnabled:          false,
		DBHost:              "127.0.0.1",
		DBPort:              "5432",
		DBName:              "vault_test",
		DBSSLMode:           "disable",
		DBMaxConns:          8,
		DBMigPassword:       "migpass",
		DBAppPassword:       "apppass",
		MasterKey:           masterKey,
		Pepper:              "test-pepper-value-for-e2e-multireplica",
		HMACSecret:          []byte("test-hmac-secret-32-bytes-multireplica-test!!"),
		CacheBackend:        cacheBackend,
		RedisAddr:           redisAddr,
		AccessTokenTTL:      5 * time.Minute,
		RefreshTokenTTL:     1 * time.Hour,
		RememberMeTTL:       1 * time.Hour,
		RateLimitEnabled:    true,
		PasswordMinLength:   15,
		HIBPCheck:           false,
		MFARequired:         true,
		RegistrationEnabled: true,
		MaxSessionsPerUser:  5,
		AppName:             "MultiReplicaVaultTest",
		AutoMigrate:         false,
		ShutdownTimeout:     2 * time.Second,
		KeyRotationDB:       true,
		KeyRetentionPeriod:  time.Hour,
		KeyRefreshInterval:  500 * time.Millisecond,
		ForceSecureCookies:  false,
	}

	db, err := pgrepo.New(context.Background(), connectDSN, cfg.DBMaxConns)
	if err != nil {
		t.Fatalf("postgres.New: %v", err)
	}

	appCache, err := cache.NewCache(cfg.CacheBackend, cfg.RedisAddr, "", db.Pool)
	if err != nil {
		db.Close()
		t.Fatalf("NewCache(%s): %v", cfg.CacheBackend, err)
	}

	userRepo := pgrepo.NewUserRepo(db)
	refreshRepo := pgrepo.NewRefreshTokenRepo(db)
	deviceRepo := pgrepo.NewDeviceRepo(db)
	clientRepo := pgrepo.NewClientRepo(db)
	auditRepo := pgrepo.NewAuditRepo(db)
	totpRepo := pgrepo.NewTOTPRepo(db)
	webauthnRepo := pgrepo.NewWebAuthnRepo(db)
	backupRepo := pgrepo.NewBackupCodeRepo(db)
	pwHistRepo := pgrepo.NewPasswordHistoryRepo(db)
	socialRepo := pgrepo.NewSocialAccountRepo(db)
	identRepo := pgrepo.NewIdentityRepo(db)
	blobRepo := pgrepo.NewBlobRepo(db)
	rateRepo := pgrepo.NewRateLimitRepo(db)

	auditLog := audit.NewLoggerWithBufferSize(auditRepo, 0, 0)

	ks, err := keystore.New(db.Pool, cfg.MasterKey, cfg.KeyRetentionPeriod)
	if err != nil {
		appCache.Close()
		db.Close()
		t.Fatalf("keystore.New: %v", err)
	}
	if err := ks.EnsureKey(context.Background(), nil); err != nil {
		ks.Stop()
		appCache.Close()
		db.Close()
		t.Fatalf("EnsureKey: %v", err)
	}
	activeKey, kid := ks.ActiveKey()

	tokenSvc := service.NewTokenService(
		activeKey, kid, cfg.Origin, cfg.Origin,
		cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.RememberMeTTL,
	)
	mfaSvc := service.NewMFAService(totpRepo, webauthnRepo, backupRepo, cfg.MFARequired)
	capEmail := newCapturingEmailSender()
	hibp := service.NewHIBPClient()

	authSvc := service.NewAuthService(
		userRepo, refreshRepo, deviceRepo, pwHistRepo,
		tokenSvc, mfaSvc, auditLog, hibp,
		appCache, capEmail, cfg.Origin, cfg.AppName, cfg.Pepper,
		cfg.PasswordMinLength, cfg.HIBPCheck, cfg.HMACSecret,
	)
	authSvc.SetRateLimitRepo(rateRepo)
	authSvc.SetMaxSessionsPerUser(cfg.MaxSessionsPerUser)

	ks.SetOnKeyChange(func(k *rsa.PrivateKey, newKid string, all map[string]*rsa.PublicKey) {
		tokenSvc.UpdateSigningKey(k, newKid)
	})
	ks.StartRefreshLoop(context.Background(), cfg.KeyRefreshInterval)

	readyDeps := &handler.ReadyzDeps{
		PingDB: func() error {
			c, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			return db.Pool.Ping(c)
		},
	}

	pubKeys := ks.AllPublicKeys()
	deps := &server.Deps{
		Config:         cfg,
		AuthSvc:        authSvc,
		TokenSvc:       tokenSvc,
		MFASvc:         mfaSvc,
		Keys:           pubKeys,
		Cache:          appCache,
		AuditLog:       auditLog,
		Users:          userRepo,
		Devices:        deviceRepo,
		Tokens:         refreshRepo,
		Clients:        clientRepo,
		TOTP:           totpRepo,
		WebAuthn:       webauthnRepo,
		BackupCodes:    backupRepo,
		PwHistory:      pwHistRepo,
		Social:         socialRepo,
		EmailSender:    capEmail,
		OAuthProviders: map[string]oauth2.Provider{},
		MasterKey:      cfg.MasterKey,
		HMACSecret:     cfg.HMACSecret,
		Pepper:         cfg.Pepper,
		HIBP:           hibp,
		HIBPEnabled:    false,
		ReadyDeps:      readyDeps,
		KeyStore:       ks,
		Identity:       identRepo,
		Blobs:          blobRepo,
	}

	srv := server.New(deps)
	go func() { _ = srv.Start() }()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForReady(t, base)

	return &testReplica{
		URL:   base,
		email: capEmail,
		ks:    ks,
		cache: appCache,
		closeFn: func() {
			ks.Stop()
			appCache.Close()
			db.Close()
		},
	}
}

// waitForReady polls until /healthz 200.
func waitForReady(t *testing.T, base string) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for i := 0; i < 200; i++ {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("replica at %s never became ready", base)
}

// cleanupState clears user data and redis keys.
func cleanupState(t *testing.T, pool *pgxpool.Pool, rclient *redis.Client) {
	t.Helper()
	ctx := context.Background()
	if pool != nil {
		qs := []string{
			"DELETE FROM auth.refresh_tokens",
			"DELETE FROM auth.devices",
			"DELETE FROM auth.password_history",
			"DELETE FROM auth.totp_secrets",
			"DELETE FROM auth.webauthn_credentials",
			"DELETE FROM auth.backup_codes",
			"DELETE FROM auth.social_accounts",
			"DELETE FROM auth.users",
			"DELETE FROM audit.audit_log",
			"DELETE FROM auth.rate_limits",
		}
		for _, q := range qs {
			_, _ = pool.Exec(ctx, q)
		}
	}
	if rclient != nil {
		_, _ = rclient.Eval(ctx, `return redis.call('FLUSHDB')`, 0)
	}
}

// uniqueEmail .
var emailCounter int64

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%d-%d@test.vault.local", prefix, time.Now().UnixNano(), atomic.AddInt64(&emailCounter, 1))
}

// registerAndVerify registers on repl, forces email_verified via pool (bypassing email), for test flows.
func registerAndVerify(t *testing.T, pool *pgxpool.Pool, client *http.Client, repl *testReplica, email string) {
	t.Helper()
	st, body := jsonPost(t, client, repl.URL+"/auth/register", map[string]string{
		"email": email, "password": testPassword, "display_name": "U",
	})
	if st == 429 {
		t.Skip("rate limited on register")
		t.SkipNow()
	}
	if st != 200 && st != 201 {
		t.Fatalf("register on %s: %d %v", repl.URL, st, body)
	}
	if pool != nil {
		_, _ = pool.Exec(context.Background(), "UPDATE auth.users SET email_verified=TRUE WHERE email=$1", email)
	}
}

// startReplicasForTest starts A at basePort, B at basePort+1 sharing DSN/redis/cache/prof.
func startReplicasForTest(t *testing.T, basePort int, redisAddr, appDSN, cacheBackend, prof string) (a, b *testReplica, closeAll func()) {
	t.Helper()
	a = startReplica(t, basePort, redisAddr, appDSN, cacheBackend, prof)
	b = startReplica(t, basePort+1, redisAddr, appDSN, cacheBackend, prof)
	closeAll = func() {
		if a != nil {
			a.closeFn()
		}
		if b != nil {
			b.closeFn()
		}
	}
	return a, b, closeAll
}

const testPassword = "MultiReplicaSecure!P4ssw0rd-15chars"
