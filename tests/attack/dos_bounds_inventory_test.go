package attack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The inventory this file replaced pinned the ABSENCE of every bound the
// resource-exhaustion review found missing: it failed if postgres.New gained a
// statement_timeout, if the vault server gained a ReadHeaderTimeout, if the
// memory cache gained an entry cap. Kept as written it would have failed the
// moment any of them were fixed, and — worse — it made the defects load-bearing:
// removing one broke the build, so the test argued for keeping them.
//
// This is the same idea pointed the other way. Each entry names a bound that
// now exists and must keep existing. A source-text assertion is coarse, so
// every one of them is paired with a behavioral test elsewhere in this package
// or beside the code; what this catches is a silent deletion during a refactor,
// which is exactly how the numbers in the argon2 comment went stale once
// already.

func dosRead(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestDoS_SourceContracts(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		file string
		want string
		why  string
	}{
		{
			"internal/repository/postgres/db.go", `"statement_timeout"`,
			"without a server-side ceiling, MaxConns pathological queries pin the whole pool " +
				"until MaxConnLifetime and the service stops serving with no error anywhere",
		},
		{
			"internal/repository/postgres/db.go", `"lock_timeout"`,
			"a statement queued behind somebody else's lock has to give up on its own",
		},
		{
			"internal/repository/postgres/db.go", "MaxConnLifetimeJitter",
			"without jitter every connection opened at startup expires at the same instant and " +
				"the pool reconnects in lockstep once an hour, forever",
		},
		{
			"internal/server/server.go", "ReadHeaderTimeout:",
			"the only one of the three servers in the tree without a header deadline; gosec G112",
		},
		{
			"internal/server/server.go", "MaxHeaderBytes: 1 << 20",
			"the 1 MiB header cap the XFF hop cap is sized against",
		},
		{
			"internal/server/server.go", "MaxBodyWithExemptions(8*1024",
			"the global 8 KiB body cap",
		},
		{
			"internal/middleware/ratelimit.go", "maxXFFHops",
			"an uncapped hop walk is bounded by MaxHeaderBytes rather than by a hop count: " +
				"~70k ParseIP calls per request",
		},
		{
			"internal/middleware/ratelimit.go", "localRLMaxEntries",
			"the in-memory fallback is reached during a cache outage and keyed by client IP, " +
				"so a v6 flood OOMs the pod during the outage it exists to survive",
		},
		{
			"internal/middleware/ratelimit.go", `r.Header.Values("X-Forwarded-For")`,
			"Header.Get reads the first field line only, so a proxy that appends its own line " +
				"is defeated by leftmost trust",
		},
		{
			"internal/cache/memory.go", "memoryMaxEntries",
			"every key in this cache is attacker-chosen in practice",
		},
		{
			"internal/cache/postgres.go", "pgSweepBatch      = 2000",
			"the postgres cache reaper's batch bound",
		},
		{
			"internal/cache/postgres.go", "pgSweepMaxBatches = 20",
			"the postgres cache reaper's per-tick ceiling",
		},
		{
			"internal/crypto/argon2.go", "argon2MaxConcurrent = 4",
			"four slots is the memory ceiling the 184 MiB / 256 MiB budget is computed from",
		},
		{
			"internal/crypto/argon2.go", "argon2MaxQueueDepth",
			"the semaphore bounds memory; this bounds the time a caller spends queued for it",
		},
		{
			"internal/crypto/argon2.go", "argon2MaxVerifyMemory = 64 * 1024",
			"the verify ceiling the worst-case peak is computed from",
		},
		{
			"internal/service/auth.go", "distributedLockoutThreshold",
			"the account-wide lock a single source cannot reach; keying the hard lock on the " +
				"source is what stopped five requests denying any account",
		},
		{
			"internal/service/auth.go", "loginThrottleMax",
			"the ceiling on the progressive delay; an unbounded delay is the hard lock again",
		},
		{
			"internal/service/hibp.go", "hibpMaxConcurrent",
			"register is fail-open on HIBP error, so the check had no bound on outbound sockets",
		},
		{
			"internal/repository/postgres/refresh_token.go", "refreshReapBatch",
			"the reaper's DELETE had no LIMIT and nothing on the server path ever ran it",
		},
		{
			"internal/audit/retention.go", "SweepMaxBatches",
			"the purge disables the append-only trigger, which is ACCESS EXCLUSIVE; unbatched " +
				"it blocks every audit insert for the length of the whole purge",
		},
		{
			"migrations/030_audit_retention_batched.sql", "max_rows INTEGER",
			"the batched cleanup function the sweeper loops over",
		},
		{
			"internal/deferwork/deferwork.go", "DefaultQueueDepth",
			"four unauthenticated call sites used to spawn one goroutine and one relay " +
				"connection per request, invisible to shutdown",
		},
		{
			"cmd/bridge/detection.go", "maxSamplesPerIP",
			"one source at 10k req/s held 600k timestamps behind the mutex every request takes",
		},
		{
			"cmd/bridge/detection.go", "maxTrackedIPs",
			"every per-source map here is keyed by an address the caller chooses",
		},
		{
			"cmd/bridge/proxy.go", "MaxBytesReader",
			"the proxy streamed whatever the client sent into an upstream connection it " +
				"opened concurrently",
		},
		{
			"cmd/bridge/proxy.go", "MaxConnsPerHost",
			"http.DefaultTransport sets neither a connection cap nor a response-header deadline",
		},
		{
			"cmd/bridge/proxy.go", "ResponseHeaderTimeout",
			"a silent upstream held a goroutine and a socket per in-flight request",
		},
		{
			"cmd/bridge/proxy.go", "defaultStrippedHeaders",
			"the bridge is the gateway the vault's trust model assumes; it must be the sole " +
				"author of anything the upstream trusts by peer identity",
		},
		{
			"cmd/bridge/proxy.go", "webhookWorkers = 8",
			"the webhook pool bound the deferred-work queue is modeled on",
		},
		{
			"cmd/bridge/decoy.go", "maxReasonPathLen",
			"a 1 MB request line became a 1 MB flag reason held for 24h and a 1 MB webhook body",
		},
		{
			"internal/adminapi/handler.go", "var uuidPattern = regexp.MustCompile",
			"compiled once at init rather than per admin search",
		},
	} {
		t.Run(filepath.Base(c.file)+": "+c.want, func(t *testing.T) {
			if !strings.Contains(dosRead(t, c.file), c.want) {
				t.Errorf("%s no longer contains %q.\n\nWhy it is there: %s", c.file, c.want, c.why)
			}
		})
	}
}

// TestDoS_RefreshTokenReaperIsOnTheServerPath pins the wiring, not just the
// batch size. The reaper existed and worked; the only production caller was a
// CLI subcommand, so the table grew until an operator remembered to run it.
func TestDoS_RefreshTokenReaperIsOnTheServerPath(t *testing.T) {
	t.Parallel()

	mainSrc := dosRead(t, "cmd/vault/main.go")
	if !strings.Contains(mainSrc, "NewRefreshTokenRetention") {
		t.Error("cmd/vault no longer starts a refresh-token sweeper; the only reaper for spent " +
			"refresh rows is a CLI subcommand again")
	}
	if !strings.Contains(dosRead(t, "internal/cli/cli.go"), "tokens.DeleteExpired") {
		t.Error("the CLI reaper is gone as well")
	}
}

// TestDoS_MailDrainRunsBeforeTheCacheCloses pins the shutdown ORDER, which is
// the half of the deferred-work fix that a refactor can silently undo. Defers run
// last-in-first-out, so the drain has to be registered AFTER the cache close to
// run before it: a deferred verification send writes its token to the cache and
// then mails the link, and a closed cache turns that into a link that never
// works.
func TestDoS_MailDrainRunsBeforeTheCacheCloses(t *testing.T) {
	t.Parallel()

	src := dosRead(t, "cmd/vault/main.go")
	cacheClose := strings.Index(src, "appCache.Close()")
	mailDrain := strings.Index(src, "deferwork.Close(")
	if cacheClose < 0 {
		t.Fatal("cmd/vault no longer closes the cache")
	}
	if mailDrain < 0 {
		t.Fatal("cmd/vault no longer drains the deferred mail pool on shutdown")
	}
	if mailDrain < cacheClose {
		t.Error("the mail drain is deferred BEFORE the cache close, so LIFO runs it after: an " +
			"in-flight verification send can write its token to a cache that is already gone")
	}
}
