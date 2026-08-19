package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/repository/postgres"
)

// The server-side ceilings are sent in the STARTUP PACKET, as pgx
// RuntimeParams, so every connection the pool opens carries them without a
// round trip. That placement is what makes them cover the background sweepers
// as well as the request path — and it is also what makes a bad parameter name
// or a badly formatted value fatal rather than cosmetic: PostgreSQL rejects the
// whole connection, so the vault does not start at all.
//
// No unit test can see that. poolConfig only proves what this process put in
// the map; whether the server accepts it is a property of the server. The one
// container test that reaches postgres.New goes through the two-argument form,
// which leaves both configurable timeouts at zero, so before this the only
// startup parameter ever exercised against a real server was
// idle_in_transaction_session_timeout.

func TestPoolStartupTimeoutsAreAcceptedByTheServer(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	ctx := context.Background()
	connStr := pool.Config().ConnString()

	db, err := postgres.NewWithOptions(ctx, connStr, postgres.Options{
		MaxConns:         3,
		StatementTimeout: 7 * time.Second,
		LockTimeout:      2500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v\n\nA rejected startup parameter fails the connection, "+
			"which means the service does not boot", err)
	}
	defer db.Close()

	for _, tc := range []struct{ setting, want string }{
		{"statement_timeout", "7s"},
		{"lock_timeout", "2500ms"},
		{"idle_in_transaction_session_timeout", "30s"},
	} {
		var got string
		if err := db.Pool.QueryRow(ctx, "SHOW "+tc.setting).Scan(&got); err != nil {
			t.Fatalf("SHOW %s: %v", tc.setting, err)
		}
		if got != tc.want {
			t.Errorf("%s = %q, want %q — the ceiling this process configured is not the one "+
				"the session is running under", tc.setting, got, tc.want)
		}
	}
}

// TestStatementTimeoutActuallyCancelsALongQuery is the behavioral half. The
// setting being present says the server parsed it; this says the server acts on
// it, which is the whole point: without it, MaxConns pathological queries pin
// the pool until MaxConnLifetime an hour later and the service stops serving
// with no error anywhere.
func TestStatementTimeoutActuallyCancelsALongQuery(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	ctx := context.Background()
	connStr := pool.Config().ConnString()

	db, err := postgres.NewWithOptions(ctx, connStr, postgres.Options{
		MaxConns:         2,
		StatementTimeout: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	defer db.Close()

	// No context deadline on purpose: the ceiling under test is the server's,
	// not the client's. A client-side cancellation would prove nothing, since
	// it needs a round trip to a server that may itself be the stuck thing.
	start := time.Now()
	_, err = db.Pool.Exec(ctx, "SELECT pg_sleep(10)")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a 10-second query ran to completion under a 250ms statement_timeout")
	}
	// 57014 is query_canceled, which is what statement_timeout raises.
	if !strings.Contains(err.Error(), "57014") && !strings.Contains(strings.ToLower(err.Error()), "canceling statement") {
		t.Fatalf("query failed with %v, want a statement-timeout cancellation", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the query was canceled after %v, far past the 250ms ceiling", elapsed)
	}
}

// TestZeroTimeoutsLeaveTheServerDefaults covers the deliberate opt-out: an
// operator who turns a ceiling off gets PostgreSQL's own default rather than a
// value this package invented for them.
func TestZeroTimeoutsLeaveTheServerDefaults(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	ctx := context.Background()
	db, err := postgres.NewWithOptions(ctx, pool.Config().ConnString(), postgres.Options{MaxConns: 2})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	defer db.Close()

	for _, setting := range []string{"statement_timeout", "lock_timeout"} {
		var got string
		if err := db.Pool.QueryRow(ctx, "SHOW "+setting).Scan(&got); err != nil {
			t.Fatalf("SHOW %s: %v", setting, err)
		}
		if got != "0" {
			t.Errorf("%s = %q with the option left at zero, want the server default \"0\"", setting, got)
		}
	}
}
