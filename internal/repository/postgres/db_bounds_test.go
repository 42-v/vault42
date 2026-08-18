package postgres

import (
	"testing"
	"time"
)

// A pool with no server-side ceiling is the shape in which MaxConns pathological
// queries pin every connection until MaxConnLifetime an hour later and the
// service stops serving with nothing in the logs. These assert the config the
// pool is built from, so they need no server.

func TestPoolConfigSetsServerSideCeilings(t *testing.T) {
	cfg, err := poolConfig("postgres://u:p@localhost:5432/vault?sslmode=disable", Options{
		MaxConns:         25,
		StatementTimeout: 10 * time.Second,
		LockTimeout:      3 * time.Second,
	})
	if err != nil {
		t.Fatalf("poolConfig: %v", err)
	}

	params := cfg.ConnConfig.RuntimeParams
	for _, tc := range []struct{ key, want string }{
		{"statement_timeout", "10000"},
		{"lock_timeout", "3000"},
		{"idle_in_transaction_session_timeout", "30000"},
	} {
		if got := params[tc.key]; got != tc.want {
			t.Errorf("%s = %q, want %q — set as a startup parameter so every connection the "+
				"pool opens carries it", tc.key, got, tc.want)
		}
	}

	if cfg.MaxConns != 25 {
		t.Errorf("MaxConns = %d, want 25", cfg.MaxConns)
	}
	if cfg.MaxConnLifetime != time.Hour {
		t.Errorf("MaxConnLifetime = %v, want 1h", cfg.MaxConnLifetime)
	}
	if cfg.MaxConnLifetimeJitter == 0 {
		t.Error("MaxConnLifetimeJitter is 0: every connection opened at startup expires at the " +
			"same instant and the whole pool reconnects in lockstep, once an hour, forever")
	}
	if cfg.MaxConnIdleTime != 15*time.Minute {
		t.Errorf("MaxConnIdleTime = %v, want 15m", cfg.MaxConnIdleTime)
	}
}

// TestPoolConfigLeavesTimeoutsUnsetWhenDisabled covers the deliberate opt-out:
// an operator who turns a ceiling off gets the server's own default rather than
// a value this package invented.
func TestPoolConfigLeavesTimeoutsUnsetWhenDisabled(t *testing.T) {
	cfg, err := poolConfig("postgres://u:p@localhost:5432/vault?sslmode=disable", Options{})
	if err != nil {
		t.Fatalf("poolConfig: %v", err)
	}
	params := cfg.ConnConfig.RuntimeParams
	if _, ok := params["statement_timeout"]; ok {
		t.Error("a zero StatementTimeout still wrote statement_timeout")
	}
	if _, ok := params["lock_timeout"]; ok {
		t.Error("a zero LockTimeout still wrote lock_timeout")
	}
	// The transaction-idle ceiling is not configurable, so it is always there.
	if params["idle_in_transaction_session_timeout"] == "" {
		t.Error("idle_in_transaction_session_timeout is unset; a session holding row locks " +
			"across a network wait is a bug or a stalled peer either way")
	}
}

// TestPoolConfigIgnoresAnOutOfRangeMaxConns keeps a typo from either disabling
// the pool or asking for a connection count the server cannot serve.
func TestPoolConfigIgnoresAnOutOfRangeMaxConns(t *testing.T) {
	for _, n := range []int{0, -1, 1001} {
		cfg, err := poolConfig("postgres://u:p@localhost:5432/vault?sslmode=disable", Options{MaxConns: n})
		if err != nil {
			t.Fatalf("poolConfig(%d): %v", n, err)
		}
		if cfg.MaxConns <= 0 {
			t.Errorf("MaxConns=%d left the pool at %d", n, cfg.MaxConns)
		}
	}
}

func TestPoolConfigRejectsAnUnparseableDSN(t *testing.T) {
	if _, err := poolConfig("://not a dsn", Options{}); err == nil {
		t.Fatal("poolConfig accepted an unparseable connection string")
	}
}

// TestSetTimeoutParamRoundsSubMillisecondUp keeps a deliberately tiny ceiling
// from being written as "0", which Postgres reads as no timeout at all — the
// opposite of what the operator asked for.
func TestSetTimeoutParamRoundsSubMillisecondUp(t *testing.T) {
	params := map[string]string{}
	setTimeoutParam(params, "statement_timeout", time.Microsecond)
	if got := params["statement_timeout"]; got != "1" {
		t.Fatalf("statement_timeout = %q, want \"1\" — a sub-millisecond ceiling must not "+
			"round down to the value Postgres reads as unlimited", got)
	}
}
