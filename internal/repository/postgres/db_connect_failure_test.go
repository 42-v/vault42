package postgres

import (
	"context"
	"testing"
)

// New must not hand back a *DB it has never proved it can talk to. pgxpool
// connects lazily, so without the ping a pool aimed at a dead or wrong host is
// indistinguishable from a working one until the first query, which is long
// after the process has finished starting, reported itself healthy and started
// taking authentication traffic it can only fail.
func TestNew_UnreachableDatabaseFailsAtStartup(t *testing.T) {
	// Port 1 is reserved and nothing listens there.
	db, err := New(context.Background(), "postgres://vault:vault@127.0.0.1:1/vault?connect_timeout=1", 5)
	if err == nil {
		if db != nil {
			db.Close()
		}
		t.Fatal("New accepted a database it could not reach")
	}
	if db != nil {
		t.Error("a *DB was returned alongside the error; a caller that ignores err would run on a dead pool")
	}
}
