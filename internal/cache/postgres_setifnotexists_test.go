package cache

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// serveInsertOneRow speaks just enough of the PostgreSQL wire protocol to
// complete the startup handshake and answer every simple-protocol query with
// an "INSERT 0 1" command tag. It lets the success path of SetIfNotExists run
// against a deterministic in-process peer instead of a real database.
func serveInsertOneRow(conn net.Conn) {
	defer conn.Close()
	backend := pgproto3.NewBackend(conn, conn)
	if _, err := backend.ReceiveStartupMessage(); err != nil {
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.4"})
	backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	backend.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return
	}
	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.Query:
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("INSERT 0 1")})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backend.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

// SetIfNotExists is the single-use guarantee behind OTP redemption and OAuth
// state consumption: when the INSERT lands, the caller must be told it took
// the lock. The error path is covered elsewhere; this exercises the success
// return built from the command tag.
func TestPostgresCache_SetIfNotExists_Inserted(t *testing.T) {
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig("postgres://vault:vault@127.0.0.1:5432/vault?sslmode=disable&default_query_exec_mode=simple_protocol")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go serveInsertOneRow(server)
		return client, nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)

	c, err := NewPostgresCache(pool)
	if err != nil {
		t.Fatalf("NewPostgresCache: %v", err)
	}

	ok, err := c.SetIfNotExists(ctx, "lock", "v", time.Minute)
	if err != nil {
		t.Fatalf("SetIfNotExists: %v", err)
	}
	if !ok {
		t.Fatal("SetIfNotExists returned false for an INSERT that affected one row")
	}
}
