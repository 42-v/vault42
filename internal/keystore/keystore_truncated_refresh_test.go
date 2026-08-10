package keystore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Refresh is where the process learns which signing keys exist. It replaces the
// whole verification set on success, so a result set that stops partway through
// is the one database failure this function must never treat as an answer: pgx
// hands over the rows that arrived and reports the failure only through
// rows.Err(), after the loop has already ended normally.
//
// Ignoring that would publish a JWKS built from however much of the table
// happened to arrive. Every kid missing from it stops verifying immediately,
// across every service that trusts this issuer, and nothing anywhere logs an
// error: the keys were simply never seen. Failing instead keeps the previously
// loaded set in memory, which is the documented behavior for every other
// Refresh failure.

// Postgres type OIDs used by the scripted signing-keys row description.
const (
	keystoreOIDBytea         = 17
	keystoreOIDVarchar       = 1043
	keystoreOIDTimestamptz   = 1184
	keystorePostgresEpochOff = 946684800 // seconds between 1970-01-01 and 2000-01-01
)

func keystoreField(name string, oid uint32) pgproto3.FieldDescription {
	return pgproto3.FieldDescription{Name: []byte(name), DataTypeOID: oid, DataTypeSize: -1, TypeModifier: -1}
}

func keystoreTimestamptz(ts time.Time) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64((ts.Unix()-keystorePostgresEpochOff)*1_000_000))
	return b
}

// keystoreTruncatedPool serves one signing-keys result set that delivers rows and
// then dies, which is what a canceled statement or a recovery conflict looks
// like on the wire. It is the only way to produce a non-nil rows.Err() after a
// successfully started iteration without a database that is already broken.
func keystoreTruncatedPool(t *testing.T, rows [][][]byte) *pgxpool.Pool {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	fields := []pgproto3.FieldDescription{
		keystoreField("kid", keystoreOIDVarchar),
		keystoreField("private_key", keystoreOIDBytea),
		keystoreField("public_key", keystoreOIDBytea),
		keystoreField("algorithm", keystoreOIDVarchar),
		keystoreField("status", keystoreOIDVarchar),
		keystoreField("created_at", keystoreOIDTimestamptz),
		keystoreField("retired_at", keystoreOIDTimestamptz),
		keystoreField("expires_at", keystoreOIDTimestamptz),
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go keystoreServeTruncated(conn, fields, rows)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, "postgres://scripted:scripted@"+ln.Addr().String()+"/scripted?sslmode=disable")
	if err != nil {
		_ = ln.Close()
		t.Fatalf("connect to the scripted backend: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_ = ln.Close()
	})
	return pool
}

func keystoreServeTruncated(conn net.Conn, fields []pgproto3.FieldDescription, rows [][][]byte) {
	defer conn.Close()

	be := pgproto3.NewBackend(conn, conn)
	if _, err := be.ReceiveStartupMessage(); err != nil {
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	for _, p := range [][2]string{
		{"server_version", "16.0"},
		{"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"},
		{"TimeZone", "UTC"},
		{"standard_conforming_strings", "on"},
		{"integer_datetimes", "on"},
	} {
		be.Send(&pgproto3.ParameterStatus{Name: p[0], Value: p[1]})
	}
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return
	}

	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.Parse:
			be.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Describe:
			be.Send(&pgproto3.ParameterDescription{})
			be.Send(&pgproto3.RowDescription{Fields: fields})
		case *pgproto3.Bind:
			be.Send(&pgproto3.BindComplete{})
		case *pgproto3.Execute:
			for _, row := range rows {
				be.Send(&pgproto3.DataRow{Values: row})
			}
			be.Send(&pgproto3.ErrorResponse{
				Severity: "ERROR", Code: "57014",
				Message: "canceling statement due to conflict with recovery",
			})
		case *pgproto3.Sync:
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

func TestKeyStore_RefreshRefusesATruncatedKeySet(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// A retired key: readable without the master key, so the row is fully
	// consumed and lands in the public set the truncated refresh would publish.
	row := [][]byte{
		[]byte("kid-retired"),
		[]byte("private-key-ciphertext"),
		pubDER,
		[]byte("RS256"),
		[]byte("retired"),
		keystoreTimestamptz(time.Now().Add(-time.Hour)),
		keystoreTimestamptz(time.Now().Add(-time.Minute)),
		nil,
	}

	ks, err := New(keystoreTruncatedPool(t, [][][]byte{row}), make([]byte, 32), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = ks.Refresh(context.Background())
	if err == nil {
		t.Fatal("a result set that died mid-stream was accepted as the complete key set; JWKS would silently lose every kid the query never reached")
	}
	if !strings.Contains(err.Error(), "iterate rows") {
		t.Errorf("err = %v, want the truncated iteration to be named", err)
	}

	if got := ks.AllPublicKeys(); len(got) != 0 {
		t.Errorf("the partial key set was published anyway: %d keys", len(got))
	}
	if _, kid := ks.ActiveKey(); kid != "" {
		t.Errorf("active kid = %q, want none: a failed refresh must not change what the process signs with", kid)
	}
}
