package migrate

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// cliconfigFakePG speaks just enough of the Postgres v3 wire protocol to get
// migrate.Run past the bookkeeping queries, and then drops the connection so
// the BEGIN for the first pending migration cannot be started. A real cluster
// does the same thing when the backend is terminated or the network breaks
// between two statements.
type cliconfigFakePG struct {
	ln        net.Listener
	wg        sync.WaitGroup
	mu        sync.Mutex
	queries   []string
	dropAfter int
}

func cliconfigStartFakePG(t *testing.T, dropAfter int) *cliconfigFakePG {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &cliconfigFakePG{ln: ln, dropAfter: dropAfter}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() // #nosec G104 -- test fake
		s.serve(conn)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *cliconfigFakePG) addr() string {
	host, port, _ := net.SplitHostPort(s.ln.Addr().String())
	return fmt.Sprintf("postgres://vault_mig@%s:%s/vault?sslmode=disable", host, port)
}

func (s *cliconfigFakePG) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.queries))
	copy(out, s.queries)
	return out
}

func (s *cliconfigFakePG) serve(conn net.Conn) {
	if err := cliconfigReadStartup(conn); err != nil {
		return
	}
	if _, err := conn.Write(cliconfigHandshake()); err != nil {
		return
	}
	for {
		typ, body, err := cliconfigReadMessage(conn)
		if err != nil {
			return
		}
		if typ != 'Q' {
			continue
		}
		sql := strings.TrimRight(string(body), "\x00")
		s.mu.Lock()
		s.queries = append(s.queries, sql)
		n := len(s.queries)
		s.mu.Unlock()
		if n > s.dropAfter {
			return
		}
		if _, err := conn.Write(cliconfigQueryReply(sql)); err != nil {
			return
		}
	}
}

func cliconfigReadStartup(conn net.Conn) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 4 || n > 1<<16 {
		return fmt.Errorf("bad startup length %d", n)
	}
	rest := make([]byte, n-4)
	_, err := io.ReadFull(conn, rest)
	return err
}

func cliconfigReadMessage(conn net.Conn) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n < 4 || n > 1<<20 {
		return 0, nil, fmt.Errorf("bad message length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

func cliconfigMessage(typ byte, payload []byte) []byte {
	out := make([]byte, 5, 5+len(payload))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)+4))
	return append(out, payload...)
}

func cliconfigHandshake() []byte {
	var out []byte
	out = append(out, cliconfigMessage('R', []byte{0, 0, 0, 0})...)
	params := [][2]string{
		{"server_version", "15.0"},
		{"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"},
		{"IntervalStyle", "postgres"},
		{"TimeZone", "UTC"},
		{"standard_conforming_strings", "on"},
		{"integer_datetimes", "on"},
	}
	for _, p := range params {
		payload := append([]byte(p[0]), 0)
		payload = append(payload, []byte(p[1])...)
		payload = append(payload, 0)
		out = append(out, cliconfigMessage('S', payload)...)
	}
	key := make([]byte, 8)
	binary.BigEndian.PutUint32(key, 4242)
	binary.BigEndian.PutUint32(key[4:], 424242)
	out = append(out, cliconfigMessage('K', key)...)
	out = append(out, cliconfigMessage('Z', []byte{'I'})...)
	return out
}

func cliconfigQueryReply(sql string) []byte {
	var out []byte
	if strings.Contains(strings.ToUpper(sql), "SELECT") {
		var rd []byte
		rd = binary.BigEndian.AppendUint16(rd, 1)
		rd = append(rd, []byte("version")...)
		rd = append(rd, 0)
		rd = binary.BigEndian.AppendUint32(rd, 0)
		rd = binary.BigEndian.AppendUint16(rd, 0)
		rd = binary.BigEndian.AppendUint32(rd, 25)
		rd = binary.BigEndian.AppendUint16(rd, 0xFFFF)
		rd = binary.BigEndian.AppendUint32(rd, 0xFFFFFFFF)
		rd = binary.BigEndian.AppendUint16(rd, 0)
		out = append(out, cliconfigMessage('T', rd)...)
		out = append(out, cliconfigMessage('C', append([]byte("SELECT 0"), 0))...)
	} else {
		out = append(out, cliconfigMessage('C', append([]byte("CREATE TABLE"), 0))...)
	}
	out = append(out, cliconfigMessage('Z', []byte{'I'})...)
	return out
}

func cliconfigConnect(t *testing.T, s *cliconfigFakePG) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(s.addr())
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Skipf("fake postgres handshake not accepted by this pgx build: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// A migration must never be recorded as applied when its transaction could not
// even be opened. Run has to stop at the first file, name it, and leave the
// remaining files untouched so a re-run picks up exactly where it stopped.
func TestRun_TransactionCannotBeStarted(t *testing.T) {
	// Four queries reach the backend before the first BEGIN: the advisory lock,
	// the CREATE TABLE, the applied-versions SELECT, and then the BEGIN itself.
	s := cliconfigStartFakePG(t, 3)
	conn := cliconfigConnect(t, s)

	dir := t.TempDir()
	for _, f := range []string{"001_initial.sql", "002_add_users.sql"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("SELECT 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	err := Run(context.Background(), conn, dir)
	if err == nil {
		t.Fatal("Run reported success though no transaction was ever opened")
	}
	if !strings.Contains(err.Error(), "begin tx for 001_initial.sql") {
		t.Fatalf("error %q does not name the migration whose transaction failed", err)
	}

	for _, q := range s.seen() {
		if strings.Contains(q, "INSERT INTO public.schema_migrations") {
			t.Errorf("migration was recorded as applied without running: %q", q)
		}
		if strings.Contains(q, "002_add_users") {
			t.Error("Run continued to the next migration after the failure")
		}
	}
}
