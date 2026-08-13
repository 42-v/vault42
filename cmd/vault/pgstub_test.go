package main

// Postgres wire stub.
//
// cmd/vault is the process that wires every subsystem together, and nearly all
// of that wiring runs after postgres.New has returned. postgres.New pings the
// pool, so with nothing answering on the wire the binary dies on its first
// database statement and the rest of main() is unobservable: a test suite for
// this package that refuses to talk to a database can only ever reach the
// argument parsing at the top of the file.
//
// Starting a real Postgres would put a container runtime between this package
// and its tests. internal/repository/postgres already solved the same problem
// with a scripted wire stub (wire_stub_test.go); this is the same idea carried
// into the entry point, extended to the extended query protocol because the
// startup path prepares statements as well as pinging.
//
// What it implements: the startup handshake with trust auth, the simple query
// path (pgx.Conn.Ping and any Exec with no arguments), and the extended query
// path (Parse/Bind/Describe/Execute/Sync) that everything with a $1 uses. A
// query that matches no rule is answered as an empty successful result, so each
// test scripts only the rows its assertion depends on and nothing else.
//
// What it is not: a database. It does not parse SQL, hold state, enforce
// constraints, or distinguish connections. Assertions built on it must be about
// what vault42 does with an answer, never about the answer itself.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/repository/postgres"
)

// pgColumn is one column of a scripted result. The OID matters beyond
// documentation: pgx asks for each column in the format the type prefers, so the
// OID declared here decides whether the value bytes below must be text or
// binary. pgWireFormat is the single place that mapping is written down.
type pgColumn struct {
	name string
	oid  uint32
}

// pgRule scripts the answer to every query containing match. Rules are tried in
// order and the first hit wins.
//
// Row values are raw wire bytes already in the format the column's OID implies,
// which is what pgText, pgBytea, and pgTimestamptz produce. A nil value is SQL
// NULL.
type pgRule struct {
	match string
	cols  []pgColumn
	rows  [][][]byte

	// tag is the CommandComplete tag. Empty means "SELECT <n>".
	tag string

	// answers, when set, replaces rows and is called with the number of times
	// this rule has already been executed. It models a table an earlier
	// statement in the same startup wrote to, which is exactly the sequence
	// KeyStore.EnsureKey performs: read, find nothing, write, read again.
	answers func(prior int) [][][]byte

	// errCode is a SQLSTATE. When set the rule answers with an ErrorResponse
	// instead of rows, which is how a test drives vault42's database-failure
	// branches without taking the database away entirely.
	errCode string
	errMsg  string
}

// textColumns describes a result whose columns are all text, which is most of
// what the startup path reads.
func textColumns(names ...string) []pgColumn {
	cols := make([]pgColumn, 0, len(names))
	for _, n := range names {
		cols = append(cols, pgColumn{name: n, oid: pgOIDText})
	}
	return cols
}

// textRow builds one all-text row.
func textRow(vals ...string) [][]byte {
	row := make([][]byte, 0, len(vals))
	for _, v := range vals {
		row = append(row, pgText(v))
	}
	return row
}

func pgText(s string) []byte  { return []byte(s) }
func pgBytea(b []byte) []byte { return b }

// pgTimestamptz encodes a timestamp the way PostgreSQL does on the binary wire:
// microseconds since midnight 2000-01-01 UTC.
func pgTimestamptz(ts time.Time) []byte {
	const epochOffset = 946684800 // 2000-01-01T00:00:00Z in Unix seconds
	micros := ts.UTC().UnixMicro() - epochOffset*1_000_000
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(micros))
	return b
}

// pgStub is a listener that answers the Postgres v3 protocol from a rule table.
type pgStub struct {
	ln net.Listener

	mu     sync.Mutex
	rules  []pgRule
	seen   []string
	served map[int]int // rule index -> executions so far
}

// startPGStub starts a stub on a loopback port and stops it when the test ends.
func startPGStub(t *testing.T, rules ...pgRule) *pgStub {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &pgStub{ln: ln, rules: rules, served: map[int]int{}}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// host and port are what the DB_HOST / DB_PORT environment variables must be set
// to for vault42 to reach the stub.
func (s *pgStub) host() string {
	h, _, _ := net.SplitHostPort(s.ln.Addr().String())
	return h
}

func (s *pgStub) port() string {
	_, p, _ := net.SplitHostPort(s.ln.Addr().String())
	return p
}

// queries returns every statement the stub has been asked to run. It exists so a
// test can assert that a startup path did reach the database rather than
// inferring it from a log line.
func (s *pgStub) queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// sawQuery reports whether any observed statement contains substr.
func (s *pgStub) sawQuery(substr string) bool {
	for _, q := range s.queries() {
		if strings.Contains(q, substr) {
			return true
		}
	}
	return false
}

func (s *pgStub) record(sql string) {
	s.mu.Lock()
	s.seen = append(s.seen, sql)
	s.mu.Unlock()
}

func (s *pgStub) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

// rule returns the first rule matching sql, or nil.
func (s *pgStub) rule(sql string) *pgRule {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		if strings.Contains(sql, s.rules[i].match) {
			r := s.rules[i]
			return &r
		}
	}
	return nil
}

// rowsFor returns the rows a rule answers with, advancing its execution counter
// when the rule answers from a function.
func (s *pgStub) rowsFor(sql string) [][][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		if !strings.Contains(sql, s.rules[i].match) {
			continue
		}
		if s.rules[i].answers == nil {
			return s.rules[i].rows
		}
		prior := s.served[i]
		s.served[i]++
		return s.rules[i].answers(prior)
	}
	return nil
}

// setRules replaces the rule table while the stub is serving. It is how a test
// changes the database underneath a running vault42, which is the only way to
// observe a background refresh loop reacting to something.
func (s *pgStub) setRules(rules ...pgRule) {
	s.mu.Lock()
	s.rules = rules
	s.served = map[int]int{}
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

func (s *pgStub) handle(conn net.Conn) {
	defer conn.Close() //nolint:errcheck // test double; the client is gone by then
	r := bufio.NewReader(conn)
	if !pgHandshake(conn, r) {
		return
	}

	// Extended-protocol state. Statements and portals are per connection, which
	// is all pgx needs: it never shares a prepared statement across connections.
	stmts := map[string]string{}
	portals := map[string]string{}
	var pending []byte
	failed := false

	write := func(b []byte) bool {
		_, err := conn.Write(b)
		return err == nil
	}

	for {
		typ, body, ok := pgReadMessage(r)
		if !ok {
			return
		}

		switch typ {
		case 'Q': // simple query
			sql := pgCString(&body)
			s.record(sql)
			if !write(s.answer(sql, true)) {
				return
			}

		case 'P': // Parse
			name := pgCString(&body)
			sql := pgCString(&body)
			stmts[name] = sql
			s.record(sql)
			if !failed {
				pending = append(pending, pgMsg('1')...)
			}

		case 'B': // Bind
			portal := pgCString(&body)
			stmt := pgCString(&body)
			portals[portal] = stmts[stmt]
			if !failed {
				pending = append(pending, pgMsg('2')...)
			}

		case 'D': // Describe
			if len(body) == 0 {
				return
			}
			kind := body[0]
			body = body[1:]
			name := pgCString(&body)
			sql := stmts[name]
			if kind == 'P' {
				sql = portals[name]
			}
			if failed {
				break
			}
			if kind == 'S' {
				pending = append(pending, pgParamDesc(pgParamCount(sql))...)
			}
			pending = append(pending, s.rowDescription(sql, false)...)

		case 'E': // Execute
			portal := pgCString(&body)
			if failed {
				break
			}
			sql := portals[portal]
			pending = append(pending, s.answer(sql, false)...)
			if rule := s.rule(sql); rule != nil && rule.errCode != "" {
				failed = true
			}

		case 'C': // Close
			if !failed {
				pending = append(pending, pgMsg('3')...)
			}

		case 'H': // Flush
			if !write(pending) {
				return
			}
			pending = nil

		case 'S': // Sync
			pending = append(pending, pgReadyIdle()...)
			if !write(pending) {
				return
			}
			pending = nil
			failed = false

		case 'X': // Terminate
			return
		}
	}
}

// pgHandshake completes the startup exchange, refusing TLS (tests connect with
// sslmode=disable) and accepting any credentials.
func pgHandshake(conn net.Conn, r *bufio.Reader) bool {
	for {
		var length int32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return false
		}
		if length < 8 {
			return false
		}
		body := make([]byte, length-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return false
		}
		switch binary.BigEndian.Uint32(body[:4]) {
		case 80877103: // SSLRequest
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return false
			}
			continue
		case 80877102: // CancelRequest
			return false
		}

		var hello []byte
		hello = append(hello, pgMsg('R', pgInt32(0))...) // AuthenticationOk
		for _, kv := range [][2]string{
			{"server_version", "16.0"},
			{"client_encoding", "UTF8"},
			{"DateStyle", "ISO, MDY"},
			{"TimeZone", "UTC"},
			{"integer_datetimes", "on"},
			{"standard_conforming_strings", "on"},
		} {
			hello = append(hello, pgMsg('S', pgCStr(kv[0]), pgCStr(kv[1]))...)
		}
		hello = append(hello, pgMsg('K', pgInt32(4242), pgInt32(4242))...)
		hello = append(hello, pgReadyIdle()...)
		_, err := conn.Write(hello)
		return err == nil
	}
}

// answer renders the scripted reply for sql. In the simple protocol the reply is
// self-contained and ends with ReadyForQuery; in the extended protocol the row
// description was already sent from Describe and ReadyForQuery follows at Sync.
func (s *pgStub) answer(sql string, simple bool) []byte {
	rule := s.rule(sql)

	if rule != nil && rule.errCode != "" {
		out := pgErrorResponse(rule.errCode, rule.errMsg)
		if simple {
			out = append(out, pgReadyIdle()...)
		}
		return out
	}

	var out []byte
	if simple {
		out = append(out, s.rowDescription(sql, true)...)
	}
	var rows [][][]byte
	if rule != nil {
		rows = s.rowsFor(sql)
		for _, row := range rows {
			out = append(out, pgDataRow(row)...)
		}
	}
	tag := "SELECT 0"
	if rule != nil {
		tag = rule.tag
		if tag == "" {
			tag = "SELECT " + strconv.Itoa(len(rows))
		}
	}
	out = append(out, pgMsg('C', pgCStr(tag))...)
	if simple {
		out = append(out, pgReadyIdle()...)
	}
	return out
}

// rowDescription describes the columns a scripted rule returns, or NoData when
// no rule matches. NoData is what makes an unmatched query read as an empty
// result set rather than as an error: the caller's rows.Next() is false at once
// and QueryRow reports pgx.ErrNoRows.
func (s *pgStub) rowDescription(sql string, simple bool) []byte {
	rule := s.rule(sql)
	if rule == nil || len(rule.cols) == 0 {
		return pgMsg('n')
	}
	parts := [][]byte{pgInt16(int16(len(rule.cols)))}
	for i, col := range rule.cols {
		format := pgWireFormat(col.oid)
		if simple {
			// The simple protocol has no Bind to negotiate formats, so every
			// value on it is text.
			format = pgTextFormatCode
		}
		parts = append(parts,
			pgCStr(col.name),
			pgInt32(0),              // table OID
			pgInt16(int16(i+1)),     // column attribute number
			pgInt32(int32(col.oid)), // type OID
			pgInt16(-1),             // type size
			pgInt32(-1),             // type modifier
			pgInt16(format),         // format code
		)
	}
	return pgMsg('T', parts...)
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

const (
	pgOIDText        uint32 = 25
	pgOIDBytea       uint32 = 17
	pgOIDTimestamptz uint32 = 1184

	pgTextFormatCode   int16 = 0
	pgBinaryFormatCode int16 = 1
)

// pgWireFormat mirrors the format pgx requests for a column of the given type.
// pgx derives it from the codec registered for the OID, so a stub that guesses
// differently sends bytes the client decodes as garbage. Keeping the mapping in
// one function makes a future scripted column type an explicit decision.
func pgWireFormat(oid uint32) int16 {
	switch oid {
	case pgOIDBytea, pgOIDTimestamptz:
		return pgBinaryFormatCode
	default:
		return pgTextFormatCode
	}
}

// pgParamPattern finds the placeholders in a statement. The stub does not parse
// SQL, but it must agree with the client about how many parameters a statement
// takes: pgx compares the argument count against the ParameterDescription and
// refuses to send the Bind if they differ.
var pgParamPattern = regexp.MustCompile(`\$(\d+)`)

// pgParamCount returns the highest placeholder index in sql.
func pgParamCount(sql string) int {
	high := 0
	for _, m := range pgParamPattern.FindAllStringSubmatch(sql, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil && n > high {
			high = n
		}
	}
	return high
}

// pgParamDesc declares n parameters of unspecified type. OID 0 makes pgx encode
// each argument from its Go type instead of from a type the stub would have to
// guess, so a statement binding a timestamp works without the stub knowing that
// the column is a timestamp.
func pgParamDesc(n int) []byte {
	parts := [][]byte{pgInt16(int16(n))}
	for i := 0; i < n; i++ {
		parts = append(parts, pgInt32(0))
	}
	return pgMsg('t', parts...)
}

func pgReadMessage(r *bufio.Reader) (byte, []byte, bool) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, false
	}
	var length int32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return 0, nil, false
	}
	if length < 4 {
		return 0, nil, false
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, false
	}
	return typ, body, true
}

// pgCString consumes one NUL-terminated string from the front of buf.
func pgCString(buf *[]byte) string {
	i := 0
	for i < len(*buf) && (*buf)[i] != 0 {
		i++
	}
	s := string((*buf)[:i])
	if i < len(*buf) {
		i++
	}
	*buf = (*buf)[i:]
	return s
}

func pgInt16(v int16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(v))
	return b
}

func pgInt32(v int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b
}

func pgCStr(s string) []byte { return append([]byte(s), 0) }

func pgMsg(typ byte, parts ...[]byte) []byte {
	var payload []byte
	for _, p := range parts {
		payload = append(payload, p...)
	}
	out := []byte{typ}
	out = append(out, pgInt32(int32(len(payload)+4))...)
	return append(out, payload...)
}

func pgReadyIdle() []byte { return pgMsg('Z', []byte{'I'}) }

func pgDataRow(vals [][]byte) []byte {
	parts := [][]byte{pgInt16(int16(len(vals)))}
	for _, v := range vals {
		if v == nil {
			parts = append(parts, pgInt32(-1))
			continue
		}
		parts = append(parts, pgInt32(int32(len(v))), v)
	}
	return pgMsg('D', parts...)
}

// pgErrorResponse is the server saying no. The SQLSTATE is what pgx surfaces to
// the caller, so it is scripted rather than left blank.
func pgErrorResponse(code, message string) []byte {
	var payload []byte
	payload = append(payload, 'S')
	payload = append(payload, pgCStr("ERROR")...)
	payload = append(payload, 'V')
	payload = append(payload, pgCStr("ERROR")...)
	payload = append(payload, 'C')
	payload = append(payload, pgCStr(code)...)
	payload = append(payload, 'M')
	payload = append(payload, pgCStr(message)...)
	payload = append(payload, 0)
	return pgMsg('E', payload)
}

// TestPGStubAnswersTheStartupProtocol guards the double itself. Every startup
// test in this package is worthless if the stub stops completing the handshake
// or stops answering prepared statements, and the symptom of that would be a
// pile of unrelated boot failures rather than one clear message. This asserts
// the three shapes vault42's startup depends on: the ping that postgres.New
// makes, a scripted single-row read, and an unmatched statement reading back as
// an empty result rather than as an error.
func TestPGStubAnswersTheStartupProtocol(t *testing.T) {
	stub := startPGStub(t, pgRule{
		match: "SELECT value FROM auth.admin_config",
		cols:  textColumns("value"),
		rows:  [][][]byte{textRow("scripted-value")},
	})

	db, err := postgres.New(context.Background(), pgStubDSN(stub), 2)
	if err != nil {
		t.Fatalf("postgres.New against the stub: %v", err)
	}
	defer db.Close()

	var got string
	err = db.Pool.QueryRow(context.Background(),
		`SELECT value FROM auth.admin_config WHERE key = $1`, "admin_token_hash").Scan(&got)
	if err != nil {
		t.Fatalf("scripted read: %v", err)
	}
	if got != "scripted-value" {
		t.Fatalf("scripted read = %q, want %q", got, "scripted-value")
	}

	var missing string
	err = db.Pool.QueryRow(context.Background(),
		`SELECT nothing FROM auth.unscripted WHERE key = $1`, "k").Scan(&missing)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unmatched statement error = %v, want pgx.ErrNoRows", err)
	}

	if !stub.sawQuery("auth.unscripted") {
		t.Fatal("stub did not record the unmatched statement")
	}
}

// pgStubDSN builds the connection string for the stub. sslmode is disabled
// because the stub refuses TLS.
func pgStubDSN(s *pgStub) string {
	return "postgres://vault_app:pw@" + s.ln.Addr().String() + "/vault?sslmode=disable"
}
