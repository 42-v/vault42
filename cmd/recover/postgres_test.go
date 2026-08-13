// Tests for openPostgres, the production escrowOpener.
//
// The rest of the suite drives the tool through an in-memory rowSource, which
// says nothing about whether the SQL is right, whether the columns are scanned in
// the order the query selects them, or whether the connection is released. Those
// only show up against a real driver.
//
// A live PostgreSQL is not available here (and starting one would make the
// offline recovery tool's test suite depend on a container runtime), so these
// tests speak the PostgreSQL v3 wire protocol back to pgx from a listener in the
// test process. That is enough for the driver to prepare, bind, execute and
// decode exactly as it would against a server, and it lets the failures that
// matter (the table is missing, the connection dies mid-read, a column does not
// decode) be produced on demand instead of waited for.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// PostgreSQL type OIDs for the six columns escrowQuery selects. The record id is
// selected as id::text, so it arrives as TEXT rather than as the UUID type.
const (
	oidBytea       = 17
	oidText        = 25
	oidInt8        = 20
	oidTimestamptz = 1184
)

// pgEpoch is the origin PostgreSQL counts binary timestamps from.
var pgEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// pgFault is the ErrorResponse a fake backend raises instead of answering.
type pgFault struct {
	code    string
	message string
}

// fakePG is a PostgreSQL server that only knows how to answer escrowQuery.
type fakePG struct {
	rows []escrowRow

	// parseFault is raised in reply to Parse, which is how a real server reports
	// a missing table or a revoked SELECT grant.
	parseFault *pgFault
	// streamFault is raised after streamAfter rows have been sent, standing in
	// for a statement timeout or a connection reset part way through a read.
	streamFault *pgFault
	streamAfter int
	// corruptTimestamp sends a deleted_at the driver cannot decode.
	corruptTimestamp bool

	ln net.Listener
	wg sync.WaitGroup

	mu         sync.Mutex
	sql        string
	limit      int64
	terminated bool
	panicked   string
}

// startFakePG brings the listener up and returns the DSN pointing at it.
func startFakePG(t *testing.T, srv *fakePG) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.ln = ln

	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.wg.Add(1)
			go func() {
				defer srv.wg.Done()
				srv.serve(conn)
			}()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		srv.wg.Wait()
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if srv.panicked != "" {
			t.Errorf("fake backend panicked, the driver sent something it does not handle: %s", srv.panicked)
		}
	})

	return fmt.Sprintf("postgres://recover:secret@%s/vault?sslmode=disable", ln.Addr().String())
}

// settle stops the listener and waits for the connection goroutines to drain.
// The tool's release function sends Terminate and closes the socket on its way
// out, which the backend observes some time later; without this, an assertion
// about what the backend saw would be racing the driver's own shutdown.
func (s *fakePG) settle(t *testing.T) {
	t.Helper()
	_ = s.ln.Close()
	s.wg.Wait()
}

// observed reports what the driver actually asked the server for. Call settle
// first if the run is expected to have finished.
func (s *fakePG) observed() (sql string, limit int64, terminated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sql, s.limit, s.terminated
}

func (s *fakePG) serve(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			s.panicked = fmt.Sprint(r)
			s.mu.Unlock()
		}
		_ = conn.Close()
	}()

	w := &wire{conn: conn}
	if !s.handshake(w) {
		return
	}

	var resultFormats []int16
	skipUntilSync := false

	for {
		typ, body, err := w.readFrontend()
		if err != nil {
			return
		}
		if typ == 'X' {
			s.mu.Lock()
			s.terminated = true
			s.mu.Unlock()
			return
		}
		if skipUntilSync && typ != 'S' {
			continue
		}

		switch typ {
		case 'P': // Parse
			r := &cursor{b: body}
			r.str() // statement name
			s.mu.Lock()
			s.sql = r.str()
			s.mu.Unlock()
			if s.parseFault != nil {
				w.errorResponse(s.parseFault)
				skipUntilSync = true
				continue
			}
			w.msg('1', nil)

		case 'D': // Describe
			r := &cursor{b: body}
			if r.byte() == 'S' {
				w.parameterDescription(oidInt8)
			}
			w.rowDescription()

		case 'B': // Bind
			resultFormats = s.readBind(body)
			w.msg('2', nil)

		case 'E': // Execute
			s.execute(w, resultFormats)
			if s.streamFault != nil {
				skipUntilSync = true
			}

		case 'S': // Sync
			skipUntilSync = false
			w.msg('Z', []byte{'I'})

		case 'H': // Flush
		}
	}
}

// handshake answers the startup message. TLS is declined because the DSN says
// sslmode=disable; a driver that asked for it anyway would be a regression worth
// seeing, so the refusal is explicit rather than assumed.
func (s *fakePG) handshake(w *wire) bool {
	for {
		body, err := w.readStartup()
		if err != nil {
			return false
		}
		switch binary.BigEndian.Uint32(body[:4]) {
		case 80877103, 80877104: // SSLRequest, GSSENCRequest
			if _, err := w.conn.Write([]byte{'N'}); err != nil {
				return false
			}
			continue
		}

		w.msg('R', []byte{0, 0, 0, 0}) // AuthenticationOk
		for _, kv := range [][2]string{
			{"server_version", "17.4"},
			{"client_encoding", "UTF8"},
			{"DateStyle", "ISO, MDY"},
			{"TimeZone", "UTC"},
			{"integer_datetimes", "on"},
			{"standard_conforming_strings", "on"},
		} {
			w.msg('S', append(cstring(kv[0]), cstring(kv[1])...))
		}
		w.msg('K', []byte{0, 0, 0, 1, 0, 0, 0, 2}) // BackendKeyData
		w.msg('Z', []byte{'I'})                    // ReadyForQuery
		return true
	}
}

// readBind records the LIMIT the driver bound and returns the result formats it
// asked the columns to come back in.
func (s *fakePG) readBind(body []byte) []int16 {
	r := &cursor{b: body}
	r.str() // portal
	r.str() // statement

	paramFormats := make([]int16, r.u16())
	for i := range paramFormats {
		paramFormats[i] = int16(r.u16())
	}
	params := int(r.u16())
	for i := range params {
		value := r.value()
		if i != 0 {
			continue
		}
		format := int16(0)
		if len(paramFormats) == 1 {
			format = paramFormats[0]
		} else if i < len(paramFormats) {
			format = paramFormats[i]
		}
		s.mu.Lock()
		if format == 1 {
			s.limit = int64(binary.BigEndian.Uint64(value)) // #nosec G115 -- int8 wire value
		} else {
			s.limit, _ = strconv.ParseInt(string(value), 10, 64)
		}
		s.mu.Unlock()
	}

	formats := make([]int16, r.u16())
	for i := range formats {
		formats[i] = int16(r.u16())
	}
	return formats
}

func (s *fakePG) execute(w *wire, resultFormats []int16) {
	sent := 0
	for _, row := range s.rows {
		if s.streamFault != nil && sent == s.streamAfter {
			w.errorResponse(s.streamFault)
			return
		}
		w.dataRow(row, resultFormats, s.corruptTimestamp)
		sent++
	}
	if s.streamFault != nil && sent == s.streamAfter {
		w.errorResponse(s.streamFault)
		return
	}
	w.msg('C', cstring("SELECT "+strconv.Itoa(sent)))
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

type wire struct{ conn net.Conn }

func (w *wire) msg(typ byte, body []byte) {
	frame := make([]byte, 5+len(body))
	frame[0] = typ
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(body)+4)) // #nosec G115 -- message bodies here are a few hundred bytes
	copy(frame[5:], body)
	if _, err := w.conn.Write(frame); err != nil {
		panic("write " + string(typ) + ": " + err.Error())
	}
}

func (w *wire) readStartup() ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(w.conn, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n < 8 || n > 1<<16 {
		return nil, errors.New("implausible startup length")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(w.conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func (w *wire) readFrontend() (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(w.conn, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:5])
	if n < 4 || n > 1<<20 {
		return 0, nil, errors.New("implausible message length")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(w.conn, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

func (w *wire) parameterDescription(oids ...uint32) {
	body := make([]byte, 2+4*len(oids))
	binary.BigEndian.PutUint16(body, uint16(len(oids))) // #nosec G115 -- one parameter
	for i, oid := range oids {
		binary.BigEndian.PutUint32(body[2+4*i:], oid)
	}
	w.msg('t', body)
}

// rowDescription describes the six columns of escrowQuery, in order.
func (w *wire) rowDescription() {
	cols := []struct {
		name string
		oid  uint32
		size int16
	}{
		{"id", oidText, -1},
		{"pseudonym", oidText, -1},
		{"payload", oidBytea, -1},
		{"deleted_at", oidTimestamptz, 8},
		{"deleted_by", oidText, -1},
		{"reason", oidText, -1},
	}

	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, uint16(len(cols))) // #nosec G115 -- six columns
	for i, col := range cols {
		body.Write(cstring(col.name))
		_ = binary.Write(&body, binary.BigEndian, uint32(16384)) // table OID
		_ = binary.Write(&body, binary.BigEndian, uint16(i+1))   // #nosec G115 -- column number
		_ = binary.Write(&body, binary.BigEndian, col.oid)       // type OID
		_ = binary.Write(&body, binary.BigEndian, col.size)      // type length
		_ = binary.Write(&body, binary.BigEndian, int32(-1))     // type modifier
		_ = binary.Write(&body, binary.BigEndian, uint16(0))     // text format, as a real Describe reports
	}
	w.msg('T', body.Bytes())
}

// The column indices here track the SELECT list in escrowQuery: id, pseudonym,
// payload, deleted_at, deleted_by, reason. Getting them out of step with the
// query would send the driver a payload where it expects a timestamp, which is
// the failure this file exists to catch, so they are written out rather than
// derived.
func (w *wire) dataRow(row escrowRow, formats []int16, corruptTimestamp bool) {
	timestamp := encodeTimestamptz(row.deletedAt, format(formats, 3))
	if corruptTimestamp {
		timestamp = []byte{0x00, 0x00, 0x00, 0x01} // too short for either encoding
	}

	cols := [][]byte{
		[]byte(row.id),
		[]byte(row.pseudonym),
		encodeBytea(row.payload, format(formats, 2)),
		timestamp,
		encodeNullableText(row.deletedBy),
		encodeNullableText(row.reason),
	}
	if row.payload == nil {
		cols[2] = nil
	}

	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, uint16(len(cols))) // #nosec G115 -- six columns
	for _, col := range cols {
		if col == nil {
			_ = binary.Write(&body, binary.BigEndian, int32(-1))
			continue
		}
		_ = binary.Write(&body, binary.BigEndian, int32(len(col))) // #nosec G115 -- test fixtures are small
		body.Write(col)
	}
	w.msg('D', body.Bytes())
}

func (w *wire) errorResponse(f *pgFault) {
	var body bytes.Buffer
	for _, field := range [][2]string{
		{"S", "ERROR"},
		{"V", "ERROR"},
		{"C", f.code},
		{"M", f.message},
	} {
		body.WriteString(field[0])
		body.Write(cstring(field[1]))
	}
	body.WriteByte(0)
	w.msg('E', body.Bytes())
}

func format(formats []int16, col int) int16 {
	switch {
	case len(formats) == 1:
		return formats[0]
	case col < len(formats):
		return formats[col]
	default:
		return 0
	}
}

func encodeBytea(b []byte, format int16) []byte {
	if format == 1 {
		return b
	}
	return append([]byte(`\x`), []byte(hex.EncodeToString(b))...)
}

func encodeTimestamptz(t time.Time, format int16) []byte {
	if format == 1 {
		out := make([]byte, 8)
		binary.BigEndian.PutUint64(out, uint64(t.UTC().Sub(pgEpoch).Microseconds())) // #nosec G115 -- fixture timestamps are after 2000
		return out
	}
	return []byte(t.UTC().Format("2006-01-02 15:04:05.999999-07:00"))
}

// encodeNullableText returns nil for a NULL column; text and binary formats are
// the same bytes for TEXT.
func encodeNullableText(s *string) []byte {
	if s == nil {
		return nil
	}
	return []byte(*s)
}

func cstring(s string) []byte { return append([]byte(s), 0) }

// cursor walks a message body.
type cursor struct {
	b []byte
	i int
}

func (c *cursor) byte() byte {
	c.i++
	return c.b[c.i-1]
}

func (c *cursor) u16() uint16 {
	c.i += 2
	return binary.BigEndian.Uint16(c.b[c.i-2:])
}

func (c *cursor) str() string {
	n := bytes.IndexByte(c.b[c.i:], 0)
	if n < 0 {
		panic("unterminated string in message body")
	}
	s := string(c.b[c.i : c.i+n])
	c.i += n + 1
	return s
}

// value reads one length-prefixed parameter, returning nil for NULL.
func (c *cursor) value() []byte {
	n := int32(binary.BigEndian.Uint32(c.b[c.i:])) // #nosec G115 -- protocol length is a signed int32
	c.i += 4
	if n < 0 {
		return nil
	}
	v := c.b[c.i : c.i+int(n)]
	c.i += int(n)
	return v
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// runAgainst drives the whole tool through openPostgres, the code path the
// shipped binary uses.
func runAgainst(t *testing.T, dsn string, args ...string) result {
	t.Helper()
	t.Setenv("DATABASE_URL", "")
	var stdout, stderr strings.Builder
	full := append([]string{"--key", writeKey(t, escrowKey), "--dsn", dsn}, args...)
	code := run(full, &stdout, &stderr, openPostgres)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// The end-to-end path: pgx prepares escrowQuery, binds --limit, streams the rows
// back, and the tool decrypts them. It also pins the two things the in-memory
// tests cannot see, namely that the SQL leaving the process is the escrow query
// and that the columns are scanned in the order the SELECT lists them.
func TestOpenPostgres_RecoversFromTheEscrowLog(t *testing.T) {
	const by = "admin:00000000-0000-0000-0000-000000000001"
	second := bareRow("second@example.invalid")
	second.payload = sealTo(t, &escrowKey.PublicKey,
		escrowJSON(t, "second@example.invalid", "Second", nil), bindingFor("second@example.invalid"))
	second.deletedAt = time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)
	second.deletedBy, second.reason = nil, nil
	srv := &fakePG{rows: []escrowRow{goodRow(t, sampleEmail), second}}
	dsn := startFakePG(t, srv)

	got := runAgainst(t, dsn, "--limit", "42")

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	recs := records(t, got.stdout)
	if len(recs) != 2 {
		t.Fatalf("recovered %d records, want 2: %q", len(recs), got.stdout)
	}
	if recs[0].Email != sampleEmail || recs[1].Email != "second@example.invalid" {
		t.Errorf("recovered %q and %q, want the rows in server order", recs[0].Email, recs[1].Email)
	}
	if !recs[0].DeletedAt.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("deleted_at = %s, want the TIMESTAMPTZ from column 2", recs[0].DeletedAt)
	}
	// Proves the binding columns survived the driver: the record only decrypts
	// because id and pseudonym came back through pgx in the shape the seal used.
	if recs[0].UserID != userIDFor(sampleEmail) || recs[0].EscrowFormat != "bound" {
		t.Errorf("record 0 = user_id %q, escrow_format %q, want the sealed subject and bound",
			recs[0].UserID, recs[0].EscrowFormat)
	}
	if recs[0].DeletedBy != by || recs[1].DeletedBy != "" {
		t.Errorf("deleted_by = %q and %q, want the column value then the NULL", recs[0].DeletedBy, recs[1].DeletedBy)
	}

	srv.settle(t)
	sql, limit, terminated := srv.observed()
	if sql != escrowQuery {
		t.Errorf("prepared SQL is not escrowQuery:\n%q", sql)
	}
	if !strings.Contains(sql, "auth.account_recovery") || !strings.Contains(sql, "ORDER BY deleted_at DESC") {
		t.Errorf("the query no longer reads the escrow log newest first:\n%q", sql)
	}
	// The binding columns have to be in the SELECT list, not merely in the Scan.
	// A query that stopped fetching them would hand every record an empty
	// binding, and every bound record in the escrow log would become
	// unrecoverable at once.
	for _, col := range []string{"id::text", "pseudonym"} {
		if !strings.Contains(sql, col) {
			t.Errorf("the query no longer selects %s, so the payload binding cannot be rebuilt:\n%q", col, sql)
		}
	}
	if limit != 42 {
		t.Errorf("bound LIMIT = %d, want 42: --limit must bound how much personal data one run reads", limit)
	}
	if !terminated {
		t.Error("the connection was not terminated: the release function must close it")
	}
}

// A wrong key still fails closed when the records arrive over the real driver,
// not only when a test hands them over in memory.
func TestOpenPostgres_WrongKeyRecoversNothing(t *testing.T) {
	row := bareRow(sampleEmail)
	row.payload = sealTo(t, &wrongKey.PublicKey,
		escrowJSON(t, sampleEmail, sampleDisplayName, nil), bindingFor(sampleEmail))
	srv := &fakePG{rows: []escrowRow{row}}
	dsn := startFakePG(t, srv)

	got := runAgainst(t, dsn)

	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
	if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 1 failure(s)") {
		t.Errorf("summary did not report the failure:\n%s", got.stderr)
	}
	mustNotLeak(t, "stderr", got.stderr, sampleEmail, sampleDisplayName)
}

// Nothing to listen on is the everyday failure when the tunnel to the database is
// not up. It must be reported as a connect failure and must not look like an
// empty escrow log.
func TestOpenPostgres_ConnectFailures(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	tests := []struct {
		name string
		dsn  string
	}{
		{"nothing listening", "postgres://recover:secret@" + deadAddr + "/vault?sslmode=disable"},
		{"malformed DSN", "postgres://recover@%zz/vault"},
		{"not a DSN at all", "the database, you know the one"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runAgainst(t, tc.dsn)

			if got.code != 1 {
				t.Errorf("exit code = %d, want 1", got.code)
			}
			if !strings.Contains(got.stderr, "recover: connect:") {
				t.Errorf("stderr = %q, want a connect failure", got.stderr)
			}
			if got.stdout != "" {
				t.Errorf("stdout = %q, want empty", got.stdout)
			}
			if strings.Contains(got.stderr, "record(s) decrypted") {
				t.Error("a failed connection printed a completion summary")
			}
		})
	}
}

// A DSN carries the database password, and every failure path prints the driver
// error verbatim. An operator running this on an incident bridge, pasting the
// output into a ticket, must not be handing over the credentials of the database
// that holds the escrow log with it.
func TestOpenPostgres_ErrorsDoNotEchoTheDSNPassword(t *testing.T) {
	const password = "sup3r-s3cret-escrow-db-password"

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	srv := &fakePG{parseFault: &pgFault{code: "42501", message: "permission denied for table account_recovery"}}
	liveDSN := strings.Replace(startFakePG(t, srv), "secret", password, 1)

	tests := []struct {
		name string
		dsn  string
	}{
		{"connect failure", "postgres://recover:" + password + "@" + deadAddr + "/vault?sslmode=disable"},
		{"query failure", liveDSN},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runAgainst(t, tc.dsn)

			if got.code != 1 {
				t.Fatalf("exit code = %d, want 1: this test is only meaningful on a failure path", got.code)
			}
			mustNotLeak(t, "connection diagnostics", got.stderr, password)
		})
	}
}

// A server that refuses the statement is a different failure from a server that
// cannot be reached: it means the escrow table is missing or the recovery role
// lost its SELECT grant. Both are fatal, and the prefixes have to stay distinct
// or an operator cannot tell a network problem from a schema problem.
func TestOpenPostgres_QueryFailureIsReportedSeparately(t *testing.T) {
	srv := &fakePG{parseFault: &pgFault{
		code:    "42P01",
		message: `relation "auth.account_recovery" does not exist`,
	}}
	dsn := startFakePG(t, srv)

	got := runAgainst(t, dsn)

	if got.code != 1 {
		t.Errorf("exit code = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, "recover: query:") {
		t.Errorf("stderr = %q, want a query failure", got.stderr)
	}
	if strings.Contains(got.stderr, "recover: connect:") {
		t.Error("a rejected statement was reported as a connection failure")
	}
	if !strings.Contains(got.stderr, "auth.account_recovery") {
		t.Errorf("the server's message was dropped:\n%s", got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
}

// A column the driver cannot decode is fatal. This is the scan path against the
// real pgx decoder rather than against a stub that returns a canned error.
func TestOpenPostgres_UndecodableColumnIsFatal(t *testing.T) {
	srv := &fakePG{
		corruptTimestamp: true,
		rows:             []escrowRow{goodRow(t, sampleEmail)},
	}
	dsn := startFakePG(t, srv)

	got := runAgainst(t, dsn)

	if got.code != 1 {
		t.Errorf("exit code = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, "recover: scan:") {
		t.Errorf("stderr = %q, want a scan failure", got.stderr)
	}
	if strings.Contains(got.stderr, "recover: iterate:") {
		t.Errorf("the scan failure was swallowed and resurfaced as an iteration failure:\n%s", got.stderr)
	}
	if strings.Contains(got.stderr, "record(s) decrypted") {
		t.Error("an aborted run printed a completion summary")
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
}

// A read that dies part way through must not be mistaken for a complete one. The
// records already emitted stay on stdout, but the run exits non-zero and prints
// no summary, so nothing downstream can treat a partial restore as the whole
// escrow log.
func TestOpenPostgres_MidStreamFailureIsFatal(t *testing.T) {
	rows := make([]escrowRow, 0, 3)
	for _, email := range []string{"first@example.invalid", "second@example.invalid", "third@example.invalid"} {
		rows = append(rows, goodRow(t, email))
	}
	srv := &fakePG{
		rows:        rows,
		streamAfter: 2,
		streamFault: &pgFault{code: "57014", message: "canceling statement due to statement timeout"},
	}
	dsn := startFakePG(t, srv)

	got := runAgainst(t, dsn)

	if got.code != 1 {
		t.Errorf("exit code = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, "recover: iterate:") {
		t.Errorf("stderr = %q, want an iteration failure", got.stderr)
	}
	if !strings.Contains(got.stderr, "statement timeout") {
		t.Errorf("the server's message was dropped:\n%s", got.stderr)
	}
	if strings.Contains(got.stderr, "record(s) decrypted") {
		t.Error("a truncated read printed a completion summary, which reads as a complete restore")
	}
	if n := len(records(t, got.stdout)); n != 2 {
		t.Errorf("emitted %d records before the failure, want the 2 the server sent", n)
	}
}

// An escrow log with no rows is a clean, empty result over the wire too.
func TestOpenPostgres_EmptyResult(t *testing.T) {
	srv := &fakePG{}
	dsn := startFakePG(t, srv)

	got := runAgainst(t, dsn)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
	if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 0 failure(s)") {
		t.Errorf("summary missing from stderr:\n%s", got.stderr)
	}
	srv.settle(t)
	if _, _, terminated := srv.observed(); !terminated {
		t.Error("the connection was not terminated after an empty read")
	}
}
