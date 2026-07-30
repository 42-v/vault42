package postgres

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A dead pool proves a repository reports a database it cannot reach. It cannot
// prove anything about a database that answers badly, which is the failure mode
// that actually loses data: a row that comes back in a shape the scanner cannot
// read, or a stream that dies halfway through, or a transaction that is refused
// at COMMIT after every statement in it succeeded. Those paths are the ones that
// decide whether a caller is handed a short list, an empty list, or an error.
//
// apPGStub is just enough of the Postgres v3 wire protocol to script those
// answers: it completes the startup handshake with trust auth and then replies
// to simple-protocol queries from a table of substring matchers.

type apPGReply func(query string) []byte

type apPGStub struct {
	ln      net.Listener
	replies []apPGRule
}

type apPGRule struct {
	match string
	reply apPGReply
}

// apStartPG starts a stub server and returns a *DB pointed at it. Queries are
// matched against the rules in order; the first substring hit wins, and an
// unmatched query gets an empty successful result so incidental traffic does not
// have to be scripted.
func apStartPG(t *testing.T, rules ...apPGRule) *DB {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &apPGStub{ln: ln, replies: rules}

	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })

	dsn := fmt.Sprintf("postgres://vault:vault@%s/vault?sslmode=disable&default_query_exec_mode=simple_protocol&pool_max_conns=1",
		ln.Addr().String())
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return &DB{Pool: pool}
}

func (s *apPGStub) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *apPGStub) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	for {
		// The startup packet has no type byte: length first, then the body.
		var length int32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return
		}
		if length < 8 {
			return
		}
		body := make([]byte, length-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		version := binary.BigEndian.Uint32(body[:4])
		if version == 80877103 { // SSLRequest
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		}
		if version == 80877102 { // CancelRequest
			return
		}
		break
	}

	var hello []byte
	hello = append(hello, apMsg('R', apInt32(0))...)
	for _, kv := range [][2]string{
		{"server_version", "16.0"},
		{"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"},
		{"TimeZone", "UTC"},
		{"integer_datetimes", "on"},
		{"standard_conforming_strings", "on"},
	} {
		hello = append(hello, apMsg('S', apCStr(kv[0]), apCStr(kv[1]))...)
	}
	hello = append(hello, apMsg('K', apInt32(4242), apInt32(4242))...)
	hello = append(hello, apReadyIdle()...)
	if _, err := conn.Write(hello); err != nil {
		return
	}

	for {
		typ, err := r.ReadByte()
		if err != nil {
			return
		}
		var length int32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return
		}
		body := make([]byte, length-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		if typ != 'Q' {
			if typ == 'X' {
				return
			}
			continue
		}
		query := strings.TrimRight(string(body), "\x00")
		if _, err := conn.Write(s.respond(query)); err != nil {
			return
		}
	}
}

func (s *apPGStub) respond(query string) []byte {
	for _, rule := range s.replies {
		if strings.Contains(query, rule.match) {
			return rule.reply(query)
		}
	}
	return append(apMsg('C', apCStr("SELECT 0")), apReadyIdle()...)
}

// ---------------------------------------------------------------------------
// wire encoding helpers
// ---------------------------------------------------------------------------

func apInt16(v int16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(v))
	return b
}

func apInt32(v int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b
}

func apCStr(s string) []byte { return append([]byte(s), 0) }

func apMsg(typ byte, parts ...[]byte) []byte {
	var payload []byte
	for _, p := range parts {
		payload = append(payload, p...)
	}
	out := []byte{typ}
	out = append(out, apInt32(int32(len(payload)+4))...)
	return append(out, payload...)
}

func apReadyIdle() []byte     { return apMsg('Z', []byte{'I'}) }
func apReadyInTx() []byte     { return apMsg('Z', []byte{'T'}) }
func apReadyTxFailed() []byte { return apMsg('Z', []byte{'E'}) }

// apCol describes one column of a scripted RowDescription.
type apCol struct {
	name string
	oid  int32
	size int16
}

func apRowDesc(cols ...apCol) []byte {
	parts := [][]byte{apInt16(int16(len(cols)))}
	for i, c := range cols {
		parts = append(parts,
			apCStr(c.name),
			apInt32(0),          // table OID
			apInt16(int16(i+1)), // column attribute number
			apInt32(c.oid),      // type OID
			apInt16(c.size),     // type size
			apInt32(-1),         // type modifier
			apInt16(0),          // text format
		)
	}
	return apMsg('T', parts...)
}

// apDataRow encodes one row. A nil value is sent as SQL NULL.
func apDataRow(vals ...*string) []byte {
	parts := [][]byte{apInt16(int16(len(vals)))}
	for _, v := range vals {
		if v == nil {
			parts = append(parts, apInt32(-1))
			continue
		}
		parts = append(parts, apInt32(int32(len(*v))), []byte(*v))
	}
	return apMsg('D', parts...)
}

func apText(s string) *string { return &s }

// apErrorResponse is the server saying no. The SQLSTATE is what pgx surfaces to
// the caller, so it is scripted rather than left blank.
func apErrorResponse(code, message string) []byte {
	var payload []byte
	payload = append(payload, 'S')
	payload = append(payload, apCStr("ERROR")...)
	payload = append(payload, 'V')
	payload = append(payload, apCStr("ERROR")...)
	payload = append(payload, 'C')
	payload = append(payload, apCStr(code)...)
	payload = append(payload, 'M')
	payload = append(payload, apCStr(message)...)
	payload = append(payload, 0)
	return apMsg('E', payload)
}

// Column shapes reused by the scripted answers.
const (
	apOIDText        = 25
	apOIDInt4        = 23
	apOIDInt8        = 20
	apOIDBool        = 16
	apOIDTimestamptz = 1184
	apOIDJSONB       = 3802
	apOIDBytea       = 17
)

func apTextCol(name string) apCol { return apCol{name: name, oid: apOIDText, size: -1} }
