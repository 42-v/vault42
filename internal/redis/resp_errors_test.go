package redis

import (
	"bufio"
	"errors"
	"testing"
)

// failingWriter fails after allowing n bytes through, so each write inside
// writeCommand can be made to be the one that breaks.
type failingWriter struct {
	remaining int
}

var errWriteFailed = errors.New("connection reset")

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, errWriteFailed
	}
	if len(p) > f.remaining {
		n := f.remaining
		f.remaining = 0
		return n, errWriteFailed
	}
	f.remaining -= len(p)
	return len(p), nil
}

// writeCommand encodes every command this client sends. A write error here means
// the connection died mid-command: the peer has received a truncated RESP frame,
// so the error must propagate and the connection must not be reused as if the
// command had been sent. Silently swallowing it would leave the client waiting
// for a reply to a command Redis never fully received.
func TestWriteCommand_PropagatesWriteErrors(t *testing.T) {
	// Fail at each successive point in the encoding: the array header, the length,
	// the terminator, the bulk marker, the argument, and the trailing CRLF.
	for _, budget := range []int{0, 1, 2, 3, 4, 5, 6, 8, 10} {
		w := bufio.NewWriterSize(&failingWriter{remaining: budget}, 1)
		err := writeCommand(w, "SET", "key", "value")
		if err == nil {
			// bufio may have buffered everything; force it out.
			err = w.Flush()
		}
		if err == nil {
			t.Errorf("budget %d: a failed write was reported as success", budget)
		}
	}
}

// The happy path must produce exactly the RESP wire format Redis expects —
// *N\r\n then $len\r\ndata\r\n per argument. A malformed frame here would be
// misparsed by the server rather than rejected.
func TestWriteCommand_Encoding(t *testing.T) {
	var buf capturingWriter
	w := bufio.NewWriter(&buf)
	if err := writeCommand(w, "SET", "k", "v"); err != nil {
		t.Fatalf("writeCommand: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"
	if got := string(buf); got != want {
		t.Errorf("frame = %q, want %q", got, want)
	}
}

type capturingWriter []byte

func (c *capturingWriter) Write(p []byte) (int, error) {
	*c = append(*c, p...)
	return len(p), nil
}
