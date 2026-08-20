package middleware

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"testing"
)

// ---------------------------------------------------------------------------
// Mock ResponseWriter implementations for testing Flush and Hijack
// ---------------------------------------------------------------------------

// plainWriter implements only http.ResponseWriter (no Flusher, no Hijacker).
type plainWriter struct {
	header     http.Header
	statusCode int
	written    []byte
}

func newPlainWriter() *plainWriter {
	return &plainWriter{header: make(http.Header)}
}

func (w *plainWriter) Header() http.Header  { return w.header }
func (w *plainWriter) WriteHeader(code int) { w.statusCode = code }
func (w *plainWriter) Write(b []byte) (int, error) {
	w.written = append(w.written, b...)
	return len(b), nil
}

// flushWriter implements http.ResponseWriter + http.Flusher.
type flushWriter struct {
	plainWriter
	flushed bool
}

func newFlushWriter() *flushWriter {
	return &flushWriter{plainWriter: plainWriter{header: make(http.Header)}}
}

func (w *flushWriter) Flush() { w.flushed = true }

// hijackWriter implements http.ResponseWriter + http.Hijacker.
type hijackWriter struct {
	plainWriter
	hijacked bool
	// Pre-configured return values for Hijack.
	conn net.Conn
	rw   *bufio.ReadWriter
	err  error
}

func newHijackWriter() *hijackWriter {
	return &hijackWriter{plainWriter: plainWriter{header: make(http.Header)}}
}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return w.conn, w.rw, w.err
}

// ---------------------------------------------------------------------------
// Tests for statusRecorder.Flush
// ---------------------------------------------------------------------------

func TestStatusRecorder_Flush_DelegatesToFlusher(t *testing.T) {
	fw := newFlushWriter()
	rec := &statusRecorder{ResponseWriter: fw, status: 200}

	rec.Flush()

	if !fw.flushed {
		t.Error("Flush should have delegated to the underlying http.Flusher")
	}
}

// The assertion here is that the call returns at all: a statusRecorder wrapping
// a writer with no Flush must swallow the call rather than type-assert its way
// into a panic, which would turn any flush on a non-flushable writer into a 500
// from Recovery. The status check afterwards pins the other half, that a
// swallowed flush does not quietly write a header.
func TestStatusRecorder_Flush_NoopWithoutFlusher(t *testing.T) {
	pw := newPlainWriter()
	rec := &statusRecorder{ResponseWriter: pw, status: 200}

	rec.Flush()

	if pw.statusCode != 0 {
		t.Errorf("underlying writer got status %d, want none written by a no-op flush", pw.statusCode)
	}
	if len(pw.written) != 0 {
		t.Errorf("underlying writer got %d bytes, want none written by a no-op flush", len(pw.written))
	}
}

// ---------------------------------------------------------------------------
// Tests for statusRecorder.Hijack
// ---------------------------------------------------------------------------

func TestStatusRecorder_Hijack_DelegatesToHijacker(t *testing.T) {
	hw := newHijackWriter()
	rec := &statusRecorder{ResponseWriter: hw, status: 200}

	conn, rw, err := rec.Hijack()
	if err != nil {
		t.Fatalf("Hijack returned unexpected error: %v", err)
	}
	if !hw.hijacked {
		t.Error("Hijack should have delegated to the underlying http.Hijacker")
	}
	// The mock returns nil values; verify they pass through.
	if conn != nil {
		t.Error("expected nil conn from mock")
	}
	if rw != nil {
		t.Error("expected nil ReadWriter from mock")
	}
}

func TestStatusRecorder_Hijack_ErrorWithoutHijacker(t *testing.T) {
	pw := newPlainWriter()
	rec := &statusRecorder{ResponseWriter: pw, status: 200}

	conn, rw, err := rec.Hijack()

	if err == nil {
		t.Fatal("Hijack should return an error when underlying writer is not a Hijacker")
	}
	if conn != nil {
		t.Error("expected nil conn on error")
	}
	if rw != nil {
		t.Error("expected nil ReadWriter on error")
	}

	// Verify the error message is descriptive.
	expected := "underlying ResponseWriter does not implement http.Hijacker"
	if err.Error() != expected {
		t.Errorf("error message = %q, want %q", err.Error(), expected)
	}
}

func TestStatusRecorder_Hijack_PropagatesError(t *testing.T) {
	hw := newHijackWriter()
	hw.err = errors.New("hijack failed: connection reset")
	rec := &statusRecorder{ResponseWriter: hw, status: 200}

	conn, rw, err := rec.Hijack()

	if err == nil {
		t.Fatal("expected error to propagate from underlying Hijacker")
	}
	if err.Error() != "hijack failed: connection reset" {
		t.Errorf("error = %q, want 'hijack failed: connection reset'", err.Error())
	}
	if conn != nil {
		t.Error("expected nil conn on error")
	}
	if rw != nil {
		t.Error("expected nil ReadWriter on error")
	}
}
