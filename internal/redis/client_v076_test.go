package redis

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// errWriter fails after allowing n successful bytes, used to drive the
// uncovered write-error branches in writeCommand.
type errWriter struct {
	remaining int
}

func (w *errWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("write failed")
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, errors.New("write failed")
	}
	w.remaining -= len(p)
	return len(p), nil
}

// writeCommand surfaces the underlying writer error during Flush.
func TestWriteCommand_FlushError(t *testing.T) {
	// Buffer larger than the payload so bytes are buffered and the error only
	// surfaces when Flush pushes them to the failing writer.
	w := bufio.NewWriterSize(&errWriter{remaining: 0}, 256)
	err := writeCommand(w, "PING")
	if err == nil {
		t.Fatal("expected flush error from writeCommand")
	}
}

// writeCommand surfaces an error mid-encode when a buffered write overflows the
// small buffer and the resulting flush hits the failing writer. A 16-byte
// buffer lets the array header buffer succeed, then fails inside the arg loop.
func TestWriteCommand_WriteError(t *testing.T) {
	w := bufio.NewWriterSize(&errWriter{remaining: 8}, 16)
	err := writeCommand(w, "SET", "longkey", "longvalue", "longerargument", "another")
	if err == nil {
		t.Fatal("expected write error from writeCommand")
	}
}

// mockRedisErr always replies with a Redis server error. exec must classify
// this as a ServerError and return the connection to the pool (not remove it).
type mockRedisErr struct {
	ln   net.Listener
	done chan struct{}
}

func newMockRedisErr(t *testing.T) *mockRedisErr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockRedisErr{ln: ln, done: make(chan struct{})}
	go m.serve()
	return m
}

func (m *mockRedisErr) addr() string { return m.ln.Addr().String() }
func (m *mockRedisErr) close()       { close(m.done); m.ln.Close() }

func (m *mockRedisErr) serve() {
	for {
		c, err := m.ln.Accept()
		if err != nil {
			select {
			case <-m.done:
				return
			default:
				continue
			}
		}
		go m.handle(c)
	}
}

func (m *mockRedisErr) handle(c net.Conn) {
	defer c.Close()
	rd := bufio.NewReader(c)
	wr := bufio.NewWriter(c)
	for {
		select {
		case <-m.done:
			return
		default:
		}
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		// Drain one command line (*N\r\n followed by bulk strings). We don't
		// need to fully parse it — read until we have consumed at least the
		// array header, then reply with a server error.
		line, err := rd.ReadBytes('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) {
				continue
			}
			return
		}
		if len(line) == 0 || line[0] != '*' {
			return
		}
		// Read the remaining bulk-string lines (2 lines per arg).
		// Parse arg count from "*N".
		n := 0
		for _, b := range line[1:] {
			if b < '0' || b > '9' {
				break
			}
			n = n*10 + int(b-'0')
		}
		for i := 0; i < n*2; i++ {
			if _, err := rd.ReadBytes('\n'); err != nil {
				return
			}
		}
		wr.WriteString("-WRONGTYPE Operation against a key holding the wrong kind of value\r\n")
		wr.Flush()
	}
}

// A server error (-WRONGTYPE) is a ServerError: exec returns it AND keeps the
// connection healthy in the pool. A follow-up command must still work.
func TestClient_Exec_RedisErrorKeepsConnection(t *testing.T) {
	m := newMockRedisErr(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr(), PoolSize: 1})
	defer c.Close()
	ctx := context.Background()

	_, err := c.Incr(ctx, "k")
	var redisErr *ServerError
	if !errors.As(err, &redisErr) {
		t.Fatalf("expected ServerError, got %T: %v", err, err)
	}

	// Connection was returned to the pool (put, not remove): the next command
	// reuses it and gets another server error rather than a dial error.
	_, err = c.Incr(ctx, "k2")
	if !errors.As(err, &redisErr) {
		t.Fatalf("second call: expected ServerError, got %T: %v", err, err)
	}

	if total := c.pool.total; total != 1 {
		t.Errorf("expected 1 pooled connection (reuse), got %d", total)
	}
}

// put discards the connection when the idle pool is already full. Building two
// live connections then returning both to a maxConns=1 pool forces the discard
// branch on the second put.
func TestPool_Put_DiscardsWhenFull(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr(), PoolSize: 2})
	defer c.Close()
	ctx := context.Background()

	// Acquire two connections concurrently so both are live (active), then the
	// pool only keeps maxConns idle — but we shrink maxConns to force discard.
	cn1, err := c.pool.get(ctx)
	if err != nil {
		t.Fatalf("get cn1: %v", err)
	}
	cn2, err := c.pool.get(ctx)
	if err != nil {
		t.Fatalf("get cn2: %v", err)
	}

	// Force the idle ceiling to 1 so the second put must discard.
	c.pool.maxConns = 1

	c.pool.put(cn1) // first put: appended to idle (len 0 < 1)
	c.pool.put(cn2) // second put: idle full -> discard branch

	c.pool.mu.Lock()
	idle := len(c.pool.idle)
	c.pool.mu.Unlock()
	if idle != 1 {
		t.Errorf("expected 1 idle connection after discard, got %d", idle)
	}
	if total := c.pool.total; total != 1 {
		t.Errorf("expected total 1 after discard, got %d", total)
	}
}

// dial returns a wrapped error when the TLS handshake target is unreachable,
// covering the TLS branch of dial.
func TestPool_Dial_TLSError(t *testing.T) {
	c := NewClient(&Options{
		Addr:        "127.0.0.1:1",
		TLS:         true,
		DialTimeout: 300 * time.Millisecond,
	})
	defer c.Close()

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected dial error for TLS to unreachable port")
	}
}
