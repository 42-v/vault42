package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// mockRedisWithEval extends the base mock to handle EVAL commands.
// We use a fresh mock rather than modifying the existing one.
// ---------------------------------------------------------------------------

type mockRedisEval struct {
	ln   net.Listener
	done chan struct{}
}

func newMockRedisEval(t *testing.T) *mockRedisEval {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockRedisEval{ln: ln, done: make(chan struct{})}
	go m.serve()
	return m
}

func (m *mockRedisEval) addr() string { return m.ln.Addr().String() }

func (m *mockRedisEval) close() {
	close(m.done)
	m.ln.Close()
}

func (m *mockRedisEval) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			select {
			case <-m.done:
				return
			default:
				continue
			}
		}
		go m.handleConn(conn)
	}
}

func (m *mockRedisEval) handleConn(c net.Conn) {
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
		args, err := m.readCommand(rd)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) {
				continue
			}
			return
		}
		if len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "PING":
			fmt.Fprintf(wr, "+PONG\r\n")
		case "EVAL":
			// Return the numkeys value as the integer result for testing.
			// args: EVAL <script> <numkeys> [key ...] [arg ...]
			if len(args) < 3 {
				fmt.Fprintf(wr, "-ERR wrong number of arguments for 'eval' command\r\n")
			} else {
				numkeys, _ := strconv.Atoi(args[2])
				fmt.Fprintf(wr, ":%d\r\n", numkeys)
			}
		default:
			fmt.Fprintf(wr, "-ERR unknown command '%s'\r\n", cmd)
		}
		wr.Flush()
	}
}

func (m *mockRedisEval) readCommand(rd *bufio.Reader) ([]string, error) {
	line, err := rd.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	line = line[:len(line)-2] // strip \r\n

	if line[0] != '*' {
		return nil, fmt.Errorf("expected array, got %c", line[0])
	}
	n, err := strconv.Atoi(string(line[1:]))
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		line, err = rd.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		line = line[:len(line)-2]
		if line[0] != '$' {
			return nil, fmt.Errorf("expected bulk string, got %c", line[0])
		}
		argLen, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, argLen+2)
		if _, err := rd.Read(buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:argLen]))
	}
	return args, nil
}

// ---------------------------------------------------------------------------
// Eval tests
// ---------------------------------------------------------------------------

func TestClient_Eval_Success(t *testing.T) {
	m := newMockRedisEval(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()

	// The mock returns numkeys as the integer result.
	result, err := c.Eval(context.Background(), "return 1", 2, "key1", "key2", "arg1")
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if result != 2 {
		t.Errorf("Eval result = %d, want 2", result)
	}
}

func TestClient_Eval_NoArgs(t *testing.T) {
	m := newMockRedisEval(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()

	result, err := c.Eval(context.Background(), "return 0", 0)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if result != 0 {
		t.Errorf("Eval result = %d, want 0", result)
	}
}

func TestClient_Eval_ClosedClient(t *testing.T) {
	m := newMockRedisEval(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	c.Close()

	_, err := c.Eval(context.Background(), "return 1", 0)
	if err == nil {
		t.Fatal("expected error from Eval on closed client")
	}
}

func TestClient_Eval_CanceledContext(t *testing.T) {
	m := newMockRedisEval(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Eval(ctx, "return 1", 0)
	if err == nil {
		t.Fatal("expected error from Eval with canceled context")
	}
}

func TestClient_Eval_BadServer(t *testing.T) {
	c := NewClient(&Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 200 * time.Millisecond,
	})
	defer c.Close()

	_, err := c.Eval(context.Background(), "return 1", 0)
	if err == nil {
		t.Fatal("expected error from Eval with unreachable server")
	}
}

// ---------------------------------------------------------------------------
// reapIdle tests
// ---------------------------------------------------------------------------

func TestPool_ReapIdle_RemovesStalConnections(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:        m.addr(),
		PoolSize:    5,
		IdleTimeout: 50 * time.Millisecond, // very short for testing
	})
	defer c.Close()

	ctx := context.Background()

	// Create some connections by issuing pings.
	for i := 0; i < 3; i++ {
		if err := c.Ping(ctx); err != nil {
			t.Fatalf("Ping %d: %v", i, err)
		}
	}

	// Verify idle connections exist.
	c.pool.mu.Lock()
	idleBefore := len(c.pool.idle)
	c.pool.mu.Unlock()
	if idleBefore == 0 {
		t.Fatal("expected at least one idle connection before reap")
	}

	// Wait for idle timeout to expire.
	time.Sleep(100 * time.Millisecond)

	// Manually trigger reapIdle (normally called by the reaper goroutine).
	c.pool.reapIdle()

	// All idle connections should have been reaped.
	c.pool.mu.Lock()
	idleAfter := len(c.pool.idle)
	c.pool.mu.Unlock()
	if idleAfter != 0 {
		t.Errorf("expected 0 idle connections after reap, got %d", idleAfter)
	}
}

func TestPool_ReapIdle_KeepsFreshConnections(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:        m.addr(),
		PoolSize:    5,
		IdleTimeout: 10 * time.Second, // long timeout — nothing should be reaped
	})
	defer c.Close()

	ctx := context.Background()

	// Create a connection.
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	c.pool.mu.Lock()
	idleBefore := len(c.pool.idle)
	c.pool.mu.Unlock()
	if idleBefore == 0 {
		t.Fatal("expected at least one idle connection")
	}

	// Immediately reap — nothing should be removed.
	c.pool.reapIdle()

	c.pool.mu.Lock()
	idleAfter := len(c.pool.idle)
	c.pool.mu.Unlock()
	if idleAfter != idleBefore {
		t.Errorf("reapIdle removed fresh connections: before=%d, after=%d", idleBefore, idleAfter)
	}
}

func TestPool_ReapIdle_DefaultTimeout(t *testing.T) {
	// When IdleTimeout is zero, reapIdle should use the default (5 minutes).
	// Fresh connections should not be reaped with the default timeout.
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:        m.addr(),
		PoolSize:    5,
		IdleTimeout: 0, // zero triggers defaultIdleTimeout
	})
	defer c.Close()

	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	c.pool.mu.Lock()
	idleBefore := len(c.pool.idle)
	c.pool.mu.Unlock()

	c.pool.reapIdle()

	c.pool.mu.Lock()
	idleAfter := len(c.pool.idle)
	c.pool.mu.Unlock()

	if idleAfter != idleBefore {
		t.Errorf("reapIdle with default timeout removed fresh connections: before=%d, after=%d", idleBefore, idleAfter)
	}
}

func TestPool_ReapIdle_TotalCountDecremented(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:        m.addr(),
		PoolSize:    5,
		IdleTimeout: 50 * time.Millisecond,
	})
	defer c.Close()

	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	totalBefore := atomic.LoadInt32(&c.pool.total)
	if totalBefore == 0 {
		t.Fatal("expected non-zero total before reap")
	}

	// Wait for idle timeout.
	time.Sleep(100 * time.Millisecond)

	c.pool.reapIdle()

	totalAfter := atomic.LoadInt32(&c.pool.total)
	if totalAfter >= totalBefore {
		t.Errorf("total connections should have decreased: before=%d, after=%d", totalBefore, totalAfter)
	}
}

func TestPool_ReapIdle_EmptyPool(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:        m.addr(),
		PoolSize:    5,
		IdleTimeout: 50 * time.Millisecond,
	})
	defer c.Close()

	// Call reapIdle on an empty pool — should not panic.
	c.pool.reapIdle()

	c.pool.mu.Lock()
	idleAfter := len(c.pool.idle)
	c.pool.mu.Unlock()
	if idleAfter != 0 {
		t.Errorf("expected 0 idle connections, got %d", idleAfter)
	}
}
