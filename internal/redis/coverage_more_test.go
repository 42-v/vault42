package redis

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedServer is a single-connection mock that replies to every command with
// a fixed raw RESP payload. It lets tests drive client reply-handling branches
// (unexpected status, nil bulk, server error) without a live Redis.
type scriptedServer struct {
	ln    net.Listener
	reply string
	done  chan struct{}
}

func newScriptedServer(t *testing.T, reply string) *scriptedServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &scriptedServer{ln: ln, reply: reply, done: make(chan struct{})}
	go s.serve()
	return s
}

func (s *scriptedServer) addr() string { return s.ln.Addr().String() }
func (s *scriptedServer) close()       { close(s.done); s.ln.Close() }

func (s *scriptedServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}
		go s.handle(c)
	}
}

func (s *scriptedServer) handle(c net.Conn) {
	defer c.Close()
	rd := bufio.NewReader(c)
	wr := bufio.NewWriter(c)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		// Read the array header for one command, then drain its bulk-string
		// argument lines so the client's writer doesn't block.
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
		n := 0
		for _, b := range line[1 : len(line)-2] {
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
		wr.WriteString(s.reply)
		wr.Flush()
	}
}

// Ping treats a status reply other than PONG as a protocol error.
func TestPing_UnexpectedReply(t *testing.T) {
	s := newScriptedServer(t, "+WRONG\r\n")
	defer s.close()

	c := NewClient(&Options{Addr: s.addr()})
	defer c.Close()

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected error for non-PONG ping reply")
	}
	if !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("expected unexpected-reply error, got %v", err)
	}
}

// Set treats a status reply other than OK as a protocol error.
func TestSet_UnexpectedReply(t *testing.T) {
	s := newScriptedServer(t, "+NOPE\r\n")
	defer s.close()

	c := NewClient(&Options{Addr: s.addr()})
	defer c.Close()

	err := c.Set(context.Background(), "k", "v", 0)
	if err == nil {
		t.Fatal("expected error for non-OK set reply")
	}
	if !strings.Contains(err.Error(), "set") {
		t.Fatalf("expected set error, got %v", err)
	}
}

// Get maps a nil bulk reply ($-1) to the sentinel Nil error, exercising the
// nil-classification branch in exec.
func TestGet_NilReplyMapsToNil(t *testing.T) {
	s := newScriptedServer(t, "$-1\r\n")
	defer s.close()

	c := NewClient(&Options{Addr: s.addr()})
	defer c.Close()

	_, err := c.Get(context.Background(), "missing")
	if !errors.Is(err, Nil) {
		t.Fatalf("expected Nil, got %v", err)
	}
}

// A server error reply propagates out of GetDel as a RedisError.
func TestGetDel_ServerError(t *testing.T) {
	s := newScriptedServer(t, "-ERR boom\r\n")
	defer s.close()

	c := NewClient(&Options{Addr: s.addr()})
	defer c.Close()

	_, err := c.GetDel(context.Background(), "k")
	var redisErr *RedisError
	if !errors.As(err, &redisErr) {
		t.Fatalf("expected RedisError, got %T: %v", err, err)
	}
}

// dial fails the connection when SELECT is requested (DB > 0) and the server
// rejects it, covering the initSelect error path inside dial.
func TestDial_SelectRejected(t *testing.T) {
	s := newScriptedServer(t, "-ERR no such db\r\n")
	defer s.close()

	c := NewClient(&Options{Addr: s.addr(), DB: 3})
	defer c.Close()

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected dial failure when SELECT is rejected")
	}
	if !strings.Contains(err.Error(), "select") {
		t.Fatalf("expected select error, got %v", err)
	}
}

// dial fails when AUTH is requested but the server rejects the password,
// covering the initAuth error path inside dial.
func TestDial_AuthRejected(t *testing.T) {
	s := newScriptedServer(t, "-WRONGPASS invalid\r\n")
	defer s.close()

	c := NewClient(&Options{Addr: s.addr(), Password: "x"})
	defer c.Close()

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected dial failure when AUTH is rejected")
	}
	if !strings.Contains(err.Error(), "auth") {
		t.Fatalf("expected auth error, got %v", err)
	}
}

// put on a closed pool tears the connection down and releases its slot instead
// of returning it to the idle list.
func TestPut_ClosedPoolDiscards(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr(), PoolSize: 1})
	ctx := context.Background()

	cn, err := c.pool.get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// Close the pool while the connection is checked out, then return it.
	go func() { c.pool.close() }()
	// Give close() a moment to flip the closed flag before put runs.
	for i := 0; i < 100; i++ {
		if atomicClosed(c.pool) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c.pool.put(cn)

	c.pool.mu.Lock()
	idle := len(c.pool.idle)
	c.pool.mu.Unlock()
	if idle != 0 {
		t.Fatalf("expected closed pool to discard connection, idle=%d", idle)
	}
}

// readReply rejects an empty status line as a protocol error.
func TestReadReply_EmptyLine(t *testing.T) {
	rd := bufio.NewReader(strings.NewReader("\r\n"))
	_, err := readReply(rd)
	if err == nil {
		t.Fatal("expected error for empty response line")
	}
}

// readReply rejects a bulk string whose declared length exceeds the 64 MiB cap.
func TestReadReply_BulkTooLarge(t *testing.T) {
	rd := bufio.NewReader(strings.NewReader("$67108865\r\n"))
	_, err := readReply(rd)
	if err == nil {
		t.Fatal("expected error for oversized bulk length")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too-large error, got %v", err)
	}
}

// exec shortens its I/O deadline to a context deadline that is nearer than
// IOTimeout; with no server reply this surfaces as a deadline error rather than
// waiting the full IOTimeout.
func TestExec_ContextDeadlineShortensTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // accept but never reply
		}
	}()

	c := NewClient(&Options{Addr: ln.Addr().String(), IOTimeout: 10 * time.Second})
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = c.Ping(ctx)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected deadline error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected context deadline to shorten wait, took %v", elapsed)
	}
}

func atomicClosed(p *pool) bool {
	return atomic.LoadInt32(&p.closed) == 1
}
