package redis

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRedis is a RESP server that answers whatever a test tells it to. The dead-address
// and hang-up tests cover the connection failing; this covers the connection *working*
// and the server answering something the client must not accept — a wrong AUTH reply, a
// SELECT that did not take, a health check that comes back wrong. Those are handshake
// bugs, and they are invisible to a test that can only make the socket fail.
func startFakeRedis(t *testing.T, handle func(args []string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rd := bufio.NewReader(c)
				for {
					args, err := readRESPCommand(rd)
					if err != nil {
						return
					}
					reply := handle(args)
					if reply == "" {
						return // hang up
					}
					if _, err := c.Write([]byte(reply)); err != nil {
						return
					}
				}
			}(cn)
		}
	}()
	return ln.Addr().String()
}

// readRESPCommand parses one inline array of bulk strings, which is how a client sends
// every command.
func readRESPCommand(rd *bufio.Reader) ([]string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected array, got %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		if !strings.HasPrefix(hdr, "$") {
			return nil, fmt.Errorf("expected bulk string, got %q", hdr)
		}
		size, err := strconv.Atoi(hdr[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2) // payload + CRLF
		if _, err := io.ReadFull(rd, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

// A server that answers AUTH with anything other than OK has not authenticated us. The
// client must refuse the connection rather than carry on unauthenticated — every
// command after this point would run with whatever privileges the server left us.
func TestPool_AuthReplyThatIsNotOKIsRejected(t *testing.T) {
	addr := startFakeRedis(t, func(args []string) string {
		if len(args) > 0 && strings.EqualFold(args[0], "AUTH") {
			return "+NOPE\r\n" // a valid reply, but not an acceptance
		}
		return "+PONG\r\n"
	})

	c := NewClient(&Options{Addr: addr, Password: "hunter2", DialTimeout: time.Second, IOTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("a rejected AUTH was treated as success — the client would run unauthenticated")
	}
	if !strings.Contains(err.Error(), "auth") {
		t.Errorf("error %q does not identify the AUTH handshake as the failure", err)
	}
}

// SELECT chooses the database. If it silently did not take, every read and write would
// land in the wrong database — the client would appear to work while operating on
// somebody else's keyspace.
func TestPool_SelectReplyThatIsNotOKIsRejected(t *testing.T) {
	addr := startFakeRedis(t, func(args []string) string {
		if len(args) > 0 && strings.EqualFold(args[0], "SELECT") {
			return "+NOPE\r\n"
		}
		return "+PONG\r\n"
	})

	c := NewClient(&Options{Addr: addr, DB: 3, DialTimeout: time.Second, IOTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("a failed SELECT was treated as success — commands would run against the wrong database")
	}
	if !strings.Contains(err.Error(), "select") {
		t.Errorf("error %q does not identify SELECT as the failure", err)
	}
}

// Pooled connections are reused, and a reused connection is health-checked with a PING
// first. A connection that answers the health check with garbage is not healthy: it must
// be discarded and replaced, not handed to the caller.
func TestPool_UnhealthyIdleConnectionIsReplaced(t *testing.T) {
	var mu sync.Mutex
	pings := 0

	addr := startFakeRedis(t, func(args []string) string {
		if len(args) == 0 {
			return "+OK\r\n"
		}
		switch strings.ToUpper(args[0]) {
		case "PING":
			mu.Lock()
			pings++
			n := pings
			mu.Unlock()
			// The first PING is the caller's own Ping(). The second is the health check
			// on the reused connection — answer that one wrong.
			if n == 1 {
				return "+PONG\r\n"
			}
			return "+GARBAGE\r\n"
		case "GET":
			return "$-1\r\n" // nil
		}
		return "+OK\r\n"
	})

	c := NewClient(&Options{Addr: addr, DialTimeout: time.Second, IOTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("first ping should succeed: %v", err)
	}

	// The connection is now idle. This Get reuses it, the health check comes back
	// wrong, and the pool must dial a fresh connection rather than fail the call.
	if _, err := c.Get(ctx, "k"); err != nil && err != Nil {
		t.Fatalf("a stale pooled connection must be replaced, not surfaced to the caller: %v", err)
	}
}

// An idle connection older than the timeout must be dropped rather than reused. Redis
// closes idle connections server-side, so handing one back would produce a spurious
// failure on a perfectly healthy client.
func TestPool_IdleConnectionPastTimeoutIsDiscarded(t *testing.T) {
	addr := startFakeRedis(t, func(args []string) string {
		if len(args) > 0 && strings.EqualFold(args[0], "GET") {
			return "$-1\r\n"
		}
		return "+PONG\r\n"
	})

	c := NewClient(&Options{
		Addr:        addr,
		IdleTimeout: time.Millisecond,
		DialTimeout: time.Second,
		IOTimeout:   time.Second,
	})
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Let the pooled connection age past IdleTimeout.
	time.Sleep(25 * time.Millisecond)

	if _, err := c.Get(ctx, "k"); err != nil && err != Nil {
		t.Fatalf("an expired idle connection must be replaced transparently: %v", err)
	}
}
