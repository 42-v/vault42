package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockRedis is a minimal Redis server for testing.
// It listens on a random TCP port and handles RESP commands.
type mockRedis struct {
	ln      net.Listener
	mu      sync.Mutex
	data    map[string]mockEntry
	done    chan struct{}
	wg      sync.WaitGroup
	authPwd string // required password (empty = no auth)
}

type mockEntry struct {
	value     string
	expiresAt time.Time
}

func newMockRedis(t *testing.T) *mockRedis {
	return newMockRedisWithAuth(t, "")
}

func newMockRedisWithAuth(t *testing.T, password string) *mockRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockRedis{
		ln:      ln,
		data:    make(map[string]mockEntry),
		done:    make(chan struct{}),
		authPwd: password,
	}
	m.wg.Add(1)
	go m.serve()
	return m
}

func (m *mockRedis) addr() string { return m.ln.Addr().String() }

func (m *mockRedis) close() {
	close(m.done)
	m.ln.Close()
	m.wg.Wait()
}

func (m *mockRedis) serve() {
	defer m.wg.Done()
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
		m.wg.Add(1)
		go m.handleConn(conn)
	}
}

func (m *mockRedis) handleConn(c net.Conn) {
	defer m.wg.Done()
	defer c.Close()

	rd := bufio.NewReader(c)
	wr := bufio.NewWriter(c)
	authed := m.authPwd == "" // no password = already authed

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

		// AUTH required check
		if !authed && cmd != "AUTH" {
			fmt.Fprintf(wr, "-NOAUTH Authentication required\r\n")
			wr.Flush()
			continue
		}

		switch cmd {
		case "AUTH":
			if len(args) < 2 {
				fmt.Fprintf(wr, "-ERR wrong number of arguments for 'auth' command\r\n")
			} else if args[1] != m.authPwd {
				fmt.Fprintf(wr, "-ERR invalid password\r\n")
			} else {
				authed = true
				fmt.Fprintf(wr, "+OK\r\n")
			}
		case "PING":
			fmt.Fprintf(wr, "+PONG\r\n")
		case "SELECT":
			fmt.Fprintf(wr, "+OK\r\n")
		case "GET":
			if len(args) < 2 {
				fmt.Fprintf(wr, "-ERR wrong number of arguments\r\n")
			} else {
				m.mu.Lock()
				e, ok := m.data[args[1]]
				if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
					if ok {
						delete(m.data, args[1])
					}
					m.mu.Unlock()
					fmt.Fprintf(wr, "$-1\r\n")
				} else {
					m.mu.Unlock()
					fmt.Fprintf(wr, "$%d\r\n%s\r\n", len(e.value), e.value)
				}
			}
		case "SET":
			m.handleSet(args, wr)
		case "DEL":
			m.mu.Lock()
			count := 0
			for _, key := range args[1:] {
				if _, ok := m.data[key]; ok {
					delete(m.data, key)
					count++
				}
			}
			m.mu.Unlock()
			fmt.Fprintf(wr, ":%d\r\n", count)
		case "GETDEL":
			if len(args) < 2 {
				fmt.Fprintf(wr, "-ERR wrong number of arguments\r\n")
			} else {
				m.mu.Lock()
				e, ok := m.data[args[1]]
				if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
					if ok {
						delete(m.data, args[1])
					}
					m.mu.Unlock()
					fmt.Fprintf(wr, "$-1\r\n")
				} else {
					delete(m.data, args[1])
					m.mu.Unlock()
					fmt.Fprintf(wr, "$%d\r\n%s\r\n", len(e.value), e.value)
				}
			}
		case "INCR":
			if len(args) < 2 {
				fmt.Fprintf(wr, "-ERR wrong number of arguments\r\n")
			} else {
				m.mu.Lock()
				e, ok := m.data[args[1]]
				var val int64
				if ok && (e.expiresAt.IsZero() || time.Now().Before(e.expiresAt)) {
					val, _ = strconv.ParseInt(e.value, 10, 64)
				}
				val++
				m.data[args[1]] = mockEntry{
					value:     strconv.FormatInt(val, 10),
					expiresAt: e.expiresAt,
				}
				m.mu.Unlock()
				fmt.Fprintf(wr, ":%d\r\n", val)
			}
		case "EXPIRE":
			if len(args) < 3 {
				fmt.Fprintf(wr, "-ERR wrong number of arguments\r\n")
			} else {
				secs, _ := strconv.Atoi(args[2])
				m.mu.Lock()
				e, ok := m.data[args[1]]
				if ok {
					e.expiresAt = time.Now().Add(time.Duration(secs) * time.Second)
					m.data[args[1]] = e
					m.mu.Unlock()
					fmt.Fprintf(wr, ":1\r\n")
				} else {
					m.mu.Unlock()
					fmt.Fprintf(wr, ":0\r\n")
				}
			}
		case "EXISTS":
			if len(args) < 2 {
				fmt.Fprintf(wr, "-ERR wrong number of arguments\r\n")
			} else {
				m.mu.Lock()
				e, ok := m.data[args[1]]
				if ok && (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
					delete(m.data, args[1])
					ok = false
				}
				m.mu.Unlock()
				if ok {
					fmt.Fprintf(wr, ":1\r\n")
				} else {
					fmt.Fprintf(wr, ":0\r\n")
				}
			}
		default:
			fmt.Fprintf(wr, "-ERR unknown command '%s'\r\n", cmd)
		}
		wr.Flush()
	}
}

func (m *mockRedis) handleSet(args []string, wr *bufio.Writer) {
	if len(args) < 3 {
		fmt.Fprintf(wr, "-ERR wrong number of arguments for 'set' command\r\n")
		return
	}

	key := args[1]
	value := args[2]
	var ttl time.Duration
	nx := false

	// Parse optional arguments
	for i := 3; i < len(args); i++ {
		switch strings.ToUpper(args[i]) {
		case "EX":
			if i+1 < len(args) {
				i++
				secs, _ := strconv.Atoi(args[i])
				ttl = time.Duration(secs) * time.Second
			}
		case "PX":
			if i+1 < len(args) {
				i++
				ms, _ := strconv.Atoi(args[i])
				ttl = time.Duration(ms) * time.Millisecond
			}
		case "NX":
			nx = true
		}
	}

	m.mu.Lock()
	if nx {
		e, ok := m.data[key]
		if ok && (e.expiresAt.IsZero() || time.Now().Before(e.expiresAt)) {
			m.mu.Unlock()
			// NX condition not met — return nil
			fmt.Fprintf(wr, "$-1\r\n")
			return
		}
	}

	entry := mockEntry{value: value}
	if ttl > 0 {
		entry.expiresAt = time.Now().Add(ttl)
	}
	m.data[key] = entry
	m.mu.Unlock()
	fmt.Fprintf(wr, "+OK\r\n")
}

// readCommand reads a RESP array command from the reader.
func (m *mockRedis) readCommand(rd *bufio.Reader) ([]string, error) {
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
		// Read $<len>\r\n
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
		// Read <data>\r\n
		buf := make([]byte, argLen+2)
		if _, err := rd.Read(buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:argLen]))
	}
	return args, nil
}

// ---------------------------------------------------------------------------
// Client tests using mock server
// ---------------------------------------------------------------------------

func TestClient_Ping(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestClient_GetSet(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	// Set a value
	if err := c.Set(ctx, "hello", "world", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Get it back
	val, err := c.Get(ctx, "hello")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "world" {
		t.Errorf("expected 'world', got %q", val)
	}
}

func TestClient_Get_NotFound(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()

	_, err := c.Get(context.Background(), "nonexistent")
	if !errors.Is(err, Nil) {
		t.Fatalf("expected Nil error, got %v", err)
	}
}

func TestClient_Set_WithTTL(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	// Set with EX (seconds)
	if err := c.Set(ctx, "ttl-key", "val", 60*time.Second); err != nil {
		t.Fatalf("Set with TTL: %v", err)
	}
	val, err := c.Get(ctx, "ttl-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "val" {
		t.Errorf("expected 'val', got %q", val)
	}
}

func TestClient_Set_WithSubSecondTTL(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	// Set with PX (milliseconds)
	if err := c.Set(ctx, "px-key", "val", 500*time.Millisecond); err != nil {
		t.Fatalf("Set with PX: %v", err)
	}
	val, err := c.Get(ctx, "px-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "val" {
		t.Errorf("expected 'val', got %q", val)
	}
}

func TestClient_Set_EmptyValue(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "empty", "", 0); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	val, err := c.Get(ctx, "empty")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "" {
		t.Errorf("expected empty string, got %q", val)
	}
}

func TestClient_Set_Overwrite(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "ow", "first", 0); err != nil {
		t.Fatalf("Set first: %v", err)
	}
	if err := c.Set(ctx, "ow", "second", 0); err != nil {
		t.Fatalf("Set second: %v", err)
	}
	val, err := c.Get(ctx, "ow")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "second" {
		t.Errorf("expected 'second', got %q", val)
	}
}

func TestClient_Del(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "del-me", "bye", 0)

	n, err := c.Del(ctx, "del-me")
	if err != nil {
		t.Fatalf("Del: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 deleted, got %d", n)
	}

	// Verify deleted
	_, err = c.Get(ctx, "del-me")
	if !errors.Is(err, Nil) {
		t.Fatalf("expected Nil after delete, got %v", err)
	}
}

func TestClient_Del_NonExistent(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()

	n, err := c.Del(context.Background(), "no-such-key")
	if err != nil {
		t.Fatalf("Del: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestClient_GetDel(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	c.Set(ctx, "gd-key", "onetime", 0)

	val, err := c.GetDel(ctx, "gd-key")
	if err != nil {
		t.Fatalf("GetDel: %v", err)
	}
	if val != "onetime" {
		t.Errorf("expected 'onetime', got %q", val)
	}

	// Verify deleted
	_, err = c.Get(ctx, "gd-key")
	if !errors.Is(err, Nil) {
		t.Fatalf("expected Nil after GetDel, got %v", err)
	}
}

func TestClient_GetDel_NotFound(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()

	_, err := c.GetDel(context.Background(), "nope")
	if !errors.Is(err, Nil) {
		t.Fatalf("expected Nil, got %v", err)
	}
}

func TestClient_SetNX(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	t.Run("key does not exist", func(t *testing.T) {
		ok, err := c.SetNX(ctx, "nx-key", "val", 0)
		if err != nil {
			t.Fatalf("SetNX: %v", err)
		}
		if !ok {
			t.Error("expected true (key was set)")
		}
	})

	t.Run("key already exists", func(t *testing.T) {
		ok, err := c.SetNX(ctx, "nx-key", "val2", 0)
		if err != nil {
			t.Fatalf("SetNX: %v", err)
		}
		if ok {
			t.Error("expected false (key already exists)")
		}
		// Verify original value unchanged
		val, _ := c.Get(ctx, "nx-key")
		if val != "val" {
			t.Errorf("expected 'val', got %q", val)
		}
	})

	t.Run("with TTL", func(t *testing.T) {
		ok, err := c.SetNX(ctx, "nx-ttl", "temp", 60*time.Second)
		if err != nil {
			t.Fatalf("SetNX with TTL: %v", err)
		}
		if !ok {
			t.Error("expected true")
		}
	})

	t.Run("with sub-second TTL", func(t *testing.T) {
		ok, err := c.SetNX(ctx, "nx-ms", "temp", 500*time.Millisecond)
		if err != nil {
			t.Fatalf("SetNX with PX: %v", err)
		}
		if !ok {
			t.Error("expected true")
		}
	})
}

func TestClient_Incr(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	t.Run("first increment", func(t *testing.T) {
		val, err := c.Incr(ctx, "counter")
		if err != nil {
			t.Fatalf("Incr: %v", err)
		}
		if val != 1 {
			t.Errorf("expected 1, got %d", val)
		}
	})

	t.Run("multiple increments", func(t *testing.T) {
		for i := int64(2); i <= 5; i++ {
			val, err := c.Incr(ctx, "counter")
			if err != nil {
				t.Fatalf("Incr: %v", err)
			}
			if val != i {
				t.Errorf("expected %d, got %d", i, val)
			}
		}
	})
}

func TestClient_Expire(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	t.Run("existing key", func(t *testing.T) {
		c.Set(ctx, "exp-key", "val", 0)
		ok, err := c.Expire(ctx, "exp-key", 60*time.Second)
		if err != nil {
			t.Fatalf("Expire: %v", err)
		}
		if !ok {
			t.Error("expected true for existing key")
		}
	})

	t.Run("non-existent key", func(t *testing.T) {
		ok, err := c.Expire(ctx, "no-key", 60*time.Second)
		if err != nil {
			t.Fatalf("Expire: %v", err)
		}
		if ok {
			t.Error("expected false for non-existent key")
		}
	})
}

func TestClient_Exists(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	t.Run("key exists", func(t *testing.T) {
		c.Set(ctx, "ex-key", "val", 0)
		ok, err := c.Exists(ctx, "ex-key")
		if err != nil {
			t.Fatalf("Exists: %v", err)
		}
		if !ok {
			t.Error("expected true")
		}
	})

	t.Run("key does not exist", func(t *testing.T) {
		ok, err := c.Exists(ctx, "no-key")
		if err != nil {
			t.Fatalf("Exists: %v", err)
		}
		if ok {
			t.Error("expected false")
		}
	})
}

func TestClient_Close(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Operations after close should fail
	_, err := c.Get(context.Background(), "key")
	if err == nil {
		t.Fatal("expected error after close")
	}
}

func TestClient_DoubleClose(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	c.Close()
	err := c.Close()
	if err == nil {
		t.Fatal("expected error on double close")
	}
}

func TestClient_BadAddr(t *testing.T) {
	c := NewClient(&Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 500 * time.Millisecond,
	})
	defer c.Close()

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected error for bad address")
	}
}

func TestClient_ContextCanceled(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := c.Get(ctx, "key")
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestClient_ContextTimeout(t *testing.T) {
	// Create a listener that accepts but never responds
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept connections but do nothing
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open but don't respond
			defer conn.Close()
		}
	}()

	c := NewClient(&Options{
		Addr:      ln.Addr().String(),
		IOTimeout: 200 * time.Millisecond,
	})
	defer c.Close()

	start := time.Now()
	err = c.Ping(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	// Should timeout relatively quickly
	if elapsed > 5*time.Second {
		t.Errorf("took %v, expected faster timeout", elapsed)
	}
}

func TestClient_WithAuth(t *testing.T) {
	m := newMockRedisWithAuth(t, "secret123")
	defer m.close()

	t.Run("correct password", func(t *testing.T) {
		c := NewClient(&Options{
			Addr:     m.addr(),
			Password: "secret123",
		})
		defer c.Close()

		if err := c.Ping(context.Background()); err != nil {
			t.Fatalf("Ping with auth: %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		c := NewClient(&Options{
			Addr:     m.addr(),
			Password: "wrong",
		})
		defer c.Close()

		err := c.Ping(context.Background())
		if err == nil {
			t.Fatal("expected auth error")
		}
	})
}

func TestClient_WithDB(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr: m.addr(),
		DB:   5,
	})
	defer c.Close()

	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping with DB: %v", err)
	}
}

func TestClient_LargeValue(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	// 10KB value
	large := strings.Repeat("x", 10000)
	if err := c.Set(ctx, "large", large, 0); err != nil {
		t.Fatalf("Set large: %v", err)
	}
	val, err := c.Get(ctx, "large")
	if err != nil {
		t.Fatalf("Get large: %v", err)
	}
	if len(val) != 10000 {
		t.Errorf("expected length 10000, got %d", len(val))
	}
}

func TestClient_ConcurrentAccess(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:     m.addr(),
		PoolSize: 5,
	})
	defer c.Close()
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("concurrent-%d", i)
			val := fmt.Sprintf("value-%d", i)
			if err := c.Set(ctx, key, val, 0); err != nil {
				errs <- fmt.Errorf("Set %s: %w", key, err)
				return
			}
			got, err := c.Get(ctx, key)
			if err != nil {
				errs <- fmt.Errorf("Get %s: %w", key, err)
				return
			}
			if got != val {
				errs <- fmt.Errorf("Get %s: expected %q, got %q", key, val, got)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestClient_SetTTLExpiry(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{Addr: m.addr()})
	defer c.Close()
	ctx := context.Background()

	// Set with short PX TTL
	if err := c.Set(ctx, "short-ttl", "temp", 100*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Should exist immediately
	val, err := c.Get(ctx, "short-ttl")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "temp" {
		t.Errorf("expected 'temp', got %q", val)
	}

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Should be gone
	_, err = c.Get(ctx, "short-ttl")
	if !errors.Is(err, Nil) {
		t.Fatalf("expected Nil after expiry, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error tests
// ---------------------------------------------------------------------------

func TestNilError(t *testing.T) {
	if Nil.Error() != "redis: nil" {
		t.Errorf("expected 'redis: nil', got %q", Nil.Error())
	}

	var err error = Nil
	if !errors.Is(err, Nil) {
		t.Error("errors.Is should match Nil")
	}
}

func TestRedisError(t *testing.T) {
	err := &RedisError{Msg: "ERR bad command"}
	if err.Error() != "redis: ERR bad command" {
		t.Errorf("expected 'redis: ERR bad command', got %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Pool tests
// ---------------------------------------------------------------------------

func TestPool_MaxConnections(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:     m.addr(),
		PoolSize: 2,
	})
	defer c.Close()
	ctx := context.Background()

	// Should handle requests up to pool size smoothly
	for i := 0; i < 10; i++ {
		if err := c.Ping(ctx); err != nil {
			t.Fatalf("Ping %d: %v", i, err)
		}
	}
}

func TestPool_ConnectionReuse(t *testing.T) {
	m := newMockRedis(t)
	defer m.close()

	c := NewClient(&Options{
		Addr:     m.addr(),
		PoolSize: 1,
	})
	defer c.Close()
	ctx := context.Background()

	// Multiple sequential operations should reuse the same connection
	for i := 0; i < 5; i++ {
		if err := c.Ping(ctx); err != nil {
			t.Fatalf("Ping %d: %v", i, err)
		}
	}

	// Pool should have at most 1 connection
	total := c.pool.total
	if total > 1 {
		t.Errorf("expected at most 1 connection, got %d", total)
	}
}

// ---------------------------------------------------------------------------
// $-1 (key not found) is a successful reply, never an exec error
// ---------------------------------------------------------------------------

// nilReplyAddr serves a Redis that answers every command with the RESP nil bulk
// string, `$-1`. That is what a real server sends for GET on a missing key, for
// GETDEL on a consumed one, and for SET ... NX when the key already exists.
func nilReplyAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				rd := bufio.NewReader(c)
				wr := bufio.NewWriter(c)
				frames := &mockRedis{}
				for {
					if _, err := frames.readCommand(rd); err != nil {
						return
					}
					if _, err := wr.WriteString("$-1\r\n"); err != nil {
						return
					}
					if err := wr.Flush(); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// exec once carried a branch that treated a Nil error from readReply as a
// healthy connection. No input reaches it: readReply turns `$-1` into
// reply{isNil: true} with a nil error, and the Nil sentinel is minted by Get and
// GetDel from r.isNil after exec has already returned. This pins that contract
// from the wire up, so the branch cannot be reintroduced as "defensive".
func TestClient_NilBulkReplyIsNotAnExecError(t *testing.T) {
	c := NewClient(&Options{
		Addr:        nilReplyAddr(t),
		PoolSize:    1,
		DialTimeout: time.Second,
		IOTimeout:   time.Second,
	})
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	cn, err := c.pool.get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	r, err := c.exec(ctx, cn, "GET", "missing")
	if err != nil {
		t.Fatalf("exec surfaced a missing key as an error: %v", err)
	}
	if !r.isNil {
		t.Error("nil-ness did not come back in the reply struct")
	}

	// A nil reply is the success path, so the connection is returned to the
	// pool rather than torn down: the deleted branch and the one below it did
	// the same thing for different reasons.
	if total := atomic.LoadInt32(&c.pool.total); total != 1 {
		t.Errorf("pool total = %d after a nil reply, want 1", total)
	}
	if active := atomic.LoadInt32(&c.pool.active); active != 0 {
		t.Errorf("pool active = %d after a nil reply, want 0", active)
	}
	c.pool.mu.Lock()
	idle := len(c.pool.idle)
	c.pool.mu.Unlock()
	if idle != 1 {
		t.Errorf("idle connections = %d after a nil reply, want 1", idle)
	}
}

// The callers' view of the same wire reply. Only Get and GetDel translate it
// into the Nil sentinel; the counting commands read it as a zero, and none of
// them may report a transport failure.
func TestClient_NilBulkReplyPerCommand(t *testing.T) {
	c := NewClient(&Options{
		Addr:        nilReplyAddr(t),
		PoolSize:    1,
		DialTimeout: time.Second,
		IOTimeout:   time.Second,
	})
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	t.Run("Get", func(t *testing.T) {
		v, err := c.Get(ctx, "missing")
		if !errors.Is(err, Nil) {
			t.Fatalf("err = %v, want the Nil sentinel", err)
		}
		if v != "" {
			t.Errorf("value = %q, want empty", v)
		}
	})

	t.Run("GetDel", func(t *testing.T) {
		v, err := c.GetDel(ctx, "missing")
		if !errors.Is(err, Nil) {
			t.Fatalf("err = %v, want the Nil sentinel", err)
		}
		if v != "" {
			t.Errorf("value = %q, want empty", v)
		}
	})

	t.Run("SetNX", func(t *testing.T) {
		ok, err := c.SetNX(ctx, "taken", "v", time.Minute)
		if err != nil {
			t.Fatalf("SetNX reported a transport error for a lost race: %v", err)
		}
		if ok {
			t.Error("SetNX claimed the key when the server declined")
		}
	})

	t.Run("Exists", func(t *testing.T) {
		found, err := c.Exists(ctx, "missing")
		if err != nil {
			t.Fatalf("Exists: %v", err)
		}
		if found {
			t.Error("Exists reported a key the server said nothing about")
		}
	})

	t.Run("Eval", func(t *testing.T) {
		n, err := c.Eval(ctx, "return redis.call('GET', KEYS[1])", 1, "missing")
		if err != nil {
			t.Fatalf("Eval: %v", err)
		}
		if n != 0 {
			t.Errorf("Eval = %d, want 0 for a nil script result", n)
		}
	})
}
