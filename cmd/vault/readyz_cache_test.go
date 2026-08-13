package main

// The /readyz cache probe.
//
// main() builds the PingCache closure that GET /readyz calls, and that closure
// is the only thing in the binary that reports a cache loss for as long as it
// lasts. It has to answer for two different losses. The process may be running
// on the per-process memory fallback because NewCache failed at boot, which
// silently turns every cross-replica control (the login and password-reset
// limiters, OAuth state, the TOTP replay guard) into a per-pod one. Or the cache
// may have been fine at boot and gone away since, which the probe catches by
// writing a key and reading it back rather than by trusting the connection.
//
// Both must report cache=degraded and both must still answer 200: taking every
// replica out of rotation the moment Redis blinks is worse for an auth service
// than running degraded and saying so.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// vaultRedisStub is the smallest RESP server the cache client will talk to. It
// lives in the parent test process; the child connects to it over loopback.
type vaultRedisStub struct {
	ln net.Listener

	mu   sync.Mutex
	data map[string]string
	cmds [][]string
	// setReply, when non-empty, replaces the reply to every SET, which is how a
	// backend that has started rejecting writes is modelled.
	setReply string
	// swallowWrites acknowledges a SET with +OK and stores nothing, which is the
	// backend the read-back exists to catch.
	swallowWrites bool
}

func newVaultRedisStub(t *testing.T) *vaultRedisStub {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &vaultRedisStub{ln: ln, data: map[string]string{}}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *vaultRedisStub) addr() string { return s.ln.Addr().String() }

func (s *vaultRedisStub) failWrites(reply string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setReply = reply
}

// forgetWrites turns the stub into a backend that acknowledges every write and
// keeps nothing. Anything written before the switch is dropped too, otherwise a
// probe would read back a value the amnesiac backend would no longer hold.
func (s *vaultRedisStub) forgetWrites(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setReply = ""
	s.swallowWrites = on
	if on {
		s.data = map[string]string{}
	}
}

// commands returns every command the stub has been sent, so a test can assert
// that the probe really made a round trip instead of reporting from cache state
// it already held.
func (s *vaultRedisStub) commands() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.cmds))
	copy(out, s.cmds)
	return out
}

func (s *vaultRedisStub) sawCommand(verb, key string) bool {
	for _, c := range s.commands() {
		if len(c) >= 2 && strings.EqualFold(c[0], verb) && c[1] == key {
			return true
		}
	}
	return false
}

func (s *vaultRedisStub) serve(conn net.Conn) {
	defer conn.Close() //nolint:errcheck // test fixture cleanup

	r := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(r)
		if err != nil {
			return
		}
		if _, err := io.WriteString(conn, s.reply(args)); err != nil {
			return
		}
	}
}

func (s *vaultRedisStub) reply(args []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(args) == 0 {
		return "-ERR empty command\r\n"
	}
	s.cmds = append(s.cmds, args)

	switch strings.ToUpper(args[0]) {
	case "PING":
		return "+PONG\r\n"
	case "SET":
		if s.setReply != "" {
			return s.setReply
		}
		if len(args) >= 3 && !s.swallowWrites {
			s.data[args[1]] = args[2]
		}
		return "+OK\r\n"
	case "GET":
		if len(args) != 2 {
			return "-ERR wrong number of arguments\r\n"
		}
		v, ok := s.data[args[1]]
		if !ok {
			return "$-1\r\n"
		}
		return fmt.Sprintf("$%d\r\n%s\r\n", len(v), v)
	case "DEL":
		delete(s.data, args[1])
		return ":1\r\n"
	default:
		return "-ERR unsupported command\r\n"
	}
}

// readRESPCommand reads one inline array of bulk strings, which is the only
// shape the cache client sends.
func readRESPCommand(r *bufio.Reader) ([]string, error) {
	header, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimRight(header, "\r\n")
	if !strings.HasPrefix(header, "*") {
		return nil, fmt.Errorf("expected a RESP array, got %q", header)
	}
	n, err := strconv.Atoi(header[1:])
	if err != nil {
		return nil, fmt.Errorf("bad array length %q: %w", header, err)
	}

	args := make([]string, 0, n)
	for range n {
		sizeLine, sizeErr := r.ReadString('\n')
		if sizeErr != nil {
			return nil, sizeErr
		}
		sizeLine = strings.TrimRight(sizeLine, "\r\n")
		if !strings.HasPrefix(sizeLine, "$") {
			return nil, fmt.Errorf("expected a bulk string, got %q", sizeLine)
		}
		size, convErr := strconv.Atoi(sizeLine[1:])
		if convErr != nil {
			return nil, fmt.Errorf("bad bulk length %q: %w", sizeLine, convErr)
		}
		buf := make([]byte, size+2) // payload plus the trailing CRLF
		if _, readErr := io.ReadFull(r, buf); readErr != nil {
			return nil, readErr
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

// readyzReport is the probe's answer as an operator's monitoring reads it.
func readyzReport(t *testing.T, addr string) map[string]string {
	t.Helper()
	code, body := get(t, addr, "/readyz")
	// 200 whatever the cache is doing. A 503 here would drain the replica.
	if code != 200 {
		t.Fatalf("GET /readyz = %d, want 200 (body %q)", code, body)
	}
	var doc map[string]string
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode /readyz body %q: %v", body, err)
	}
	return doc
}

// TestReadyzReportsTheMemoryFallbackForAsLongAsItLasts covers the first of the
// two losses. TestCacheBackendFallback already pins the warning the boot writes,
// but that line scrolls away within minutes and the process then looks identical
// to a healthy one. An operator whose fleet is quietly enforcing per-pod rate
// limits has only this probe to find out.
func TestReadyzReportsTheMemoryFallbackForAsLongAsItLasts(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["CACHE_BACKEND"] = "redis"
	env["REDIS_ADDR"] = "127.0.0.1:" + deadPort(t)

	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
		doc := readyzReport(t, addr)
		if doc["cache"] != "degraded" {
			t.Errorf("/readyz reports cache=%q on the memory fallback, want degraded; "+
				"nothing else tells an operator that every cross-replica control is now per-pod", doc["cache"])
		}
		if doc["database"] != "up" {
			t.Errorf("/readyz reports database=%q, want up", doc["database"])
		}
		if doc["status"] != "ready" {
			t.Errorf("/readyz reports status=%q, want ready; a cache outage must not drain the replica", doc["status"])
		}
	})
	requireExit(t, res, 0, "cache init failed, falling back to per-process memory")
}

// TestReadyzProbesTheCacheWithARoundTrip covers the second loss, in the two
// shapes the probe has to tell apart from health. Both are driven against one
// running process so the healthy answer above them is a control: without it,
// "degraded" could just as well mean the probe never reports anything else.
func TestReadyzProbesTheCacheWithARoundTrip(t *testing.T) {
	redis := newVaultRedisStub(t)
	stub := bootedStub(t)
	addr := freeAddr(t)
	env := bootEnv(t, stub, addr)
	env["CACHE_BACKEND"] = "redis"
	env["REDIS_ADDR"] = redis.addr()

	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
		if doc := readyzReport(t, addr); doc["cache"] != "up" {
			t.Fatalf("/readyz reports cache=%q against a working cache, want up", doc["cache"])
		}
		if !redis.sawCommand("SET", "readyz:probe") || !redis.sawCommand("GET", "readyz:probe") {
			t.Fatalf("the probe did not write and read its own key; commands were %v", redis.commands())
		}

		// A backend that has started refusing writes. Nothing is wrong with the
		// connection, so only the write itself reveals it.
		redis.failWrites("-ERR simulated write failure\r\n")
		if doc := readyzReport(t, addr); doc["cache"] != "degraded" {
			t.Errorf("/readyz reports cache=%q while the cache is rejecting writes, want degraded", doc["cache"])
		}

		// A backend that acknowledges writes and then has nothing to return. This
		// is the case the read-back exists for: the write succeeds, so a probe
		// that stopped after the Set would call this healthy while every rate
		// limiter and OAuth state read comes back empty.
		redis.forgetWrites(true)
		if doc := readyzReport(t, addr); doc["cache"] != "degraded" {
			t.Errorf("/readyz reports cache=%q against a cache that forgets what it acknowledged, want degraded", doc["cache"])
		}
	})
	requireExit(t, res, 0, "")

	// The fallback warning belongs to the other test: this cache was healthy at
	// boot, and a process that quietly fell back would make the probe results
	// above mean nothing.
	if strings.Contains(res.stderr, "cache init failed") {
		t.Fatalf("the process fell back to memory at boot instead of using the stub:\n%s", res.stderr)
	}
}

// vaultRedisStubIsResponsive is a guard on the fixture rather than on the
// binary: if the stub ever stopped speaking RESP, the probe tests above would
// report a degraded cache for the wrong reason and still pass their assertions.
func TestVaultRedisStubAnswersTheCacheHandshake(t *testing.T) {
	s := newVaultRedisStub(t)

	conn, err := net.DialTimeout("tcp", s.addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial stub: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test client cleanup

	if _, err := io.WriteString(conn, "*1\r\n$4\r\nPING\r\n"); err != nil {
		t.Fatalf("write PING: %v", err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read PONG: %v", err)
	}
	if got != "+PONG\r\n" {
		t.Fatalf("stub answered PING with %q, want +PONG", got)
	}
}
