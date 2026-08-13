package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFlagStore(t *testing.T) {
	fs := NewFlagStore(100*time.Millisecond, "")

	// Initially not flagged
	if fs.IsFlagged("1.2.3.4") {
		t.Error("IP should not be flagged initially")
	}

	// Flag it
	fs.Flag("1.2.3.4", "test", 100)
	if !fs.IsFlagged("1.2.3.4") {
		t.Error("IP should be flagged")
	}

	// Check list
	entries := fs.List()
	if len(entries) != 1 {
		t.Errorf("List() = %d entries, want 1", len(entries))
	}
	if entries[0].IP != "1.2.3.4" {
		t.Errorf("List()[0].IP = %q, want %q", entries[0].IP, "1.2.3.4")
	}

	// Unflag
	if !fs.Unflag("1.2.3.4") {
		t.Error("Unflag should return true for flagged IP")
	}
	if fs.IsFlagged("1.2.3.4") {
		t.Error("IP should not be flagged after unflag")
	}

	// Unflag non-existent
	if fs.Unflag("5.5.5.5") {
		t.Error("Unflag should return false for non-flagged IP")
	}
}

func TestFlagStoreTTL(t *testing.T) {
	fs := NewFlagStore(50*time.Millisecond, "")

	fs.Flag("1.2.3.4", "test", 100)
	if !fs.IsFlagged("1.2.3.4") {
		t.Error("IP should be flagged")
	}

	time.Sleep(80 * time.Millisecond)

	if fs.IsFlagged("1.2.3.4") {
		t.Error("IP should have expired")
	}
}

func TestFlagStoreReap(t *testing.T) {
	fs := NewFlagStore(50*time.Millisecond, "")

	fs.Flag("1.1.1.1", "test", 100)
	fs.Flag("2.2.2.2", "test", 100)

	time.Sleep(80 * time.Millisecond)
	fs.Reap()

	fs.mu.RLock()
	count := len(fs.flags)
	fs.mu.RUnlock()

	if count != 0 {
		t.Errorf("Reap: %d entries remain, want 0", count)
	}
}

// TestFlagStoreExpiredEntryIsHiddenButNotRemoved pins the split between the read
// path and the reaper. IsFlagged and List filter on ExpiresAt, so an expired flag
// stops routing traffic to the honeypot the instant it lapses rather than at the
// next reaper tick. The entry itself survives until Reap runs, which is why a
// bridge that never calls StartReaper leaks one map entry per flagged IP forever
// instead of merely serving stale decisions.
func TestFlagStoreExpiredEntryIsHiddenButNotRemoved(t *testing.T) {
	fs := NewFlagStore(30*time.Millisecond, "")
	fs.Flag("9.9.9.9", "test", 100)

	time.Sleep(60 * time.Millisecond)

	if fs.IsFlagged("9.9.9.9") {
		t.Error("IsFlagged should be false once the TTL has lapsed")
	}
	if got := fs.List(); len(got) != 0 {
		t.Errorf("List() = %d entries, want 0 once the TTL has lapsed", len(got))
	}

	fs.mu.RLock()
	residual := len(fs.flags)
	fs.mu.RUnlock()
	if residual != 1 {
		t.Fatalf("expired entry count before Reap = %d, want 1", residual)
	}

	fs.Reap()

	fs.mu.RLock()
	residual = len(fs.flags)
	fs.mu.RUnlock()
	if residual != 0 {
		t.Errorf("expired entry count after Reap = %d, want 0", residual)
	}
}

// TestFlagStoreReflagRestartsTheClock documents that traffic does not extend a
// flag but a fresh Flag call does. FlagEntry's own doc promises exactly this, and
// it is what makes the TTL a bounded blast radius for a false positive: a wrongly
// flagged user is released on wall-clock time no matter how much they browse.
func TestFlagStoreReflagRestartsTheClock(t *testing.T) {
	fs := NewFlagStore(80*time.Millisecond, "")

	fs.Flag("1.2.3.4", "first", 30)
	fs.mu.RLock()
	firstExpiry := fs.flags["1.2.3.4"].ExpiresAt
	fs.mu.RUnlock()

	time.Sleep(40 * time.Millisecond)

	// Reads must not push the expiry out.
	fs.IsFlagged("1.2.3.4")
	fs.List()
	fs.mu.RLock()
	afterReads := fs.flags["1.2.3.4"].ExpiresAt
	fs.mu.RUnlock()
	if !afterReads.Equal(firstExpiry) {
		t.Errorf("reads moved ExpiresAt from %v to %v", firstExpiry, afterReads)
	}

	// A second flag replaces the entry wholesale, including reason and score.
	fs.Flag("1.2.3.4", "second", 100)
	fs.mu.RLock()
	entry := *fs.flags["1.2.3.4"]
	fs.mu.RUnlock()

	if !entry.ExpiresAt.After(firstExpiry) {
		t.Errorf("re-flag ExpiresAt = %v, want later than %v", entry.ExpiresAt, firstExpiry)
	}
	if entry.Reason != "second" || entry.Score != 100 {
		t.Errorf("re-flag entry = %q/%d, want second/100", entry.Reason, entry.Score)
	}
}

// TestFlagStoreConcurrentAccess drives every FlagStore method from many
// goroutines at once. The store sits on the request hot path of a network proxy,
// so a data race here is not theoretical: it is one flagged attacker away. The
// assertion at the end is that the store is still internally consistent, which a
// torn map write would not survive even if the race detector missed the write.
func TestFlagStoreConcurrentAccess(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")

	const workers = 32
	const iterations = 40

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", w)
			for i := 0; i < iterations; i++ {
				fs.Flag(ip, "concurrent", i)
				fs.IsFlagged(ip)
				fs.List()
				if i%3 == 0 {
					fs.Unflag(ip)
				}
				fs.Reap()
			}
			// A settled final write per worker, so the end state is a known
			// value rather than whatever the churn happened to leave behind.
			fs.Flag(ip, fmt.Sprintf("final-%d", w), w)
		}(w)
	}
	wg.Wait()

	// Each worker only ever touched its own IP, so every entry must carry that
	// worker's own reason and score. A crossed write would show up as one
	// worker's marker under another worker's key.
	entries := fs.List()
	if len(entries) != workers {
		t.Fatalf("List() = %d entries, want %d", len(entries), workers)
	}
	byIP := make(map[string]FlagEntry, len(entries))
	for _, e := range entries {
		byIP[e.IP] = e
	}
	for w := 0; w < workers; w++ {
		ip := fmt.Sprintf("10.0.0.%d", w)
		got, ok := byIP[ip]
		if !ok {
			t.Fatalf("%s missing after concurrent churn", ip)
		}
		wantReason := fmt.Sprintf("final-%d", w)
		if got.Reason != wantReason || got.Score != w {
			t.Errorf("%s = %q/%d, want %q/%d", ip, got.Reason, got.Score, wantReason, w)
		}
		if !fs.IsFlagged(ip) {
			t.Errorf("%s is listed but IsFlagged says otherwise", ip)
		}
	}
}

// TestFlagStoreListReturnsCopies guards the admin API against handing out live
// pointers into the store. List returns values, so a caller that mutates what it
// got back cannot rewrite a flag's expiry or reason behind the proxy's back.
func TestFlagStoreListReturnsCopies(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	fs.Flag("1.2.3.4", "original", 100)

	entries := fs.List()
	if len(entries) != 1 {
		t.Fatalf("List() = %d entries, want 1", len(entries))
	}
	entries[0].Reason = "tampered"
	entries[0].ExpiresAt = time.Now().Add(-time.Hour)

	again := fs.List()
	if len(again) != 1 {
		t.Fatalf("second List() = %d entries, want 1", len(again))
	}
	if again[0].Reason != "original" {
		t.Errorf("Reason = %q after caller mutation, want %q", again[0].Reason, "original")
	}
	if !fs.IsFlagged("1.2.3.4") {
		t.Error("caller mutation of a List() result expired the live flag")
	}
}

// ---------------------------------------------------------------------------
// RESP2 fake
// ---------------------------------------------------------------------------

// redisReply is what a fakeRedis handler hands back: the exact bytes to write on
// the wire, and whether to hang up afterwards.
//
// Handlers return raw protocol rather than a typed value on purpose. The code
// under test is a hand-rolled RESP2 parser reachable from whatever host an
// operator puts in BRIDGE_REDIS_ADDR, so the replies worth testing hardest are
// the ones a healthy Redis never sends: truncated bulk strings, absurd lengths,
// unknown type bytes, and a socket that closes mid-reply.
type redisReply struct {
	raw   string
	close bool
}

// redisHandler answers one command. args[0] is the verb.
type redisHandler func(args []string) redisReply

// fakeRedis is an in-process RESP2 endpoint speaking the GET/SET/DEL/SCAN subset
// the bridge uses. It records every command it receives so tests can assert on
// what the bridge actually sent, not only on what it did afterwards.
type fakeRedis struct {
	ln net.Listener

	mu      sync.Mutex
	data    map[string]string
	cmds    [][]string
	handler redisHandler
}

func newFakeRedis(t *testing.T) *fakeRedis {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	f := &fakeRedis{ln: ln, data: make(map[string]string)}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()

	return f
}

func (f *fakeRedis) addr() string { return f.ln.Addr().String() }

// preload seeds a key as if a previous bridge process had written it.
func (f *fakeRedis) preload(key, val string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = val
}

func (f *fakeRedis) snapshot() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.data))
	for k, v := range f.data {
		out[k] = v
	}
	return out
}

func (f *fakeRedis) commands() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.cmds))
	copy(out, f.cmds)
	return out
}

// script replaces the default command handling.
func (f *fakeRedis) script(h redisHandler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = h
}

func (f *fakeRedis) serve(conn net.Conn) {
	defer conn.Close() // #nosec G104 -- test fixture cleanup

	r := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(r)
		if err != nil {
			return
		}

		f.mu.Lock()
		f.cmds = append(f.cmds, args)
		handler := f.handler
		f.mu.Unlock()

		reply := redisReply{}
		if handler != nil {
			reply = handler(args)
		} else {
			reply = f.defaultReply(args)
		}

		if reply.raw != "" {
			if _, err := conn.Write([]byte(reply.raw)); err != nil {
				return
			}
		}
		if reply.close {
			return
		}
	}
}

func (f *fakeRedis) defaultReply(args []string) redisReply {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(args) == 0 {
		return redisReply{raw: "-ERR empty command\r\n"}
	}

	switch strings.ToUpper(args[0]) {
	case "GET":
		if len(args) != 2 {
			return redisReply{raw: "-ERR wrong number of arguments\r\n"}
		}
		v, ok := f.data[args[1]]
		if !ok {
			return redisReply{raw: "$-1\r\n"}
		}
		return redisReply{raw: respBulk(v)}

	case "SET":
		if len(args) < 3 {
			return redisReply{raw: "-ERR wrong number of arguments\r\n"}
		}
		f.data[args[1]] = args[2]
		return redisReply{raw: "+OK\r\n"}

	case "DEL":
		if len(args) != 2 {
			return redisReply{raw: "-ERR wrong number of arguments\r\n"}
		}
		if _, ok := f.data[args[1]]; ok {
			delete(f.data, args[1])
			return redisReply{raw: ":1\r\n"}
		}
		return redisReply{raw: ":0\r\n"}

	case "SCAN":
		pattern := "*"
		for i := 1; i+1 < len(args); i++ {
			if strings.EqualFold(args[i], "MATCH") {
				pattern = args[i+1]
			}
		}
		var keys []string
		for k := range f.data {
			if globMatch(pattern, k) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		return redisReply{raw: respScanPage("0", keys)}
	}

	return redisReply{raw: "-ERR unknown command\r\n"}
}

// globMatch implements the only pattern shape the bridge uses: a literal prefix
// followed by a single trailing star.
func globMatch(pattern, key string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(key, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == key
}

func respBulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }

func respArray(items ...string) string {
	return fmt.Sprintf("*%d\r\n", len(items)) + strings.Join(items, "")
}

// respScanPage builds the two-element SCAN reply: next cursor, then the keys.
func respScanPage(cursor string, keys []string) string {
	bulks := make([]string, 0, len(keys))
	for _, k := range keys {
		bulks = append(bulks, respBulk(k))
	}
	return respArray(respBulk(cursor), respArray(bulks...))
}

func readRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("fakeRedis: expected array header, got %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		if !strings.HasPrefix(hdr, "$") {
			return nil, fmt.Errorf("fakeRedis: expected bulk header, got %q", hdr)
		}
		size, err := strconv.Atoi(hdr[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

// deadAddr returns an address nothing is listening on, by binding a port and
// immediately releasing it.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // #nosec G104 -- releasing the port is the point
	return addr
}

// ---------------------------------------------------------------------------
// Redis client
// ---------------------------------------------------------------------------

// TestRedisClientRoundTrip checks that the hand-rolled RESP2 encoder produces
// commands a server actually understands and that each reply type decodes back
// to the right Go value. The assertions are on the bytes the server received,
// because an encoder that emitted a well-formed but wrong command would still
// round-trip cleanly against a mock that only looked at the verb.
func TestRedisClientRoundTrip(t *testing.T) {
	f := newFakeRedis(t)

	rc, err := newRedisClient(f.addr())
	if err != nil {
		t.Fatalf("newRedisClient: %v", err)
	}
	defer rc.Close()

	if err := rc.Set("k1", "v1", 90*time.Second); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := f.snapshot()["k1"]; got != "v1" {
		t.Errorf("server stored %q under k1, want %q", got, "v1")
	}

	cmds := f.commands()
	if len(cmds) != 1 {
		t.Fatalf("server saw %d commands, want 1", len(cmds))
	}
	wantSet := []string{"SET", "k1", "v1", "EX", "90"}
	if strings.Join(cmds[0], "\x00") != strings.Join(wantSet, "\x00") {
		t.Errorf("SET command = %q, want %q", cmds[0], wantSet)
	}

	got, err := rc.Get("k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "v1" {
		t.Errorf("Get = %q, want %q", got, "v1")
	}

	// A missing key is a nil bulk string, which must decode to the empty string
	// with no error rather than to an error the caller would log on every miss.
	missing, err := rc.Get("nope")
	if err != nil {
		t.Fatalf("Get(missing): %v", err)
	}
	if missing != "" {
		t.Errorf("Get(missing) = %q, want empty", missing)
	}

	if err := rc.Del("k1"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if _, ok := f.snapshot()["k1"]; ok {
		t.Error("k1 still present after Del")
	}

	// Deleting a key that is already gone is not an error.
	if err := rc.Del("k1"); err != nil {
		t.Fatalf("Del(missing): %v", err)
	}
}

// TestRedisClientSetEncodesTTLAsWholeSeconds pins the EX argument. A duration
// under a second truncates to "EX 0", which real Redis rejects outright, so a
// bridge configured with a sub-second BRIDGE_FLAG_TTL would fail every
// persistence write. The encoding is what the test locks; the operational
// consequence is why it is worth locking.
func TestRedisClientSetEncodesTTLAsWholeSeconds(t *testing.T) {
	tests := []struct {
		ttl  time.Duration
		want string
	}{
		{24 * time.Hour, "86400"},
		{90 * time.Second, "90"},
		{1500 * time.Millisecond, "1"},
		{500 * time.Millisecond, "0"},
	}

	for _, tt := range tests {
		t.Run(tt.ttl.String(), func(t *testing.T) {
			f := newFakeRedis(t)
			rc, err := newRedisClient(f.addr())
			if err != nil {
				t.Fatalf("newRedisClient: %v", err)
			}
			defer rc.Close()

			if err := rc.Set("k", "v", tt.ttl); err != nil {
				t.Fatalf("Set: %v", err)
			}
			cmds := f.commands()
			if len(cmds) != 1 || len(cmds[0]) != 5 {
				t.Fatalf("commands = %q, want one 5-argument SET", cmds)
			}
			if cmds[0][4] != tt.want {
				t.Errorf("EX argument = %q, want %q", cmds[0][4], tt.want)
			}
		})
	}
}

// rawReplyResult runs one GET against a server scripted to answer with exactly
// raw, optionally hanging up afterwards.
func rawReplyResult(t *testing.T, raw string, closeAfter bool) (string, error) {
	t.Helper()

	f := newFakeRedis(t)
	f.script(func(_ []string) redisReply {
		return redisReply{raw: raw, close: closeAfter}
	})

	rc, err := newRedisClient(f.addr())
	if err != nil {
		t.Fatalf("newRedisClient: %v", err)
	}
	defer rc.Close()

	return rc.Get("probe")
}

// TestRedisClientReplyDecoding walks every branch of readReply, including the
// ones only a broken or hostile server produces. BRIDGE_REDIS_ADDR is an
// operator-supplied network address and the client performs no authentication
// step, so anything that can occupy that port chooses these bytes. Each case
// must end in a value or an error, never in a hang and never in a panic that
// would take the proxy down with it.
func TestRedisClientReplyDecoding(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		closeAfter bool
		want       string
		wantErr    string
	}{
		{
			name: "simple string",
			raw:  "+PONG\r\n",
			want: "PONG",
		},
		{
			name:    "error reply is surfaced verbatim",
			raw:     "-WRONGTYPE Operation against a key\r\n",
			wantErr: "redis: WRONGTYPE Operation against a key",
		},
		{
			name: "integer",
			raw:  ":42\r\n",
			want: "42",
		},
		{
			name: "bulk string",
			raw:  "$5\r\nhello\r\n",
			want: "hello",
		},
		{
			name: "empty bulk string",
			raw:  "$0\r\n\r\n",
			want: "",
		},
		{
			name: "nil bulk string",
			raw:  "$-1\r\n",
			want: "",
		},
		{
			name: "bulk string containing CRLF is length delimited",
			raw:  "$4\r\na\r\nb\r\n",
			want: "a\r\nb",
		},
		{
			name:    "oversized bulk string is refused before allocating",
			raw:     "$10485761\r\n",
			wantErr: "bulk string too large",
		},
		{
			name: "array is flattened newline separated",
			raw:  "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
			want: "foo\nbar",
		},
		{
			name: "nested array is flattened too",
			raw:  "*2\r\n$1\r\n0\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n",
			want: "0\na\nb",
		},
		{
			name: "empty array",
			raw:  "*0\r\n",
			want: "",
		},
		{
			name: "nil array",
			raw:  "*-1\r\n",
			want: "",
		},
		{
			name:    "oversized array is refused before allocating",
			raw:     "*10001\r\n",
			wantErr: "array too large",
		},
		{
			name:    "unknown type byte",
			raw:     "?surprise\r\n",
			wantErr: "unexpected reply type: ?",
		},
		{
			name:       "hang up before any reply",
			raw:        "",
			closeAfter: true,
			wantErr:    "EOF",
		},
		{
			name:       "bulk header promising more than is sent",
			raw:        "$100\r\nshort",
			closeAfter: true,
			wantErr:    "EOF",
		},
		{
			name:       "array header promising more elements than are sent",
			raw:        "*3\r\n$1\r\na\r\n",
			closeAfter: true,
			wantErr:    "EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rawReplyResult(t, tt.raw, tt.closeAfter)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Get = %q, want error containing %q", got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got != tt.want {
				t.Errorf("Get = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRedisClientWriteFailureIsReported covers the send half of do. Once the
// socket is gone every command must fail fast with an error the caller can log,
// rather than blocking or reporting success and losing the write.
func TestRedisClientWriteFailureIsReported(t *testing.T) {
	f := newFakeRedis(t)

	rc, err := newRedisClient(f.addr())
	if err != nil {
		t.Fatalf("newRedisClient: %v", err)
	}
	rc.Close()

	if _, err := rc.Get("k"); err == nil {
		t.Error("Get on a closed client returned no error")
	}
	if err := rc.Set("k", "v", time.Minute); err == nil {
		t.Error("Set on a closed client returned no error")
	}
	if err := rc.Del("k"); err == nil {
		t.Error("Del on a closed client returned no error")
	}
	if _, err := rc.Scan("bridge:flag:*"); err == nil {
		t.Error("Scan on a closed client returned no error")
	}
}

// TestNewRedisClientDialFailure keeps the dial error on the caller's side of the
// boundary. NewFlagStore depends on getting an error here to fall back to
// memory-only operation instead of holding a half-built client.
func TestNewRedisClientDialFailure(t *testing.T) {
	rc, err := newRedisClient(deadAddr(t))
	if err == nil {
		rc.Close()
		t.Fatal("newRedisClient against a closed port returned no error")
	}
}

// TestRedisScanPaginates walks the cursor loop. Redis is free to return a
// partial page with a non-zero cursor on every call, so a client that stopped
// after the first reply would silently load a fraction of the flag set on
// startup and serve the real vault to attackers it had already caught.
func TestRedisScanPaginates(t *testing.T) {
	f := newFakeRedis(t)

	pages := []struct {
		cursor string
		keys   []string
	}{
		{"17", []string{"bridge:flag:1.1.1.1", "bridge:flag:2.2.2.2"}},
		{"42", []string{"bridge:flag:3.3.3.3"}},
		{"0", []string{"bridge:flag:4.4.4.4"}},
	}

	// The handler runs on the fake's connection goroutine, so the call log is
	// collected under a mutex and asserted on after Scan returns rather than
	// from inside the handler.
	var mu sync.Mutex
	var cursors []string

	f.script(func(args []string) redisReply {
		mu.Lock()
		defer mu.Unlock()

		if !strings.EqualFold(args[0], "SCAN") {
			return redisReply{raw: "-ERR unexpected command\r\n"}
		}
		idx := len(cursors)
		cursors = append(cursors, args[1])
		if idx >= len(pages) {
			return redisReply{raw: respScanPage("0", nil)}
		}
		return redisReply{raw: respScanPage(pages[idx].cursor, pages[idx].keys)}
	})

	rc, err := newRedisClient(f.addr())
	if err != nil {
		t.Fatalf("newRedisClient: %v", err)
	}
	defer rc.Close()

	keys, err := rc.Scan("bridge:flag:*")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want := []string{
		"bridge:flag:1.1.1.1",
		"bridge:flag:2.2.2.2",
		"bridge:flag:3.3.3.3",
		"bridge:flag:4.4.4.4",
	}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("Scan = %q, want %q", keys, want)
	}

	mu.Lock()
	got := append([]string(nil), cursors...)
	mu.Unlock()

	// Each call after the first must carry the cursor the previous reply handed
	// back, otherwise the loop would spin on the same page forever.
	wantCursors := []string{"0", "17", "42"}
	if strings.Join(got, ",") != strings.Join(wantCursors, ",") {
		t.Errorf("SCAN cursors = %q, want %q", got, wantCursors)
	}
}

// TestRedisScanEmptyResult covers the page with a cursor but no keys, which is
// what a real Redis returns constantly when MATCH filters everything out of a
// COUNT-sized slice. It must yield no keys rather than one empty-string key that
// loadFromRedis would then treat as a flag on the empty IP.
func TestRedisScanEmptyResult(t *testing.T) {
	f := newFakeRedis(t)

	rc, err := newRedisClient(f.addr())
	if err != nil {
		t.Fatalf("newRedisClient: %v", err)
	}
	defer rc.Close()

	keys, err := rc.Scan("bridge:flag:*")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Scan on an empty store = %q, want no keys", keys)
	}
}

// TestRedisScanErrorPropagates makes sure a failing SCAN aborts the walk instead
// of returning a truncated key set that loadFromRedis would treat as the whole
// flag list.
func TestRedisScanErrorPropagates(t *testing.T) {
	f := newFakeRedis(t)
	f.script(func(_ []string) redisReply {
		return redisReply{raw: "-ERR no permission\r\n"}
	})

	rc, err := newRedisClient(f.addr())
	if err != nil {
		t.Fatalf("newRedisClient: %v", err)
	}
	defer rc.Close()

	keys, err := rc.Scan("bridge:flag:*")
	if err == nil {
		t.Fatalf("Scan = %q, want an error", keys)
	}
	if keys != nil {
		t.Errorf("Scan returned %q alongside an error, want nil", keys)
	}
}

// TestRedisClientSerializesConcurrentCommands is the reason redisClient carries
// a mutex at all. One connection carries every command, so two goroutines
// writing at once would interleave their RESP frames and each would then read
// the other's reply. The bridge issues a Redis write from the request path on
// every flag, so concurrent use is the normal case rather than an edge case.
func TestRedisClientSerializesConcurrentCommands(t *testing.T) {
	f := newFakeRedis(t)

	rc, err := newRedisClient(f.addr())
	if err != nil {
		t.Fatalf("newRedisClient: %v", err)
	}
	defer rc.Close()

	const workers = 16
	const iterations = 15

	var wg sync.WaitGroup
	errs := make(chan error, workers*iterations)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			key := fmt.Sprintf("bridge:flag:10.0.0.%d", w)
			val := fmt.Sprintf("worker-%d", w)
			for i := 0; i < iterations; i++ {
				if err := rc.Set(key, val, time.Minute); err != nil {
					errs <- fmt.Errorf("set: %w", err)
					return
				}
				got, err := rc.Get(key)
				if err != nil {
					errs <- fmt.Errorf("get: %w", err)
					return
				}
				// A crossed reply would return another worker's value here.
				if got != val {
					errs <- fmt.Errorf("Get(%s) = %q, want %q", key, got, val)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	if stored := f.snapshot(); len(stored) != workers {
		t.Errorf("server holds %d keys, want %d", len(stored), workers)
	}
}

// ---------------------------------------------------------------------------
// FlagStore over Redis
// ---------------------------------------------------------------------------

// TestFlagStoreRedisPersistence checks the write-through half of the store. The
// point of Redis here is that a bridge restart, or a second replica, does not
// hand a caught attacker back to the real vault, which only holds if Flag and
// Unflag reach Redis with the key shape loadFromRedis later looks for.
func TestFlagStoreRedisPersistence(t *testing.T) {
	f := newFakeRedis(t)

	fs := NewFlagStore(2*time.Hour, f.addr())
	defer fs.Close()

	if fs.redis == nil {
		t.Fatal("FlagStore did not attach the Redis client")
	}

	before := time.Now()
	fs.Flag("203.0.113.7", "auto:rate_exceeded", 150)

	stored := f.snapshot()
	val, ok := stored["bridge:flag:203.0.113.7"]
	if !ok {
		t.Fatalf("Redis holds %v, want a bridge:flag:203.0.113.7 key", stored)
	}

	parts := strings.SplitN(val, "|", 3)
	if len(parts) != 3 {
		t.Fatalf("stored value %q does not have three pipe separated fields", val)
	}
	if parts[0] != "auto:rate_exceeded" {
		t.Errorf("stored reason = %q, want %q", parts[0], "auto:rate_exceeded")
	}
	if parts[1] != "150" {
		t.Errorf("stored score = %q, want %q", parts[1], "150")
	}
	ts, err := time.Parse(time.RFC3339, parts[2])
	if err != nil {
		t.Fatalf("stored timestamp %q is not RFC3339: %v", parts[2], err)
	}
	if ts.Before(before.Add(-time.Second)) || ts.After(time.Now().Add(time.Second)) {
		t.Errorf("stored timestamp %v is not the flag time", ts)
	}

	// The TTL must reach Redis too, otherwise a flag outlives its own expiry
	// across a restart and a false positive becomes permanent.
	var sawSetTTL string
	for _, cmd := range f.commands() {
		if strings.EqualFold(cmd[0], "SET") && len(cmd) == 5 {
			sawSetTTL = cmd[4]
		}
	}
	if sawSetTTL != "7200" {
		t.Errorf("SET EX argument = %q, want %q", sawSetTTL, "7200")
	}

	if !fs.Unflag("203.0.113.7") {
		t.Fatal("Unflag returned false for a flagged IP")
	}
	if _, ok := f.snapshot()["bridge:flag:203.0.113.7"]; ok {
		t.Error("Redis key survived Unflag")
	}
}

// TestFlagStoreUnflagSkipsRedisWhenNotFlagged stops the store from issuing a DEL
// for an IP it never held. The admin unflag endpoint is reachable with a valid
// token and an arbitrary body, so an unbounded stream of DELs for unknown keys
// would be a free amplification path into the shared Redis.
func TestFlagStoreUnflagSkipsRedisWhenNotFlagged(t *testing.T) {
	f := newFakeRedis(t)

	fs := NewFlagStore(time.Hour, f.addr())
	defer fs.Close()

	if fs.Unflag("198.51.100.9") {
		t.Error("Unflag returned true for an IP that was never flagged")
	}
	for _, cmd := range f.commands() {
		if strings.EqualFold(cmd[0], "DEL") {
			t.Errorf("Unflag of an unknown IP issued %q", cmd)
		}
	}
}

// TestFlagStoreSurvivesRedisWriteFailures pins the failure mode as fail-open on
// persistence and fail-closed on protection. If Redis rejects the write the IP
// must still be flagged in memory, because the alternative is that a Redis
// outage quietly disables the honeypot for every new detection.
func TestFlagStoreSurvivesRedisWriteFailures(t *testing.T) {
	f := newFakeRedis(t)
	f.script(func(args []string) redisReply {
		if strings.EqualFold(args[0], "SCAN") {
			return redisReply{raw: respScanPage("0", nil)}
		}
		return redisReply{raw: "-READONLY You can't write against a read only replica\r\n"}
	})

	fs := NewFlagStore(time.Hour, f.addr())
	defer fs.Close()

	fs.Flag("192.0.2.10", "auto:automation_ua", 100)
	if !fs.IsFlagged("192.0.2.10") {
		t.Error("a failed Redis SET dropped the in-memory flag")
	}

	if !fs.Unflag("192.0.2.10") {
		t.Error("a failed Redis DEL made Unflag report failure")
	}
	if fs.IsFlagged("192.0.2.10") {
		t.Error("a failed Redis DEL left the in-memory flag in place")
	}
}

// TestNewFlagStoreFallsBackToMemoryWhenRedisIsDown is the startup half of the
// same contract. An unreachable BRIDGE_REDIS_ADDR must not stop the bridge from
// coming up, because a bridge that refuses to start takes the real vault offline
// with it.
func TestNewFlagStoreFallsBackToMemoryWhenRedisIsDown(t *testing.T) {
	fs := NewFlagStore(time.Hour, deadAddr(t))
	defer fs.Close()

	if fs.redis != nil {
		t.Error("FlagStore attached a client despite the dial failing")
	}

	fs.Flag("192.0.2.1", "test", 100)
	if !fs.IsFlagged("192.0.2.1") {
		t.Error("memory-only store did not flag")
	}
	if !fs.Unflag("192.0.2.1") {
		t.Error("memory-only store did not unflag")
	}
}

// TestFlagStoreLoadsExistingFlagsFromRedis is the restart path. Every rejection
// below is a flag that silently does not come back, so each one is named
// separately rather than folded into a single count assertion.
func TestFlagStoreLoadsExistingFlagsFromRedis(t *testing.T) {
	f := newFakeRedis(t)

	recent := time.Now().Add(-30 * time.Minute).Format(time.RFC3339)
	stale := time.Now().Add(-72 * time.Hour).Format(time.RFC3339)

	f.preload("bridge:flag:1.1.1.1", "auto:automation_ua|130|"+recent)
	f.preload("bridge:flag:2.2.2.2", "manual flag|100|"+recent)
	// Written by a bridge run that has expired under the current TTL.
	f.preload("bridge:flag:3.3.3.3", "auto:score|100|"+stale)
	// Truncated value from a partial write or an older schema.
	f.preload("bridge:flag:4.4.4.4", "auto:score|100")
	// An unparseable timestamp lands the entry in year one, so it is dropped.
	f.preload("bridge:flag:5.5.5.5", "auto:score|100|not-a-timestamp")
	// A decoy reason with a pipe in the path. Old rows used this same
	// reason|score|timestamp shape, so a parser that still splits on the first
	// two pipes will shift the fields and drop the flag as expired.
	f.preload("bridge:flag:6.6.6.6", "decoy:/wp-admin/a|b|100|"+recent)
	// An unrelated key in the same database must be ignored by the MATCH pattern.
	f.preload("other:key", "should not be loaded")

	fs := NewFlagStore(24*time.Hour, f.addr())
	defer fs.Close()

	if !fs.IsFlagged("1.1.1.1") {
		t.Error("1.1.1.1 was not restored from Redis")
	}
	if !fs.IsFlagged("2.2.2.2") {
		t.Error("2.2.2.2 was not restored from Redis")
	}
	if fs.IsFlagged("3.3.3.3") {
		t.Error("3.3.3.3 was restored despite being past its TTL")
	}
	if fs.IsFlagged("4.4.4.4") {
		t.Error("4.4.4.4 was restored from a truncated value")
	}
	if fs.IsFlagged("5.5.5.5") {
		t.Error("5.5.5.5 was restored despite an unparseable timestamp")
	}
	if !fs.IsFlagged("6.6.6.6") {
		t.Error("6.6.6.6 was not restored; a pipe in the reason shifted the timestamp and the flag was dropped as expired")
	}
	if fs.IsFlagged("other:key") || fs.IsFlagged("key") {
		t.Error("a key outside the bridge:flag namespace was loaded as a flag")
	}

	entries := fs.List()
	if len(entries) != 3 {
		t.Fatalf("List() = %d entries, want 3: %+v", len(entries), entries)
	}

	// Reason and score must survive the round trip, since the admin flag list is
	// the only record of why an IP is in the honeypot after a restart.
	byIP := map[string]FlagEntry{}
	for _, e := range entries {
		byIP[e.IP] = e
	}
	if got := byIP["1.1.1.1"]; got.Reason != "auto:automation_ua" || got.Score != 130 {
		t.Errorf("1.1.1.1 restored as %q/%d, want auto:automation_ua/130", got.Reason, got.Score)
	}
	if got := byIP["2.2.2.2"]; got.Reason != "manual flag" || got.Score != 100 {
		t.Errorf("2.2.2.2 restored as %q/%d, want manual flag/100", got.Reason, got.Score)
	}
	if got := byIP["6.6.6.6"]; got.Reason != "decoy:/wp-admin/a|b" || got.Score != 100 {
		t.Errorf("6.6.6.6 restored as %q/%d, want decoy:/wp-admin/a|b/100", got.Reason, got.Score)
	}
}

// TestFlagStoreLoadSkipsKeysThatFailToRead covers the per-key GET error. A key
// that vanishes between the SCAN and the GET, or that another client retyped,
// must cost only that one flag rather than aborting the whole restore.
func TestFlagStoreLoadSkipsKeysThatFailToRead(t *testing.T) {
	f := newFakeRedis(t)

	good := "auto:score|100|" + time.Now().Format(time.RFC3339)
	f.preload("bridge:flag:1.1.1.1", good)
	f.preload("bridge:flag:2.2.2.2", good)

	f.script(func(args []string) redisReply {
		if strings.EqualFold(args[0], "GET") && args[1] == "bridge:flag:1.1.1.1" {
			return redisReply{raw: "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"}
		}
		return f.defaultReply(args)
	})

	fs := NewFlagStore(time.Hour, f.addr())
	defer fs.Close()

	if fs.IsFlagged("1.1.1.1") {
		t.Error("1.1.1.1 was loaded despite its GET failing")
	}
	if !fs.IsFlagged("2.2.2.2") {
		t.Error("2.2.2.2 was skipped, so one bad key aborted the whole restore")
	}
}

// TestFlagStoreLoadSurvivesScanFailure keeps a Redis that answers the dial but
// refuses SCAN from taking the bridge down. The store must come up empty and
// keep the connection for subsequent writes.
func TestFlagStoreLoadSurvivesScanFailure(t *testing.T) {
	f := newFakeRedis(t)
	f.preload("bridge:flag:1.1.1.1", "auto:score|100|"+time.Now().Format(time.RFC3339))

	f.script(func(args []string) redisReply {
		if strings.EqualFold(args[0], "SCAN") {
			return redisReply{raw: "-NOPERM this user has no permissions to run the 'scan' command\r\n"}
		}
		return f.defaultReply(args)
	})

	fs := NewFlagStore(time.Hour, f.addr())
	defer fs.Close()

	var scanned bool
	for _, cmd := range f.commands() {
		if strings.EqualFold(cmd[0], "SCAN") {
			scanned = true
		}
	}
	if !scanned {
		t.Fatal("NewFlagStore never issued a SCAN")
	}
	if fs.redis == nil {
		t.Error("a failed SCAN dropped the Redis client")
	}
	if got := len(fs.List()); got != 0 {
		t.Errorf("List() = %d entries after a failed SCAN, want 0", got)
	}

	// Writes must still go through on the connection that survived.
	fs.Flag("9.9.9.9", "after-scan-failure", 100)
	if _, ok := f.snapshot()["bridge:flag:9.9.9.9"]; !ok {
		t.Error("no write reached Redis after the failed SCAN")
	}
}

// TestFlagStoreRedisReasonWithPipeSurvivesRestart is the decoy path that made
// the encoding matter.
//
// Flag used to serialise as reason|score|timestamp and loadFromRedis split on
// the first two pipes, so a reason containing a pipe shifted the score and
// timestamp. The timestamp failed to parse, ExpiresAt landed in year one, and
// the entry was dropped as expired. Decoy reasons are "decoy:" plus the raw
// request path, and a pipe is legal in a URL path, so GET /wp-admin/a|b flagged
// an attacker in memory and then forgot them on the next restart. Old rows
// without a pipe in the reason must keep loading, which is why the writer also
// stores a plain decoy reason next to the pipe-bearing one.
func TestFlagStoreRedisReasonWithPipeSurvivesRestart(t *testing.T) {
	f := newFakeRedis(t)

	writer := NewFlagStore(24*time.Hour, f.addr())
	writer.Flag("198.51.100.4", "decoy:/wp-admin/a|b", 100)
	writer.Flag("198.51.100.5", "decoy:/wp-admin", 100)
	writer.Flag("198.51.100.6", "manual|investigation|notes", 80)
	writer.Close()

	if _, ok := f.snapshot()["bridge:flag:198.51.100.4"]; !ok {
		t.Fatal("the pipe-bearing flag never reached Redis")
	}

	reloaded := NewFlagStore(24*time.Hour, f.addr())
	defer reloaded.Close()

	if !reloaded.IsFlagged("198.51.100.5") {
		t.Error("a plain reason did not survive the restart")
	}
	if !reloaded.IsFlagged("198.51.100.4") {
		t.Fatal("a pipe-bearing decoy reason was dropped on reload")
	}
	if !reloaded.IsFlagged("198.51.100.6") {
		t.Fatal("a multi-pipe admin reason was dropped on reload")
	}

	byIP := map[string]FlagEntry{}
	for _, e := range reloaded.List() {
		byIP[e.IP] = e
	}
	if got := byIP["198.51.100.4"]; got.Reason != "decoy:/wp-admin/a|b" || got.Score != 100 {
		t.Errorf("198.51.100.4 restored as %q/%d, want decoy:/wp-admin/a|b/100", got.Reason, got.Score)
	}
	if got := byIP["198.51.100.5"]; got.Reason != "decoy:/wp-admin" || got.Score != 100 {
		t.Errorf("198.51.100.5 restored as %q/%d, want decoy:/wp-admin/100", got.Reason, got.Score)
	}
	if got := byIP["198.51.100.6"]; got.Reason != "manual|investigation|notes" || got.Score != 80 {
		t.Errorf("198.51.100.6 restored as %q/%d, want manual|investigation|notes/80", got.Reason, got.Score)
	}
}

// TestParseFlagValueSplitsFromTheRight is the parser itself, including the
// truncated and unparseable rows loadFromRedis has to skip. The reload tests
// prove a Flag() write comes back; this table proves a hostile or partial
// value cannot shift the timestamp into a live expiry.
func TestParseFlagValueSplitsFromTheRight(t *testing.T) {
	ts := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	encoded := ts.Format(time.RFC3339)

	tests := []struct {
		name       string
		val        string
		wantOK     bool
		wantReason string
		wantScore  int
		wantZero   bool
	}{
		{
			name:       "legacy three field row",
			val:        "auto:rate_exceeded|150|" + encoded,
			wantOK:     true,
			wantReason: "auto:rate_exceeded",
			wantScore:  150,
		},
		{
			name:       "pipe in a decoy path",
			val:        "decoy:/wp-admin/a|b|100|" + encoded,
			wantOK:     true,
			wantReason: "decoy:/wp-admin/a|b",
			wantScore:  100,
		},
		{
			name:       "several pipes in an admin reason",
			val:        "a|b|c|80|" + encoded,
			wantOK:     true,
			wantReason: "a|b|c",
			wantScore:  80,
		},
		{
			name:   "truncated, no timestamp",
			val:    "auto:score|100",
			wantOK: false,
		},
		{
			name:   "no separators",
			val:    "not-a-flag",
			wantOK: false,
		},
		{
			name:       "unparseable timestamp still reports the reason",
			val:        "auto:score|100|not-a-timestamp",
			wantOK:     true,
			wantReason: "auto:score",
			wantScore:  100,
			wantZero:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, score, flaggedAt, ok := parseFlagValue(tt.val)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (reason=%q score=%d at=%v)", ok, tt.wantOK, reason, score, flaggedAt)
			}
			if !tt.wantOK {
				return
			}
			if reason != tt.wantReason || score != tt.wantScore {
				t.Errorf("parsed %q/%d, want %q/%d", reason, score, tt.wantReason, tt.wantScore)
			}
			if tt.wantZero {
				if !flaggedAt.IsZero() {
					t.Errorf("flaggedAt = %v, want zero for an unparseable timestamp", flaggedAt)
				}
				return
			}
			if !flaggedAt.Equal(ts) {
				t.Errorf("flaggedAt = %v, want %v", flaggedAt, ts)
			}
		})
	}
}

// TestFlagStoreCloseIsSafeWithoutRedis keeps shutdown from depending on whether
// persistence was configured. main defers Close unconditionally.
func TestFlagStoreCloseIsSafeWithoutRedis(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	fs.Close()
	fs.Close()
}
