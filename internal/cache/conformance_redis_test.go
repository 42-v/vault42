package cache

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRedis is an in-process RESP2 server covering the command subset
// RedisCache issues. It exists so the Redis backend can be held to the same
// behavioral table as the memory backend without a container: the Redis half of
// this package was previously exercised only through constructor error paths
// and a nil client, and Increment (which goes through EVAL) had never run at
// all.
type fakeRedis struct {
	ln   net.Listener
	mu   sync.Mutex
	data map[string]fakeEntry
	// evalArgs records the argument vector of every EVAL, so a test can pin
	// what the client actually asks the server for rather than trusting the
	// server's interpretation of it.
	evalArgs [][]string
	done     chan struct{}
	wg       sync.WaitGroup
}

type fakeEntry struct {
	value     string
	expiresAt time.Time
}

func newFakeRedis(t *testing.T) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeRedis{ln: ln, data: make(map[string]fakeEntry), done: make(chan struct{})}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(f.close)
	return f
}

func (f *fakeRedis) addr() string { return f.ln.Addr().String() }

func (f *fakeRedis) close() {
	select {
	case <-f.done:
		return
	default:
	}
	close(f.done)
	_ = f.ln.Close()
	f.wg.Wait()
}

func (f *fakeRedis) evals() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.evalArgs))
	copy(out, f.evalArgs)
	return out
}

func (f *fakeRedis) serve() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			select {
			case <-f.done:
				return
			default:
				continue
			}
		}
		f.wg.Add(1)
		go f.handle(c)
	}
}

// live reports the entry under key if it exists and has not expired, deleting
// it first if it has. Redis evicts lazily on access, which is the behavior the
// backends are being compared against.
func (f *fakeRedis) live(key string) (fakeEntry, bool) {
	e, ok := f.data[key]
	if !ok {
		return fakeEntry{}, false
	}
	if !e.expiresAt.IsZero() && !time.Now().Before(e.expiresAt) {
		delete(f.data, key)
		return fakeEntry{}, false
	}
	return e, true
}

func (f *fakeRedis) handle(c net.Conn) {
	defer f.wg.Done()
	defer c.Close() //nolint:errcheck // test peer teardown

	rd := bufio.NewReader(c)
	wr := bufio.NewWriter(c)
	for {
		select {
		case <-f.done:
			return
		default:
		}
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		args, err := readArray(rd)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if len(args) == 0 {
			continue
		}
		f.dispatch(args, wr)
		if err := wr.Flush(); err != nil {
			return
		}
	}
}

//nolint:gocognit // one switch arm per supported command; splitting it hides the protocol mapping
func (f *fakeRedis) dispatch(args []string, wr *bufio.Writer) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch strings.ToUpper(args[0]) {
	case "PING":
		writeStatus(wr, "PONG")
	case "AUTH", "SELECT":
		writeStatus(wr, "OK")
	case "GET":
		if e, ok := f.live(args[1]); ok {
			writeBulk(wr, e.value)
		} else {
			writeNil(wr)
		}
	case "GETDEL":
		if e, ok := f.live(args[1]); ok {
			delete(f.data, args[1])
			writeBulk(wr, e.value)
		} else {
			writeNil(wr)
		}
	case "EXISTS":
		if _, ok := f.live(args[1]); ok {
			writeInt(wr, 1)
		} else {
			writeInt(wr, 0)
		}
	case "DEL":
		n := 0
		for _, k := range args[1:] {
			if _, ok := f.data[k]; ok {
				delete(f.data, k)
				n++
			}
		}
		writeInt(wr, int64(n))
	case "SET":
		f.set(args, wr)
	case "INCR":
		writeInt(wr, f.incr(args[1]))
	case "EXPIRE", "PEXPIRE":
		unit := time.Second
		if strings.EqualFold(args[0], "PEXPIRE") {
			unit = time.Millisecond
		}
		n, _ := strconv.ParseInt(args[2], 10, 64)
		e, ok := f.data[args[1]]
		if !ok {
			writeInt(wr, 0)
			return
		}
		if n <= 0 {
			// Redis deletes the key outright for a non-positive expiry.
			delete(f.data, args[1])
			writeInt(wr, 1)
			return
		}
		e.expiresAt = time.Now().Add(time.Duration(n) * unit)
		f.data[args[1]] = e
		writeInt(wr, 1)
	case "EVAL":
		f.eval(args, wr)
	default:
		writeErr(wr, "unknown command '"+args[0]+"'")
	}
}

func (f *fakeRedis) set(args []string, wr *bufio.Writer) {
	if len(args) < 3 {
		writeErr(wr, "wrong number of arguments for 'set' command")
		return
	}
	key, value := args[1], args[2]
	var ttl time.Duration
	nx := false
	for i := 3; i < len(args); i++ {
		switch strings.ToUpper(args[i]) {
		case "EX":
			if i+1 < len(args) {
				i++
				n, _ := strconv.ParseInt(args[i], 10, 64)
				ttl = time.Duration(n) * time.Second
			}
		case "PX":
			if i+1 < len(args) {
				i++
				n, _ := strconv.ParseInt(args[i], 10, 64)
				ttl = time.Duration(n) * time.Millisecond
			}
		case "NX":
			nx = true
		}
	}
	if nx {
		if _, ok := f.live(key); ok {
			writeNil(wr)
			return
		}
	}
	e := fakeEntry{value: value}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	}
	f.data[key] = e
	writeStatus(wr, "OK")
}

func (f *fakeRedis) incr(key string) int64 {
	var n int64
	exp := time.Time{}
	if e, ok := f.live(key); ok {
		n, _ = strconv.ParseInt(e.value, 10, 64)
		exp = e.expiresAt
	}
	n++
	f.data[key] = fakeEntry{value: strconv.FormatInt(n, 10), expiresAt: exp}
	return n
}

// eval runs the one script this package ships, following the script text rather
// than its intent: INCR, then set the expiry only when the counter came back as
// 1. The unit of ARGV[1] is taken from whichever expiry command the script
// names, so the fake stays faithful to the script as written instead of to the
// script as intended. Anything else is answered as an error, so a change the
// fake has not been taught shows up as a failure rather than passing silently.
func (f *fakeRedis) eval(args []string, wr *bufio.Writer) {
	f.evalArgs = append(f.evalArgs, append([]string(nil), args...))
	if len(args) < 5 || args[1] != incrWithExpireScript {
		writeErr(wr, "fakeRedis: unrecognized script")
		return
	}
	unit := time.Second
	if strings.Contains(args[1], "PEXPIRE") {
		unit = time.Millisecond
	}
	key := args[3]
	n := f.incr(key)
	if n == 1 {
		d, err := strconv.ParseInt(args[4], 10, 64)
		if err == nil && d > 0 {
			e := f.data[key]
			e.expiresAt = time.Now().Add(time.Duration(d) * unit)
			f.data[key] = e
		}
	}
	writeInt(wr, n)
}

func writeStatus(w *bufio.Writer, s string) { fmt.Fprintf(w, "+%s\r\n", s) }
func writeErr(w *bufio.Writer, s string)    { fmt.Fprintf(w, "-ERR %s\r\n", s) }
func writeInt(w *bufio.Writer, n int64)     { fmt.Fprintf(w, ":%d\r\n", n) }
func writeNil(w *bufio.Writer)              { fmt.Fprint(w, "$-1\r\n") }
func writeBulk(w *bufio.Writer, s string)   { fmt.Fprintf(w, "$%d\r\n%s\r\n", len(s), s) }

// readArray parses one RESP2 command array. It reads bulk payloads by length so
// a key or value containing CRLF round-trips exactly, which is the property the
// binary-safety case in the conformance table depends on.
func readArray(rd *bufio.Reader) ([]string, error) {
	line, err := readCRLF(rd)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("fakeRedis: expected array, got %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := readCRLF(rd)
		if err != nil {
			return nil, err
		}
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, fmt.Errorf("fakeRedis: expected bulk, got %q", hdr)
		}
		size, err := strconv.Atoi(hdr[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(rd, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

func readCRLF(rd *bufio.Reader) (string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}
