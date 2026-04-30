package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// FlagEntry represents a flagged IP with metadata.
type FlagEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Score     int       `json:"score"`
	FlaggedAt time.Time `json:"flagged_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// FlagStore manages flagged IPs with optional Redis persistence.
type FlagStore struct {
	mu    sync.RWMutex
	flags map[string]*FlagEntry
	ttl   time.Duration
	redis *redisClient
}

// NewFlagStore creates a new flag store. If redisAddr is non-empty, it connects
// to Redis for persistence and loads existing flags.
func NewFlagStore(ttl time.Duration, redisAddr string) *FlagStore {
	fs := &FlagStore{
		flags: make(map[string]*FlagEntry),
		ttl:   ttl,
	}

	if redisAddr != "" {
		rc, err := newRedisClient(redisAddr)
		if err != nil {
			log.Printf("bridge: redis connection failed, running memory-only: %v", err)
		} else {
			fs.redis = rc
			fs.loadFromRedis()
		}
	}

	return fs
}

// Flag marks an IP as flagged.
func (fs *FlagStore) Flag(ip, reason string, score int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	now := time.Now()
	entry := &FlagEntry{
		IP:        ip,
		Reason:    reason,
		Score:     score,
		FlaggedAt: now,
		ExpiresAt: now.Add(fs.ttl),
	}
	fs.flags[ip] = entry

	if fs.redis != nil {
		val := fmt.Sprintf("%s|%d|%s", reason, score, now.Format(time.RFC3339))
		if err := fs.redis.Set("bridge:flag:"+ip, val, fs.ttl); err != nil {
			log.Printf("bridge: redis SET failed for %s: %v", ip, err) // #nosec G706 -- IP is validated before flag
		}
	}
}

// Unflag removes a flagged IP.
func (fs *FlagStore) Unflag(ip string) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, ok := fs.flags[ip]; !ok {
		return false
	}
	delete(fs.flags, ip)

	if fs.redis != nil {
		if err := fs.redis.Del("bridge:flag:" + ip); err != nil {
			log.Printf("bridge: redis DEL failed for %s: %v", ip, err)
		}
	}
	return true
}

// IsFlagged checks if an IP is currently flagged (memory-only, zero-latency).
func (fs *FlagStore) IsFlagged(ip string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entry, ok := fs.flags[ip]
	if !ok {
		return false
	}
	return time.Now().Before(entry.ExpiresAt)
}

// List returns all currently flagged IPs.
func (fs *FlagStore) List() []FlagEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	now := time.Now()
	var entries []FlagEntry
	for _, e := range fs.flags {
		if now.Before(e.ExpiresAt) {
			entries = append(entries, *e)
		}
	}
	return entries
}

// Reap removes expired entries.
func (fs *FlagStore) Reap() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	now := time.Now()
	for ip, entry := range fs.flags {
		if now.After(entry.ExpiresAt) {
			delete(fs.flags, ip)
		}
	}
}

// Close shuts down the Redis connection if active.
func (fs *FlagStore) Close() {
	if fs.redis != nil {
		fs.redis.Close()
	}
}

func (fs *FlagStore) loadFromRedis() {
	keys, err := fs.redis.Scan("bridge:flag:*")
	if err != nil {
		log.Printf("bridge: redis SCAN failed: %v", err)
		return
	}

	loaded := 0
	for _, key := range keys {
		ip := strings.TrimPrefix(key, "bridge:flag:")
		val, err := fs.redis.Get(key)
		if err != nil {
			continue
		}

		parts := strings.SplitN(val, "|", 3)
		if len(parts) < 3 {
			continue
		}

		reason := parts[0]
		score := 0
		fmt.Sscanf(parts[1], "%d", &score)                 // #nosec G104 -- parse failure leaves score=0
		flaggedAt, _ := time.Parse(time.RFC3339, parts[2]) // #nosec G104 -- parse failure leaves zero time

		entry := &FlagEntry{
			IP:        ip,
			Reason:    reason,
			Score:     score,
			FlaggedAt: flaggedAt,
			ExpiresAt: flaggedAt.Add(fs.ttl),
		}
		if time.Now().Before(entry.ExpiresAt) {
			fs.flags[ip] = entry
			loaded++
		}
	}

	if loaded > 0 {
		log.Printf("bridge: loaded %d flags from Redis", loaded)
	}
}

// Minimal inline RESP2 Redis client — GET, SET (with EX), DEL, SCAN only.

type redisClient struct {
	conn net.Conn
	mu   sync.Mutex
	r    *bufio.Reader
}

func newRedisClient(addr string) (*redisClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &redisClient{
		conn: conn,
		r:    bufio.NewReader(conn),
	}, nil
}

func (rc *redisClient) Close() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.conn.Close() // #nosec G104 -- best-effort close
}

func (rc *redisClient) do(args ...string) (string, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Build RESP array
	cmd := fmt.Sprintf("*%d\r\n", len(args))
	for _, arg := range args {
		cmd += fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg)
	}

	if _, err := rc.conn.Write([]byte(cmd)); err != nil {
		return "", err
	}

	return rc.readReply()
}

func (rc *redisClient) readReply() (string, error) {
	line, err := rc.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")

	switch line[0] {
	case '+': // Simple string
		return line[1:], nil
	case '-': // Error
		return "", fmt.Errorf("redis: %s", line[1:])
	case ':': // Integer
		return line[1:], nil
	case '$': // Bulk string
		n := 0
		fmt.Sscanf(line[1:], "%d", &n) // #nosec G104 -- parse failure leaves n=0, handled below
		if n < 0 {
			return "", nil
		}
		if n > 10*1024*1024 { // 10 MB max
			return "", fmt.Errorf("redis: bulk string too large: %d", n)
		}
		buf := make([]byte, n+2)
		_, err := readFull(rc.r, buf)
		if err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	case '*': // Array
		n := 0
		fmt.Sscanf(line[1:], "%d", &n) // #nosec G104 -- parse failure leaves n=0, handled below
		if n < 0 {
			return "", nil
		}
		if n > 10000 {
			return "", fmt.Errorf("redis: array too large: %d", n)
		}
		var parts []string
		for i := 0; i < n; i++ {
			part, err := rc.readReply()
			if err != nil {
				return "", err
			}
			parts = append(parts, part)
		}
		return strings.Join(parts, "\n"), nil
	default:
		return "", fmt.Errorf("redis: unexpected reply type: %c", line[0])
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := r.Read(buf[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (rc *redisClient) Get(key string) (string, error) {
	return rc.do("GET", key)
}

func (rc *redisClient) Set(key, value string, ttl time.Duration) error {
	_, err := rc.do("SET", key, value, "EX", fmt.Sprintf("%d", int(ttl.Seconds())))
	return err
}

func (rc *redisClient) Del(key string) error {
	_, err := rc.do("DEL", key)
	return err
}

func (rc *redisClient) Scan(pattern string) ([]string, error) {
	var keys []string
	cursor := "0"
	for {
		reply, err := rc.do("SCAN", cursor, "MATCH", pattern, "COUNT", "100")
		if err != nil {
			return nil, err
		}
		parts := strings.SplitN(reply, "\n", 2)
		cursor = parts[0]
		if len(parts) >= 2 {
			if parts[1] != "" {
				for _, k := range strings.Split(parts[1], "\n") {
					if k != "" {
						keys = append(keys, k)
					}
				}
			}
		}
		if cursor == "0" {
			break
		}
	}
	return keys, nil
}
