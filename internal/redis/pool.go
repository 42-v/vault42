package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultPoolSize    = 10
	defaultDialTimeout = 5 * time.Second
	defaultIOTimeout   = 3 * time.Second
	defaultIdleTimeout = 5 * time.Minute
	reapInterval       = 30 * time.Second
	healthCheckTimeout = 2 * time.Second
)

// conn wraps a TCP connection with a buffered reader/writer.
type conn struct {
	netConn  net.Conn
	rd       *bufio.Reader
	wr       *bufio.Writer
	lastUsed time.Time
}

// pool is a thread-safe connection pool for Redis.
type pool struct {
	mu       sync.Mutex
	idle     []*conn
	active   int32 // atomic: number of connections in use
	total    int32 // atomic: total connections (idle + active)
	closed   int32 // atomic: 1 if pool is closed
	maxConns int
	sem      chan struct{} // semaphore: limits total concurrent connections
	opts     *Options
	done     chan struct{}
}

func newPool(opts *Options) *pool {
	size := opts.PoolSize
	if size <= 0 {
		size = defaultPoolSize
	}
	sem := make(chan struct{}, size)
	for i := 0; i < size; i++ {
		sem <- struct{}{}
	}
	p := &pool{
		idle:     make([]*conn, 0, size),
		maxConns: size,
		sem:      sem,
		opts:     opts,
		done:     make(chan struct{}),
	}
	go p.reaper(reapInterval)
	return p
}

// get acquires a connection from the pool, creating one if needed.
// Blocks if the pool is at capacity until a connection is returned or ctx is done.
func (p *pool) get(ctx context.Context) (*conn, error) {
	if atomic.LoadInt32(&p.closed) == 1 {
		return nil, errors.New("redis: client is closed")
	}

	// Acquire semaphore slot (blocks if pool is full)
	select {
	case <-p.sem:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, errors.New("redis: client is closed")
	}

	// Try to reuse an idle connection
	p.mu.Lock()
	for len(p.idle) > 0 {
		// Pop from the end (LIFO — most recently used connections are healthier)
		cn := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]

		// Check idle timeout
		idleTimeout := p.opts.IdleTimeout
		if idleTimeout <= 0 {
			idleTimeout = defaultIdleTimeout
		}
		if time.Since(cn.lastUsed) > idleTimeout {
			p.mu.Unlock()
			atomic.AddInt32(&p.total, -1)
			cn.netConn.Close() // #nosec G104 -- closing idle-expired connection; error is non-actionable
			p.mu.Lock()
			continue
		}

		atomic.AddInt32(&p.active, 1)
		p.mu.Unlock()

		// Quick health check: set a short deadline and PING
		if err := p.healthCheck(cn); err != nil {
			atomic.AddInt32(&p.active, -1)
			atomic.AddInt32(&p.total, -1)
			cn.netConn.Close() // #nosec G104 -- closing unhealthy connection; already errored
			// Try again with a new connection (we already hold sem slot)
			cn, err := p.dial(ctx)
			if err != nil {
				p.sem <- struct{}{} // release sem slot on failure
			}
			return cn, err
		}

		return cn, nil
	}
	p.mu.Unlock()

	// No idle connections — create a new one (we already hold sem slot)
	cn, err := p.dial(ctx)
	if err != nil {
		p.sem <- struct{}{} // release sem slot on failure
	}
	return cn, err
}

// put returns a healthy connection to the pool.
func (p *pool) put(cn *conn) {
	if atomic.LoadInt32(&p.closed) == 1 {
		atomic.AddInt32(&p.active, -1)
		atomic.AddInt32(&p.total, -1)
		cn.netConn.Close()  // #nosec G104 -- pool closed; connection teardown is best-effort
		p.sem <- struct{}{} // release sem slot
		return
	}

	cn.lastUsed = time.Now()
	atomic.AddInt32(&p.active, -1)

	p.mu.Lock()
	if len(p.idle) < p.maxConns {
		p.idle = append(p.idle, cn)
		p.mu.Unlock()
		p.sem <- struct{}{} // release sem slot
		return
	}
	p.mu.Unlock()

	// Pool is full — discard this connection
	atomic.AddInt32(&p.total, -1)
	cn.netConn.Close()  // #nosec G104 -- discarding excess connection; error is non-actionable
	p.sem <- struct{}{} // release sem slot
}

// remove closes a connection due to an error (don't return to pool).
func (p *pool) remove(cn *conn) {
	atomic.AddInt32(&p.active, -1)
	atomic.AddInt32(&p.total, -1)
	cn.netConn.Close()  // #nosec G104 -- removing errored connection; already failed
	p.sem <- struct{}{} // release sem slot
}

// dial creates a new TCP connection to Redis.
// Caller must hold a semaphore slot.
func (p *pool) dial(ctx context.Context) (*conn, error) {
	dialTimeout := p.opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}

	// Use context deadline if shorter than dial timeout
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		if d := time.Until(deadline); d < dialTimeout {
			dialTimeout = d
		}
	}

	d := net.Dialer{Timeout: dialTimeout}
	var netConn net.Conn
	var err error
	if p.opts.TLS {
		serverName := p.opts.TLSServerName
		if serverName == "" {
			// Parse hostname from address for certificate verification
			serverName, _, _ = net.SplitHostPort(p.opts.Addr)
		}
		// tls.Dialer rather than tls.DialWithDialer, which accepts no context.
		// The handshake is a second round trip after the TCP connect, and on
		// that leg a canceled caller was ignored: the plaintext branch below
		// returns the moment ctx is done, while this one held its pool slot
		// until DialTimeout expired. A peer that completes the TCP connect and
		// then stalls the handshake is the ordinary shape of a half-configured
		// TLS proxy in front of Redis, and every request that reached it during
		// one cost a connection from a pool of ten.
		td := &tls.Dialer{
			NetDialer: &d,
			Config: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: serverName,
				// Nil means the host trust store; see Options.TLSRootCAs for why
				// that is not enough on the runtime image.
				RootCAs: p.opts.TLSRootCAs,
			},
		}
		netConn, err = td.DialContext(ctx, "tcp", p.opts.Addr)
	} else {
		netConn, err = d.DialContext(ctx, "tcp", p.opts.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("redis: dial %s: %w", p.opts.Addr, err)
	}

	cn := &conn{
		netConn:  netConn,
		rd:       bufio.NewReaderSize(netConn, 4096),
		wr:       bufio.NewWriterSize(netConn, 4096),
		lastUsed: time.Now(),
	}

	// Authenticate if password is set
	if p.opts.Password != "" {
		if err := p.initAuth(cn); err != nil {
			cn.netConn.Close() // #nosec G104 -- cleanup after auth failure
			return nil, err
		}
	}

	// Select database if non-zero
	if p.opts.DB > 0 {
		if err := p.initSelect(cn); err != nil {
			cn.netConn.Close() // #nosec G104 -- cleanup after select failure
			return nil, err
		}
	}

	atomic.AddInt32(&p.total, 1)
	atomic.AddInt32(&p.active, 1)
	return cn, nil
}

// initAuth sends AUTH command.
func (p *pool) initAuth(cn *conn) error {
	cn.netConn.SetDeadline(time.Now().Add(defaultIOTimeout)) // #nosec G104 -- deadline errors surface on next I/O op //nolint:errcheck
	defer cn.netConn.SetDeadline(time.Time{})                // #nosec G104 -- deadline errors surface on next I/O op //nolint:errcheck

	if err := writeCommand(cn.wr, "AUTH", p.opts.Password); err != nil {
		return fmt.Errorf("redis: auth write: %w", err)
	}
	r, err := readReply(cn.rd)
	if err != nil {
		return fmt.Errorf("redis: auth: %w", err)
	}
	if r.str != "OK" {
		return fmt.Errorf("redis: auth: unexpected response %q", r.str)
	}
	return nil
}

// initSelect sends SELECT command.
func (p *pool) initSelect(cn *conn) error {
	cn.netConn.SetDeadline(time.Now().Add(defaultIOTimeout)) // #nosec G104 -- deadline errors surface on next I/O op //nolint:errcheck
	defer cn.netConn.SetDeadline(time.Time{})                // #nosec G104 -- deadline errors surface on next I/O op //nolint:errcheck

	dbStr := fmt.Sprintf("%d", p.opts.DB)
	if err := writeCommand(cn.wr, "SELECT", dbStr); err != nil {
		return fmt.Errorf("redis: select write: %w", err)
	}
	r, err := readReply(cn.rd)
	if err != nil {
		return fmt.Errorf("redis: select: %w", err)
	}
	if r.str != "OK" {
		return fmt.Errorf("redis: select: unexpected response %q", r.str)
	}
	return nil
}

// healthCheck sends PING on a reused connection.
func (p *pool) healthCheck(cn *conn) error {
	cn.netConn.SetDeadline(time.Now().Add(healthCheckTimeout)) // #nosec G104 -- deadline errors surface on next I/O op //nolint:errcheck
	defer cn.netConn.SetDeadline(time.Time{})                  // #nosec G104 -- deadline errors surface on next I/O op //nolint:errcheck

	if err := writeCommand(cn.wr, "PING"); err != nil {
		return err
	}
	r, err := readReply(cn.rd)
	if err != nil {
		return err
	}
	if r.str != "PONG" {
		return fmt.Errorf("redis: ping: unexpected %q", r.str)
	}
	return nil
}

// reaper periodically closes idle connections that have expired.
func (p *pool) reaper(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.reapIdle()
		}
	}
}

// reapIdle removes expired idle connections.
func (p *pool) reapIdle() {
	idleTimeout := p.opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}
	now := time.Now()

	p.mu.Lock()
	var kept []*conn
	var stale []*conn
	for _, cn := range p.idle {
		if now.Sub(cn.lastUsed) > idleTimeout {
			stale = append(stale, cn)
		} else {
			kept = append(kept, cn)
		}
	}
	p.idle = kept
	p.mu.Unlock()

	for _, cn := range stale {
		atomic.AddInt32(&p.total, -1)
		cn.netConn.Close() // #nosec G104 -- reaping idle-expired connections; error is non-actionable
	}
}

// close shuts down the pool, closing all connections.
func (p *pool) close() error {
	if !atomic.CompareAndSwapInt32(&p.closed, 0, 1) {
		return errors.New("redis: client already closed")
	}

	close(p.done)

	// Drain semaphore to prevent in-flight get() calls from acquiring slots.
	// This blocks until all active connections are returned via put()/remove().
	for i := 0; i < p.maxConns; i++ {
		<-p.sem
	}

	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	var firstErr error
	for _, cn := range idle {
		if err := cn.netConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		atomic.AddInt32(&p.total, -1)
	}
	return firstErr
}
