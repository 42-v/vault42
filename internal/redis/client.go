// Package redis provides a minimal, stdlib-only Redis client for The Vault.
//
// Supports RESP2 protocol with connection pooling, AUTH, SELECT, and the
// command subset needed by the cache layer: PING, GET, SET (with EX/NX),
// DEL, GETDEL, INCR, EXPIRE, EXISTS.
package redis

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Options configures the Redis client.
type Options struct {
	Addr          string        // host:port (required)
	Password      string        // AUTH password (optional)
	DB            int           // SELECT database (default 0)
	PoolSize      int           // max connections (default 10)
	DialTimeout   time.Duration // TCP connect timeout (default 5s)
	IOTimeout     time.Duration // read/write timeout per command (default 3s)
	IdleTimeout   time.Duration // close idle connections after this duration (default 5m)
	TLS           bool          // enable TLS encryption (default false)
	TLSServerName string        // TLS ServerName for certificate verification (default: hostname from Addr)

	// TLSRootCAs is the set of roots the server certificate is verified
	// against. Nil falls back to the host trust store, which is correct for a
	// managed Redis holding a publicly rooted certificate and useless for an
	// in-cluster one: the runtime image is distroless-static and carries public
	// roots only, so a private CA is not in it and every dial fails
	// verification with nothing an operator can set to fix it. The pool is
	// supplied by the caller for the same reason cmd/admin-gateway builds its
	// ClientCAs there -- reading the PEM at startup turns an unreadable or
	// malformed bundle into a refused boot instead of a cache that quietly
	// never connects.
	TLSRootCAs *x509.CertPool
}

// Client is a Redis client with connection pooling.
type Client struct {
	opts *Options
	pool *pool
}

// NewClient creates a new Redis client.
func NewClient(opts *Options) *Client {
	if opts.IOTimeout <= 0 {
		opts.IOTimeout = defaultIOTimeout
	}
	return &Client{
		opts: opts,
		pool: newPool(opts),
	}
}

// Ping sends a PING command and returns an error if the server is unreachable.
func (c *Client) Ping(ctx context.Context) error {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return err
	}

	r, err := c.exec(ctx, cn, "PING")
	if err != nil {
		return err
	}
	if r.str != "PONG" {
		return fmt.Errorf("redis: ping: unexpected %q", r.str)
	}
	return nil
}

// Get retrieves the string value of key. Returns Nil error if key does not exist.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return "", err
	}

	r, err := c.exec(ctx, cn, "GET", key)
	if err != nil {
		return "", err
	}
	if r.isNil {
		return "", Nil
	}
	return r.str, nil
}

// Set stores a key-value pair. If ttl > 0, sets EX (expiry in seconds).
// Sub-second TTLs use PX (milliseconds).
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return err
	}

	var r reply
	if ttl <= 0 {
		r, err = c.exec(ctx, cn, "SET", key, value)
	} else if ttl < time.Second || ttl%time.Second != 0 {
		// Use PX for sub-second precision
		r, err = c.exec(ctx, cn, "SET", key, value, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	} else {
		r, err = c.exec(ctx, cn, "SET", key, value, "EX", strconv.FormatInt(int64(ttl.Seconds()), 10))
	}
	if err != nil {
		return err
	}
	if r.str != "OK" {
		return fmt.Errorf("redis: set: unexpected %q", r.str)
	}
	return nil
}

// SetNX sets key to value only if key does not already exist (SET key value NX).
// Returns true if the key was set, false if it already existed.
// If ttl > 0, also sets EX/PX.
func (c *Client) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return false, err
	}

	var r reply
	if ttl <= 0 {
		r, err = c.exec(ctx, cn, "SET", key, value, "NX")
	} else if ttl < time.Second || ttl%time.Second != 0 {
		r, err = c.exec(ctx, cn, "SET", key, value, "PX", strconv.FormatInt(ttl.Milliseconds(), 10), "NX")
	} else {
		r, err = c.exec(ctx, cn, "SET", key, value, "EX", strconv.FormatInt(int64(ttl.Seconds()), 10), "NX")
	}
	if err != nil {
		return false, err
	}
	// Redis returns nil ($-1) when NX condition not met (key exists),
	// and +OK when the key was successfully set.
	if r.isNil {
		return false, nil
	}
	return r.str == "OK", nil
}

// Del deletes one or more keys. Returns the number of keys deleted.
func (c *Client) Del(ctx context.Context, keys ...string) (int64, error) {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return 0, err
	}

	args := make([]string, 0, 1+len(keys))
	args = append(args, "DEL")
	args = append(args, keys...)

	r, err := c.exec(ctx, cn, args...)
	if err != nil {
		return 0, err
	}
	return r.num, nil
}

// GetDel atomically gets the value of key and deletes it.
// Returns Nil error if key does not exist.
func (c *Client) GetDel(ctx context.Context, key string) (string, error) {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return "", err
	}

	r, err := c.exec(ctx, cn, "GETDEL", key)
	if err != nil {
		return "", err
	}
	if r.isNil {
		return "", Nil
	}
	return r.str, nil
}

// Incr atomically increments the integer value at key by 1.
// Returns the new value after incrementing. Creates key with value 1 if it doesn't exist.
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return 0, err
	}

	r, err := c.exec(ctx, cn, "INCR", key)
	if err != nil {
		return 0, err
	}
	return r.num, nil
}

// Expire sets a timeout on key. Returns true if the timeout was set,
// false if the key does not exist.
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return false, err
	}

	r, err := c.exec(ctx, cn, "EXPIRE", key, strconv.FormatInt(int64(ttl.Seconds()), 10))
	if err != nil {
		return false, err
	}
	return r.num == 1, nil
}

// Exists checks if key exists. Returns true if it does.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return false, err
	}

	r, err := c.exec(ctx, cn, "EXISTS", key)
	if err != nil {
		return false, err
	}
	return r.num > 0, nil
}

// Eval executes a Lua script on the Redis server using the EVAL command.
// numkeys specifies how many of the args are KEYS (the rest are ARGV).
// Returns the integer result of the script.
func (c *Client) Eval(ctx context.Context, script string, numkeys int, args ...string) (int64, error) {
	cn, err := c.pool.get(ctx)
	if err != nil {
		return 0, err
	}

	cmdArgs := make([]string, 0, 3+len(args))
	cmdArgs = append(cmdArgs, "EVAL", script, strconv.Itoa(numkeys))
	cmdArgs = append(cmdArgs, args...)

	r, err := c.exec(ctx, cn, cmdArgs...)
	if err != nil {
		return 0, err
	}
	return r.num, nil
}

// Close shuts down the client and releases all connections.
func (c *Client) Close() error {
	return c.pool.close()
}

// exec sends a command on the given connection and handles pool return/removal.
func (c *Client) exec(ctx context.Context, cn *conn, args ...string) (reply, error) {
	// A caller who has already given up must not have their command executed.
	// GETDEL and SET NX are consumed on the server whether or not anyone is
	// still listening, so sending one anyway burns a single-use email
	// verification token, password reset token, OAuth exchange code or PKCE
	// verifier on behalf of a request that will never see the reply. Returning
	// the connection rather than removing it matters too: an expired deadline
	// belongs to the caller, not to the socket, and treating it as a broken
	// connection made a burst of timed-out requests drain the pool at exactly
	// the moment the cache was already slow.
	if err := ctx.Err(); err != nil {
		c.pool.put(cn)
		return reply{}, err
	}

	ioTimeout := c.opts.IOTimeout

	// Respect context deadline if shorter
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d < ioTimeout {
			ioTimeout = d
		}
	}

	deadline := time.Now().Add(ioTimeout)
	cn.netConn.SetDeadline(deadline) // #nosec G104 -- deadline errors surface on next I/O op //nolint:errcheck

	if err := writeCommand(cn.wr, args...); err != nil {
		c.pool.remove(cn)
		return reply{}, fmt.Errorf("redis: write %s: %w", args[0], err)
	}

	r, err := readReply(cn.rd)
	if err != nil {
		// A key that does not exist is never an error here: readReply turns the
		// $-1 bulk reply into reply{isNil: true} with a nil error (resp.go), and
		// the Nil sentinel is produced by Get/GetDel from r.isNil after exec has
		// already returned. So err is always a real failure at this point.
		//
		// ServerError is a server error (e.g., WRONGTYPE), connection is still healthy
		var redisErr *ServerError
		if errors.As(err, &redisErr) {
			cn.netConn.SetDeadline(time.Time{}) // #nosec G104 -- deadline clear; errors surface on next I/O op //nolint:errcheck
			c.pool.put(cn)
			return reply{}, err
		}
		// Network/protocol error — remove connection from pool
		c.pool.remove(cn)
		return reply{}, err
	}

	cn.netConn.SetDeadline(time.Time{}) // #nosec G104 -- deadline clear; errors surface on next I/O op //nolint:errcheck
	c.pool.put(cn)
	return r, nil
}
