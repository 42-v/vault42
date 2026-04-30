package redis

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// RESP protocol type markers.
const (
	respStatus = '+' // Simple string
	respError  = '-' // Error
	respInt    = ':' // Integer
	respBulk   = '$' // Bulk string
	respArray  = '*' // Array
)

// writeCommand encodes a Redis command in RESP2 format and writes it to w.
// Format: *<numargs>\r\n$<len>\r\n<arg>\r\n ...
func writeCommand(w *bufio.Writer, args ...string) error {
	// Array header: *N\r\n
	if err := w.WriteByte(respArray); err != nil {
		return err
	}
	if _, err := w.WriteString(strconv.Itoa(len(args))); err != nil {
		return err
	}
	if _, err := w.WriteString("\r\n"); err != nil {
		return err
	}

	// Each argument as bulk string: $<len>\r\n<data>\r\n
	for _, arg := range args {
		if err := w.WriteByte(respBulk); err != nil {
			return err
		}
		if _, err := w.WriteString(strconv.Itoa(len(arg))); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
		if _, err := w.WriteString(arg); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
	}

	return w.Flush()
}

// readReply reads one RESP reply from the reader.
// Returns the parsed value: string, int64, nil, or error.
type reply struct {
	str   string // for status/bulk string replies
	num   int64  // for integer replies
	isNil bool   // for nil bulk string ($-1)
}

// readReply reads a single RESP2 reply.
func readReply(r *bufio.Reader) (reply, error) {
	line, err := readLine(r)
	if err != nil {
		return reply{}, err
	}
	if len(line) == 0 {
		return reply{}, errors.New("redis: empty response line")
	}

	switch line[0] {
	case respStatus:
		// +OK\r\n → "OK"
		return reply{str: string(line[1:])}, nil

	case respError:
		// -ERR message\r\n → error
		return reply{}, &RedisError{Msg: string(line[1:])}

	case respInt:
		// :42\r\n → 42
		n, err := strconv.ParseInt(string(line[1:]), 10, 64)
		if err != nil {
			return reply{}, fmt.Errorf("redis: invalid integer %q", line[1:])
		}
		return reply{num: n}, nil

	case respBulk:
		// $<len>\r\n<data>\r\n or $-1\r\n (nil)
		n, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return reply{}, fmt.Errorf("redis: invalid bulk length %q", line[1:])
		}
		if n < 0 {
			return reply{isNil: true}, nil
		}
		if n > 64*1024*1024 {
			return reply{}, fmt.Errorf("redis: bulk string too large: %d", n)
		}
		// Read exactly n bytes + \r\n
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return reply{}, fmt.Errorf("redis: read bulk data: %w", err)
		}
		return reply{str: string(buf[:n])}, nil

	default:
		return reply{}, fmt.Errorf("redis: unexpected reply type %q", string(line[0]))
	}
}

// readLine reads a RESP line (terminated by \r\n) and returns it without the terminator.
func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("redis: read line: %w", err)
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, errors.New("redis: invalid line terminator")
	}
	return line[:len(line)-2], nil
}
