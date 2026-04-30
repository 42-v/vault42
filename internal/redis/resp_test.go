package redis

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWriteCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "PING",
			args: []string{"PING"},
			want: "*1\r\n$4\r\nPING\r\n",
		},
		{
			name: "GET",
			args: []string{"GET", "mykey"},
			want: "*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n",
		},
		{
			name: "SET with value",
			args: []string{"SET", "key", "value"},
			want: "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n",
		},
		{
			name: "SET with EX",
			args: []string{"SET", "key", "val", "EX", "60"},
			want: "*5\r\n$3\r\nSET\r\n$3\r\nkey\r\n$3\r\nval\r\n$2\r\nEX\r\n$2\r\n60\r\n",
		},
		{
			name: "SET with NX",
			args: []string{"SET", "key", "val", "NX"},
			want: "*4\r\n$3\r\nSET\r\n$3\r\nkey\r\n$3\r\nval\r\n$2\r\nNX\r\n",
		},
		{
			name: "DEL",
			args: []string{"DEL", "mykey"},
			want: "*2\r\n$3\r\nDEL\r\n$5\r\nmykey\r\n",
		},
		{
			name: "GETDEL",
			args: []string{"GETDEL", "mykey"},
			want: "*2\r\n$6\r\nGETDEL\r\n$5\r\nmykey\r\n",
		},
		{
			name: "INCR",
			args: []string{"INCR", "counter"},
			want: "*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n",
		},
		{
			name: "EXPIRE",
			args: []string{"EXPIRE", "key", "60"},
			want: "*3\r\n$6\r\nEXPIRE\r\n$3\r\nkey\r\n$2\r\n60\r\n",
		},
		{
			name: "EXISTS",
			args: []string{"EXISTS", "key"},
			want: "*2\r\n$6\r\nEXISTS\r\n$3\r\nkey\r\n",
		},
		{
			name: "AUTH",
			args: []string{"AUTH", "password123"},
			want: "*2\r\n$4\r\nAUTH\r\n$11\r\npassword123\r\n",
		},
		{
			name: "SELECT",
			args: []string{"SELECT", "1"},
			want: "*2\r\n$6\r\nSELECT\r\n$1\r\n1\r\n",
		},
		{
			name: "empty value",
			args: []string{"SET", "key", ""},
			want: "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$0\r\n\r\n",
		},
		{
			name: "binary-safe value with spaces",
			args: []string{"SET", "key", "hello world"},
			want: "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$11\r\nhello world\r\n",
		},
		{
			name: "value with CRLF",
			args: []string{"SET", "key", "line1\r\nline2"},
			want: "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$12\r\nline1\r\nline2\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := bufio.NewWriter(&buf)
			if err := writeCommand(w, tt.args...); err != nil {
				t.Fatalf("writeCommand: %v", err)
			}
			got := buf.String()
			if got != tt.want {
				t.Errorf("writeCommand(%v)\n  got:  %q\n  want: %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestReadReply_Status(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("+OK\r\n"))
	rep, err := readReply(r)
	if err != nil {
		t.Fatalf("readReply: %v", err)
	}
	if rep.str != "OK" {
		t.Errorf("expected OK, got %q", rep.str)
	}
	if rep.isNil {
		t.Error("expected isNil=false")
	}
}

func TestReadReply_PONG(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("+PONG\r\n"))
	rep, err := readReply(r)
	if err != nil {
		t.Fatalf("readReply: %v", err)
	}
	if rep.str != "PONG" {
		t.Errorf("expected PONG, got %q", rep.str)
	}
}

func TestReadReply_Error(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("-ERR unknown command\r\n"))
	_, err := readReply(r)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var redisErr *RedisError
	if !errors.As(err, &redisErr) {
		t.Fatalf("expected RedisError, got %T: %v", err, err)
	}
	if redisErr.Msg != "ERR unknown command" {
		t.Errorf("expected message 'ERR unknown command', got %q", redisErr.Msg)
	}
}

func TestReadReply_Integer(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{":0\r\n", 0},
		{":1\r\n", 1},
		{":42\r\n", 42},
		{":-1\r\n", -1},
		{":1000000\r\n", 1000000},
	}
	for _, tt := range tests {
		r := bufio.NewReader(strings.NewReader(tt.input))
		rep, err := readReply(r)
		if err != nil {
			t.Fatalf("readReply(%q): %v", tt.input, err)
		}
		if rep.num != tt.want {
			t.Errorf("readReply(%q): got %d, want %d", tt.input, rep.num, tt.want)
		}
	}
}

func TestReadReply_BulkString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "$5\r\nhello\r\n", "hello"},
		{"empty", "$0\r\n\r\n", ""},
		{"with spaces", "$11\r\nhello world\r\n", "hello world"},
		{"numeric value", "$1\r\n2\r\n", "2"},
		{"large", "$10\r\n0123456789\r\n", "0123456789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tt.input))
			rep, err := readReply(r)
			if err != nil {
				t.Fatalf("readReply: %v", err)
			}
			if rep.str != tt.want {
				t.Errorf("got %q, want %q", rep.str, tt.want)
			}
			if rep.isNil {
				t.Error("expected isNil=false")
			}
		})
	}
}

func TestReadReply_NilBulk(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("$-1\r\n"))
	rep, err := readReply(r)
	if err != nil {
		t.Fatalf("readReply: %v", err)
	}
	if !rep.isNil {
		t.Error("expected isNil=true")
	}
}

func TestReadReply_InvalidType(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("~invalid\r\n"))
	_, err := readReply(r)
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
}

func TestReadReply_InvalidInteger(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(":notanumber\r\n"))
	_, err := readReply(r)
	if err == nil {
		t.Fatal("expected error for invalid integer")
	}
}

func TestReadReply_InvalidBulkLength(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("$abc\r\n"))
	_, err := readReply(r)
	if err == nil {
		t.Fatal("expected error for invalid bulk length")
	}
}

func TestReadReply_TruncatedBulk(t *testing.T) {
	// Claim 10 bytes but only provide 3
	r := bufio.NewReader(strings.NewReader("$10\r\nabc"))
	_, err := readReply(r)
	if err == nil {
		t.Fatal("expected error for truncated bulk data")
	}
}

func TestReadLine_EmptyInput(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(""))
	_, err := readLine(r)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestReadLine_NoTerminator(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("just text\n"))
	_, err := readLine(r)
	if err == nil {
		t.Fatal("expected error for missing \\r before \\n")
	}
}
