package email

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// A relay that accepts the connection and never sends its banner must not hold
// the sender, or the socket, past the deadline. net/smtp takes no context, so
// the select in Send returned on time while the goroutine it abandoned sat in
// the banner read forever with the connection open; in production that was a
// deferwork worker per stalled send, and eight of them stop all auth mail.
func TestSendGivesUpOnARelayThatNeverAnswers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	closed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Never write a banner. Read until the client hangs up.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		close(closed)
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	s := NewSMTPSender(host, port, "", "", "noreply@example.test")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Send(ctx, Address{}, "user@example.test", "subject", "<p>x</p>", "x")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send = %v, want context.DeadlineExceeded", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Send took %v against a 300ms deadline", took)
	}

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the SMTP connection was still open 3s after Send gave up: the conversation " +
			"has no deadline of its own and leaks with its goroutine")
	}
}

// The two ways a send can meet its deadline must read the same to a caller:
// ctx.Done answers context.DeadlineExceeded, so a conversation that died on
// the socket's copy of that deadline has to as well.
func TestConversationResultReportsTheSocketDeadlineAsTheSendDeadline(t *testing.T) {
	timedOut := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	if err := conversationResult(fmt.Errorf("email: smtp connect x: %w", timedOut)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a socket deadline came back as %v, not context.DeadlineExceeded", err)
	}
	refused := errors.New("email: smtp connect x: connection refused")
	if err := conversationResult(refused); err != refused {
		t.Errorf("an unrelated failure came back as %v; it must pass through unchanged", err)
	}
	if err := conversationResult(nil); err != nil {
		t.Errorf("a delivered message came back as %v", err)
	}
}
