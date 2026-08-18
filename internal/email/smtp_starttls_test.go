package email

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ASVS V12.3.1 / AR-23. Every credential vault42 mails — the verification link,
// the password-reset link, the email one-time code — is a bearer secret for the
// duration of its TTL. smtp.SendMail upgrades to TLS only when the server
// advertises STARTTLS, so an on-path attacker who strips the capability from
// the EHLO response gets the whole message in cleartext and the send still
// reports success. Requiring STARTTLS is what turns that into a failed send.

func TestSendRefusesAServerThatDoesNotOfferSTARTTLS(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "s@t.com")
	err := sender.Send(context.Background(), Address{}, "r@t.com", "Reset your password",
		"<a href=\"https://vault.test/reset?token=SECRET\">reset</a>", "https://vault.test/reset?token=SECRET")

	if err == nil {
		t.Fatal("Send succeeded against a server that never offered STARTTLS; the reset link went out in cleartext")
	}
	if !errors.Is(err, ErrSMTPNoSTARTTLS) {
		t.Fatalf("Send error = %v, want ErrSMTPNoSTARTTLS", err)
	}
	if msgs := srv.messages(); len(msgs) != 0 {
		t.Fatalf("server received %d messages; the send must fail closed before DATA", len(msgs))
	}
}

func TestSendAllowsPlaintextOnlyWhenTheOperatorOptsIn(t *testing.T) {
	srv := newMockSMTPServer(t)
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "s@t.com", AllowPlaintext(true))
	if err := sender.Send(context.Background(), Address{}, "r@t.com", "Sub", "<b>h</b>", "t"); err != nil {
		t.Fatalf("Send with the plaintext opt-out failed: %v", err)
	}
	if msgs := srv.messages(); len(msgs) != 1 {
		t.Fatalf("server received %d messages, want 1", len(msgs))
	}
}

// A conversation that fails after the transport decision is still a failed
// send: the message is not queued and Send says so.
func TestSendReportsAMidConversationRefusal(t *testing.T) {
	srv := newMockSMTPServer(t)
	srv.failData = true
	defer srv.close()

	sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "s@t.com", AllowPlaintext(true))
	err := sender.Send(context.Background(), Address{}, "r@t.com", "Sub", "<b>h</b>", "t")

	if err == nil {
		t.Fatal("Send succeeded although the server refused the message body")
	}
	if !strings.Contains(err.Error(), "smtp send") {
		t.Fatalf("Send error = %v, want the SMTP conversation failure", err)
	}
	if msgs := srv.messages(); len(msgs) != 0 {
		t.Fatalf("server recorded %d messages for a refused transaction", len(msgs))
	}
}

// A server that advertises STARTTLS is upgraded, opt-out or not: the opt-out
// permits plaintext where TLS is unavailable, it does not decline TLS that is
// on offer.
func TestSendUpgradesWheneverSTARTTLSIsAdvertised(t *testing.T) {
	for _, allowPlaintext := range []bool{false, true} {
		t.Run(map[bool]string{false: "required", true: "opt-out set"}[allowPlaintext], func(t *testing.T) {
			srv := newMockSMTPServer(t)
			srv.advertiseSTARTTLS = true
			defer srv.close()

			sender := NewSMTPSender("127.0.0.1", srv.port(), "", "", "s@t.com", AllowPlaintext(allowPlaintext))
			err := sender.Send(context.Background(), Address{}, "r@t.com", "Sub", "<b>h</b>", "t")

			// The mock accepts STARTTLS and then hangs up rather than serving a
			// certificate, so the handshake fails. That the failure is a TLS
			// failure is the point: the client attempted the upgrade.
			if err == nil {
				t.Fatal("Send succeeded although the STARTTLS handshake could not complete")
			}
			if !strings.Contains(err.Error(), "starttls") {
				t.Fatalf("Send error = %v, want a STARTTLS handshake failure", err)
			}
			if got := srv.starttlsAttempts(); got != 1 {
				t.Fatalf("STARTTLS attempts = %d, want 1", got)
			}
		})
	}
}
