package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// An undelivered verification link is the difference between an account its
// owner can reach and one they cannot, and the send is deliberately non-fatal,
// so nothing else records that it happened: the row just sits there unverified,
// indistinguishable from one whose owner never clicked. Without this record an
// operator asked why a user cannot log in has only a log line to go on.
func TestAnUndeliveredVerificationMailIsAudited(t *testing.T) {
	var entries []*model.AuditEntry
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			entries = append(entries, e)
			return nil
		},
	}, 0)

	svc := &AuthService{
		cache:       &mocks.MockCache{},
		emailSender: &mocks.MockEmailSender{SendFn: func(context.Context, string, string, string, string) error { return errors.New("smtp unavailable") }},
		auditLog:    auditLog,
		appName:     "TestVault",
		origin:      "https://vault.test",
	}

	svc.sendVerificationEmail(context.Background(), "user@example.com", "user-123", "", "")

	if len(entries) != 1 {
		t.Fatalf("audit records written = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.UserID != "user-123" {
		t.Fatalf("audit record names user %q, want user-123", e.UserID)
	}
	if e.Metadata["action"] != "verification_email_not_sent" {
		t.Fatalf("audit action = %v, want verification_email_not_sent", e.Metadata["action"])
	}
	if e.Metadata["reason"] != "delivery_failed" {
		t.Fatalf("audit reason = %v, want delivery_failed", e.Metadata["reason"])
	}
	// The record is read by operators, so it carries an address they can act on
	// without becoming a second copy of the mailbox in the audit table.
	if e.Metadata["email"] != "u***@example.com" {
		t.Fatalf("audit email = %v, want the masked address", e.Metadata["email"])
	}
}

// The send runs on its own goroutine, where a nil dereference is not an error
// return, it is the whole process. A deployment with no audit sink wired must
// not lose the server the first time its mailer refuses a connection.
func TestAnUndeliveredVerificationMailWithoutAnAuditSinkDoesNotCrash(t *testing.T) {
	svc := &AuthService{
		cache:       &mocks.MockCache{},
		emailSender: &mocks.MockEmailSender{SendFn: func(context.Context, string, string, string, string) error { return errors.New("smtp unavailable") }},
		appName:     "TestVault",
		origin:      "https://vault.test",
	}

	svc.sendVerificationEmail(context.Background(), "user@example.com", "user-123", "", "")
}

// SendSignupVerification is the single entry point both signup paths use, and a
// service wired without a mailer has to be a no-op there rather than a nil
// dereference: the deployment that disables email still registers users.
func TestSignupVerificationIsSkippedWhenNoMailerIsConfigured(t *testing.T) {
	// Half a mailer is still no mailer: with only a cache there is nothing to
	// send with, and with only a sender the token has nowhere to live, so a
	// mailed link would be dead on arrival. Neither half may be used alone.
	t.Run("no email sender", func(t *testing.T) {
		var cached bool
		svc := &AuthService{cache: &mocks.MockCache{
			SetFn: func(context.Context, string, string, time.Duration) error {
				cached = true
				return nil
			},
		}}
		svc.SendSignupVerification(context.Background(), "user@example.com", "user-123", "")

		time.Sleep(100 * time.Millisecond) // the send is fire-and-forget
		if cached {
			t.Error("a verification token was stored for a link that can never be sent")
		}
	})

	t.Run("no cache", func(t *testing.T) {
		sent := make(chan struct{}, 1)
		svc := &AuthService{emailSender: &mocks.MockEmailSender{
			SendFn: func(context.Context, string, string, string, string) error {
				sent <- struct{}{}
				return nil
			},
		}}
		svc.SendSignupVerification(context.Background(), "user@example.com", "user-123", "")

		select {
		case <-sent:
			t.Error("a verification email was sent with no cache to store the token in")
		case <-time.After(100 * time.Millisecond):
		}
	})
}
