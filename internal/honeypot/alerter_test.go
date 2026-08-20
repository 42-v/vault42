package honeypot

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
)

// The honeypot alerter fires on a trap-account login — the clearest signal there is that
// someone is working through a credential dump against this vault. It is best-effort by
// design and must never take the request path down with it: a malformed webhook URL is an
// operator typo in an env var, and the correct response is a log line, not a panic in the
// middle of an attack.
// What makes the typo survivable is that it never reaches http.NewRequest: the
// scheme gate drops it at construction, so Alert takes the audit-only path. The
// trigger still has to be recorded, because that row is the only evidence the
// trap fired and it must not depend on the operator having spelled the webhook
// correctly.
func TestAlerter_MalformedWebhookURLDoesNotPanic(t *testing.T) {
	var entries []*model.AuditEntry
	a := NewAlerter("://not-a-url", []string{"trap@example.com"}, apAuditSpy(&entries))

	if a.webhookURL != "" {
		t.Fatalf("webhookURL = %q, want it dropped at construction", a.webhookURL)
	}

	// Must not panic and must not block.
	a.Alert(context.Background(), Event{
		EventType: "trap_login",
		IP:        "203.0.113.1",
	})

	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want the trap trigger recorded exactly once", len(entries))
	}
	if entries[0].EventType != audit.HoneypotTrigger {
		t.Errorf("audit event type = %q, want %q", entries[0].EventType, audit.HoneypotTrigger)
	}
}

// With no webhook configured the alerter is inert, which is the default. It still has to
// answer the trap-user question, because that is what decides whether a login gets the
// fake response.
func TestAlerter_TrapUserMatching(t *testing.T) {
	a := NewAlerter("", []string{"trap@example.com", "admin@example.com"}, nil)

	if !a.IsTrapUser("trap@example.com") {
		t.Error("a configured trap user was not recognized, so the attacker gets a real error instead of the honeypot")
	}
	if a.IsTrapUser("real-user@example.com") {
		t.Error("a real user was treated as a trap account and served a fake session")
	}

	a.Alert(context.Background(), Event{EventType: "trap_login"}) // no webhook: must be inert
}
