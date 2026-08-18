package honeypot

import (
	"context"
	"testing"
)

// The honeypot alerter fires on a trap-account login — the clearest signal there is that
// someone is working through a credential dump against this vault. It is best-effort by
// design and must never take the request path down with it: a malformed webhook URL is an
// operator typo in an env var, and the correct response is a log line, not a panic in the
// middle of an attack.
func TestAlerter_MalformedWebhookURLDoesNotPanic(t *testing.T) {
	a := NewAlerter("://not-a-url", []string{"trap@example.com"}, nil)

	// Must not panic and must not block.
	a.Alert(context.Background(), Event{
		EventType: "trap_login",
		IP:        "203.0.113.1",
	})
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
