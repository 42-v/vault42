package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// clientAuditCapture collects the audit rows a handler writes, so a test can
// assert on the trail rather than on the response. The response is deliberately
// identical for every rejection, which is the whole reason the trail has to
// carry the distinction.
type clientAuditCapture struct {
	mu   sync.Mutex
	rows []*model.AuditEntry
}

func (c *clientAuditCapture) add(entries ...*model.AuditEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = append(c.rows, entries...)
}

func (c *clientAuditCapture) last(t *testing.T) *model.AuditEntry {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.rows) == 0 {
		return nil
	}
	return c.rows[len(c.rows)-1]
}

// newAuditingClientHandler builds a ClientHandler whose audit logger writes
// straight through, with no flush interval, so a row is observable as soon as
// the handler returns.
func newAuditingClientHandler(t *testing.T, clients *mocks.MockClientRepo) (*ClientHandler, *clientAuditCapture) {
	t.Helper()

	rows := &clientAuditCapture{}
	repo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error { rows.add(e); return nil },
		InsertBatchFn: func(_ context.Context, es []*model.AuditEntry) error {
			rows.add(es...)
			return nil
		},
	}
	tokenSvc, _ := newTestTokenService(t)
	return NewClientHandler(clients, tokenSvc, audit.NewLogger(repo, 0)), rows
}

// postClientToken drives POST /client/token with form credentials.
func postClientToken(h *ClientHandler, clientID, secret string) *httptest.ResponseRecorder {
	body := ""
	if clientID != "" || secret != "" {
		body = "client_id=" + clientID + "&client_secret=" + secret
	}
	req := httptest.NewRequest(http.MethodPost, "/client/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, req)
	return w
}

// TestEveryClientAuthRejectionIsAudited is the regression for a brute force that
// left no trace anywhere.
//
// audit.ClientAuth was emitted only after a successful grant. The four rejection
// paths wrote a 401 and nothing else. The only other control on
// POST /client/token is a 10-per-minute limiter keyed on IP, so a distributed
// guess against a service client's secret, the credential that gates
// kms:unwrap, mint:token and the service-document store, produced no audit rows
// at all: nothing to alert on while it ran, and nothing to reconstruct after.
//
// The reason is asserted rather than just the presence of a row. The 401 is
// identical for all four cases on purpose, so the caller cannot tell an unknown
// client from a wrong secret. That makes the audit record the only place the
// distinction can exist, and it is what an investigator needs first.
func TestEveryClientAuthRejectionIsAudited(t *testing.T) {
	const knownID = "svc-known"
	const knownSecret = "correct-horse-battery-staple"

	for _, tc := range []struct {
		name       string
		active     bool
		clientID   string
		secret     string
		wantReason string
	}{
		{"no credentials at all", true, "", "", "unparseable_credentials"},
		{"unknown client", true, "svc-absent", "whatever", "unknown_client"},
		{"inactive client", false, knownID, knownSecret, "inactive_client"},
		{"wrong secret", true, knownID, "not-the-secret", "wrong_secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := makeClientWithSecret(t, knownID, "known", knownSecret, "app", []string{"read"}, tc.active)
			clients := &mocks.MockClientRepo{
				GetByIDFn: func(_ context.Context, id string) (*model.Client, error) {
					if id == knownID {
						return client, nil
					}
					return nil, nil
				},
			}

			h, rows := newAuditingClientHandler(t, clients)
			w := postClientToken(h, tc.clientID, tc.secret)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body %s)", w.Code, w.Body.String())
			}

			row := rows.last(t)
			if row == nil {
				t.Fatalf("a rejected client-credentials grant wrote no audit row. Every rejection "+
					"answers the same 401, so with no row nothing anywhere records that the "+
					"attempt happened: %s", tc.name)
			}
			if row.EventType != audit.ClientAuth {
				t.Errorf("event type = %q, want %q", row.EventType, audit.ClientAuth)
			}
			reason, _ := row.Metadata["reason"].(string)
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q. The response cannot carry this distinction, so "+
					"the audit row is the only place it exists.", reason, tc.wantReason)
			}
			if result, _ := row.Metadata["result"].(string); result != "failure" {
				t.Errorf("result = %q, want failure; a success and a rejection share an event "+
					"type and must be separable without parsing the reason", result)
			}
		})
	}
}

// TestClientAuthAuditBoundsTheAttemptedID stops the audit table becoming the
// cheapest thing on the endpoint to attack.
//
// The client id on the unknown-client path is whatever the caller sent. Writing
// it unbounded turns one request into one arbitrarily large row, which fills the
// audit store faster than anything else here can.
func TestClientAuthAuditBoundsTheAttemptedID(t *testing.T) {
	clients := &mocks.MockClientRepo{
		GetByIDFn: func(context.Context, string) (*model.Client, error) { return nil, nil },
	}
	h, rows := newAuditingClientHandler(t, clients)

	// 512 bytes, not 64 KB. Token bodies pass through
	// http.MaxBytesReader(w, r.Body, 8192), so an oversized body never reaches
	// parseClientCredentials at all: it fails to parse and the handler takes the
	// unparseable-credentials path with an empty id, leaving the truncation this
	// test exists for unexecuted. The id has to be over the audit limit and under
	// the body limit for the case to be the one it claims.
	postClientToken(h, strings.Repeat("A", 512), "x")

	row := rows.last(t)
	if row == nil {
		t.Fatal("no audit row was written for an oversized client id")
	}
	if got := len(row.ClientID); got > clientAuthFailureIDLimit {
		t.Errorf("audited client id is %d bytes, want at most %d; unbounded, one request writes "+
			"one arbitrarily large audit row", got, clientAuthFailureIDLimit)
	}
}
