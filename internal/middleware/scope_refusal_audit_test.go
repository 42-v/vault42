package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// capturingAuditRepo keeps the entries written through it, and records whether
// the context each write arrived on had already been cancelled.
type capturingAuditRepo struct {
	mu        sync.Mutex
	entries   []*model.AuditEntry
	cancelled []bool
}

func (c *capturingAuditRepo) Insert(ctx context.Context, e *model.AuditEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
	c.cancelled = append(c.cancelled, ctx.Err() != nil)
	return nil
}

func (c *capturingAuditRepo) InsertBatch(ctx context.Context, entries []*model.AuditEntry) error {
	for _, e := range entries {
		if err := c.Insert(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (c *capturingAuditRepo) Query(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
	return nil, nil
}
func (c *capturingAuditRepo) CountByUser(context.Context, string) (int, error) { return 0, nil }
func (c *capturingAuditRepo) Cleanup(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (c *capturingAuditRepo) CleanupLocked(context.Context, time.Time) (int64, bool, error) {
	return 0, true, nil
}

func (c *capturingAuditRepo) snapshot() ([]*model.AuditEntry, []bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries, c.cancelled
}

// withScopelessClaims puts an authenticated caller carrying no scopes on the
// request, which is what a stolen non-mint client token looks like at this
// point in the chain.
func withScopelessClaims(r *http.Request) *http.Request {
	claims := &vaultcrypto.VaultClaims{ClientID: "svc-stolen"}
	claims.Subject = "svc-stolen"
	return r.WithContext(context.WithValue(r.Context(), ClaimsKey, claims))
}

// TestRequireScopeAuditsARefusal is the regression for a probe that left no
// trace.
//
// Refusals that happen in the middleware chain never reach the handler, so the
// handler's own audit call cannot record them. For POST /mint that meant a
// stolen non-mint client token, a user token, or a token of the wrong type
// could be fired at the delegated-signing endpoint indefinitely and produce
// nothing at all in the audit log — while mint.go's own comment says "a client
// probing ... is the early signal that the credential has been taken" and
// docs/api.md promises that every path, accepted and refused, writes one
// token_minted event.
func TestRequireScopeAuditsARefusal(t *testing.T) {
	repo := &capturingAuditRepo{}
	logger := audit.NewLogger(repo, 0)

	h := RequireScope("mint:token", WithScopeRefusalAudit(logger, audit.TokenMinted, 45))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("the handler ran on a request that should have been refused")
		}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withScopelessClaims(httptest.NewRequest(http.MethodPost, "/mint", nil)))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	entries, _ := repo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("%d audit entries written, want 1. A refused mint left no trace, so probing the "+
			"delegated-signing endpoint is invisible.", len(entries))
	}
	e := entries[0]
	if e.EventType != audit.TokenMinted {
		t.Errorf("event type = %q, want %q", e.EventType, audit.TokenMinted)
	}
	if e.ClientID != "svc-stolen" {
		t.Errorf("client_id = %q, want the caller that was refused", e.ClientID)
	}
	if got := e.Metadata["reason"]; got != "insufficient_scope" {
		t.Errorf("metadata reason = %v, want insufficient_scope", got)
	}
	if got := e.Metadata["scope"]; got != "mint:token" {
		t.Errorf("metadata scope = %v, want the scope the resource required", got)
	}
	if got := e.Metadata["success"]; got != false {
		t.Errorf("metadata success = %v, want false", got)
	}
}

// TestRequireScopeRefusalSurvivesRequestCancellation pins the write against the
// obvious way to erase it.
//
// The client being refused chooses when to hang up, and can do it the instant
// the server starts handling the request. If the audit write rode the request
// context, a prober would delete their own record by closing the connection —
// the same reason the admin plane's refusal audits use context.WithoutCancel.
func TestRequireScopeRefusalSurvivesRequestCancellation(t *testing.T) {
	repo := &capturingAuditRepo{}
	logger := audit.NewLogger(repo, 0)

	h := RequireScope("mint:token", WithScopeRefusalAudit(logger, audit.TokenMinted, 45))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	ctx, cancel := context.WithCancel(context.Background())
	r := withScopelessClaims(httptest.NewRequest(http.MethodPost, "/mint", nil).WithContext(ctx))
	cancel()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	entries, cancelled := repo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("%d audit entries written, want 1: a prober erased their own record by dropping "+
			"the connection", len(entries))
	}
	if cancelled[0] {
		t.Error("the audit write ran on the cancelled request context, so a store that honours " +
			"cancellation would have discarded it")
	}
}

// TestRequireScopeWithoutAnAuditorStillRefuses keeps the audit optional and the
// decision unconditional.
func TestRequireScopeWithoutAnAuditorStillRefuses(t *testing.T) {
	h := RequireScope("mint:token")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("the handler ran on a request that should have been refused")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withScopelessClaims(httptest.NewRequest(http.MethodPost, "/mint", nil)))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}
