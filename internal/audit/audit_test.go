package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// mockAuditRepo is a test double for AuditRepository.
type mockAuditRepo struct {
	mu      sync.Mutex
	entries []*model.AuditEntry
}

func (m *mockAuditRepo) Insert(_ context.Context, entry *model.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditRepo) InsertBatch(_ context.Context, entries []*model.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entries...)
	return nil
}

func (m *mockAuditRepo) Query(_ context.Context, _ repository.AuditFilter) ([]*model.AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.entries, nil
}

func (m *mockAuditRepo) CountByUser(_ context.Context, _ string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries), nil
}

func (m *mockAuditRepo) Cleanup(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockAuditRepo) CleanupLocked(ctx context.Context, olderThan time.Time) (int64, bool, error) {
	n, err := m.Cleanup(ctx, olderThan)
	return n, true, err
}

func TestLogImmediate(t *testing.T) {
	repo := &mockAuditRepo{}
	logger := NewLogger(repo, 0) // no batching
	ctx := context.Background()

	err := logger.Log(ctx, LoginSuccess, "user-1", "", "1.2.3.4", "Mozilla", "fp123", "",
		map[string]interface{}{"action": "login"}, 0)
	if err != nil {
		t.Fatal(err)
	}

	if len(repo.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(repo.entries))
	}

	e := repo.entries[0]
	if e.EventType != LoginSuccess {
		t.Errorf("event_type = %q, want %q", e.EventType, LoginSuccess)
	}
	if e.UserID != "user-1" {
		t.Errorf("user_id = %q, want user-1", e.UserID)
	}
	if e.IP != "1.2.3.4" {
		t.Errorf("ip = %q, want 1.2.3.4", e.IP)
	}
}

func TestLogBatchFlush(t *testing.T) {
	repo := &mockAuditRepo{}
	logger := NewLogger(repo, 100*time.Millisecond)
	ctx := context.Background()

	logger.Log(ctx, LoginSuccess, "u1", "", "1.1.1.1", "", "", "", nil, 0)
	logger.Log(ctx, LoginFailure, "u2", "", "2.2.2.2", "", "", "", nil, 50)

	// Not flushed yet
	repo.mu.Lock()
	earlyCount := len(repo.entries)
	repo.mu.Unlock()
	if earlyCount != 0 {
		t.Error("entries should be buffered, not flushed yet")
	}

	// Wait for batch flush
	time.Sleep(200 * time.Millisecond)

	repo.mu.Lock()
	count := len(repo.entries)
	repo.mu.Unlock()

	if count != 2 {
		t.Errorf("after flush, expected 2 entries, got %d", count)
	}

	logger.Close(ctx)
}

func TestScrubSensitiveMetadata(t *testing.T) {
	repo := &mockAuditRepo{}
	logger := NewLogger(repo, 0)
	ctx := context.Background()

	logger.Log(ctx, LoginSuccess, "u1", "", "1.1.1.1", "", "", "",
		map[string]interface{}{
			"password":     "super-secret",
			"token":        "jwt-token-here",
			"access_token": "at-value",
			"action":       "login",            // this should survive
			"email":        "user@example.com", // this should survive
		}, 0)

	e := repo.entries[0]
	if _, ok := e.Metadata["password"]; ok {
		t.Error("password should be scrubbed from metadata")
	}
	if _, ok := e.Metadata["token"]; ok {
		t.Error("token should be scrubbed from metadata")
	}
	if _, ok := e.Metadata["access_token"]; ok {
		t.Error("access_token should be scrubbed from metadata")
	}
	if e.Metadata["action"] != "login" {
		t.Error("non-sensitive metadata should survive")
	}
	if e.Metadata["email"] != "user@example.com" {
		t.Error("non-sensitive metadata should survive")
	}
}

func TestScrubMetadataNil(t *testing.T) {
	result := scrubMetadata(nil)
	if result != nil {
		t.Error("nil metadata should return nil")
	}
}

// TestIsCriticalEvent_Table covers critical event detection.
func TestIsCriticalEvent_Table(t *testing.T) {
	tests := []struct {
		event string
		want  bool
	}{
		{"login_failure", true},
		{"password_change", true},
		{"password_reset", true},
		{"token_revoke", true},
		{"admin_action", true},
		{"2fa_setup", false},
		{"session_revoke", false},
		{"login_success", false},
		{"registration", false},
		{"unknown", false},
		{"", false},
		{"noncritical:event", false},
	}
	for _, tt := range tests {
		t.Run(tt.event, func(t *testing.T) {
			if got := isCriticalEvent(tt.event); got != tt.want {
				t.Errorf("isCriticalEvent(%q)=%v want %v", tt.event, got, tt.want)
			}
		})
	}
}
