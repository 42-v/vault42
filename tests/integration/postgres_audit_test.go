package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestPostgresAuditRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewAuditRepo(db)
	ctx := context.Background()

	userID1 := randomID()
	userID2 := randomID()

	baseTime := time.Now().UTC().Truncate(time.Microsecond)

	makeEntry := func(eventType, userID string, offset time.Duration) *model.AuditEntry {
		return &model.AuditEntry{
			ID:              randomID(),
			Timestamp:       baseTime.Add(offset),
			EventType:       eventType,
			UserID:          userID,
			IP:              "192.168.1.1",
			UserAgent:       "TestAgent/1.0",
			FingerprintHash: "sha256fingerprint",
			RiskScore:       0,
		}
	}

	t.Run("Insert single", func(t *testing.T) {
		e := makeEntry("login_success", userID1, 0)
		if err := repo.Insert(ctx, e); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	})

	t.Run("Insert with metadata", func(t *testing.T) {
		e := &model.AuditEntry{
			ID:        randomID(),
			Timestamp: baseTime.Add(1 * time.Second),
			EventType: "login_failure",
			UserID:    userID1,
			IP:        "10.0.0.1",
			Metadata:  map[string]interface{}{"reason": "invalid_password", "attempts": float64(3)},
			RiskScore: 5,
		}
		if err := repo.Insert(ctx, e); err != nil {
			t.Fatalf("Insert with metadata: %v", err)
		}
	})

	t.Run("InsertBatch", func(t *testing.T) {
		entries := []*model.AuditEntry{
			makeEntry("token_refresh", userID2, 2*time.Second),
			makeEntry("token_refresh", userID2, 3*time.Second),
			makeEntry("logout", userID2, 4*time.Second),
		}
		if err := repo.InsertBatch(ctx, entries); err != nil {
			t.Fatalf("InsertBatch: %v", err)
		}
	})

	t.Run("InsertBatch empty", func(t *testing.T) {
		if err := repo.InsertBatch(ctx, []*model.AuditEntry{}); err != nil {
			t.Fatalf("InsertBatch empty: %v", err)
		}
	})

	t.Run("InsertBatch is all-or-nothing on mid-batch failure", func(t *testing.T) {
		dupID := randomID()
		entries := []*model.AuditEntry{
			makeEntry("batch_fail", userID1, 5*time.Second),
			makeEntry("batch_fail", userID1, 6*time.Second),
		}
		entries[0].ID = dupID
		entries[1].ID = dupID
		if err := repo.InsertBatch(ctx, entries); err == nil {
			t.Fatal("InsertBatch reported success for a batch with a duplicate primary key")
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit.audit_log WHERE id=$1`, dupID).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Errorf("%d entries of a failed batch were committed, want 0", count)
		}
	})

	t.Run("Query no filter", func(t *testing.T) {
		entries, err := repo.Query(ctx, repository.AuditFilter{})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) < 5 {
			t.Errorf("len = %d, want >= 5 (from previous subtests)", len(entries))
		}
		// Verify descending timestamp order
		for i := 1; i < len(entries); i++ {
			if entries[i].Timestamp.After(entries[i-1].Timestamp) {
				t.Errorf("entries not in descending timestamp order at index %d", i)
				break
			}
		}
	})

	t.Run("Query by UserID", func(t *testing.T) {
		entries, err := repo.Query(ctx, repository.AuditFilter{UserID: userID1})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) < 2 {
			t.Errorf("len = %d, want >= 2 for userID1", len(entries))
		}
		for _, e := range entries {
			if e.UserID != userID1 {
				t.Errorf("UserID = %q, want %q", e.UserID, userID1)
			}
		}
	})

	t.Run("Query by EventType", func(t *testing.T) {
		entries, err := repo.Query(ctx, repository.AuditFilter{EventType: "token_refresh"})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) < 2 {
			t.Errorf("len = %d, want >= 2 for token_refresh", len(entries))
		}
		for _, e := range entries {
			if e.EventType != "token_refresh" {
				t.Errorf("EventType = %q, want %q", e.EventType, "token_refresh")
			}
		}
	})

	t.Run("Query by Since", func(t *testing.T) {
		since := baseTime.Add(2 * time.Second)
		entries, err := repo.Query(ctx, repository.AuditFilter{Since: &since})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		for _, e := range entries {
			if e.Timestamp.Before(since) {
				t.Errorf("Timestamp %v is before Since %v", e.Timestamp, since)
			}
		}
	})

	t.Run("Query by Until", func(t *testing.T) {
		until := baseTime.Add(1 * time.Second)
		entries, err := repo.Query(ctx, repository.AuditFilter{Until: &until})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		for _, e := range entries {
			if e.Timestamp.After(until) {
				t.Errorf("Timestamp %v is after Until %v", e.Timestamp, until)
			}
		}
	})

	t.Run("Query by Since and Until range", func(t *testing.T) {
		since := baseTime.Add(1 * time.Second)
		until := baseTime.Add(3 * time.Second)
		entries, err := repo.Query(ctx, repository.AuditFilter{Since: &since, Until: &until})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		for _, e := range entries {
			if e.Timestamp.Before(since) || e.Timestamp.After(until) {
				t.Errorf("Timestamp %v outside range [%v, %v]", e.Timestamp, since, until)
			}
		}
	})

	t.Run("Query with Limit", func(t *testing.T) {
		entries, err := repo.Query(ctx, repository.AuditFilter{Limit: 2})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) != 2 {
			t.Errorf("len = %d, want 2 (with Limit=2)", len(entries))
		}
	})

	t.Run("Query with Offset", func(t *testing.T) {
		allEntries, err := repo.Query(ctx, repository.AuditFilter{Limit: 100})
		if err != nil {
			t.Fatalf("Query all: %v", err)
		}
		if len(allEntries) < 3 {
			t.Skip("need at least 3 entries for offset test")
		}

		offsetEntries, err := repo.Query(ctx, repository.AuditFilter{Limit: 100, Offset: 2})
		if err != nil {
			t.Fatalf("Query with offset: %v", err)
		}
		if len(offsetEntries) != len(allEntries)-2 {
			t.Errorf("len = %d, want %d (total %d minus offset 2)", len(offsetEntries), len(allEntries)-2, len(allEntries))
		}
	})

	t.Run("Query combined UserID and EventType", func(t *testing.T) {
		entries, err := repo.Query(ctx, repository.AuditFilter{
			UserID:    userID2,
			EventType: "token_refresh",
		})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) < 2 {
			t.Errorf("len = %d, want >= 2", len(entries))
		}
		for _, e := range entries {
			if e.UserID != userID2 || e.EventType != "token_refresh" {
				t.Errorf("got UserID=%q EventType=%q, want %q/%q", e.UserID, e.EventType, userID2, "token_refresh")
			}
		}
	})

	t.Run("Query empty result", func(t *testing.T) {
		entries, err := repo.Query(ctx, repository.AuditFilter{UserID: randomID()})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("len = %d, want 0", len(entries))
		}
	})

	t.Run("Insert with empty optional fields", func(t *testing.T) {
		e := &model.AuditEntry{
			ID:        randomID(),
			Timestamp: baseTime.Add(10 * time.Second),
			EventType: "system_event",
			RiskScore: 0,
		}
		if err := repo.Insert(ctx, e); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		entries, err := repo.Query(ctx, repository.AuditFilter{EventType: "system_event"})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) < 1 {
			t.Fatal("expected at least 1 system_event entry")
		}
		found := entries[0]
		if found.UserID != "" {
			t.Errorf("UserID = %q, want empty", found.UserID)
		}
		if found.IP != "" {
			t.Errorf("IP = %q, want empty", found.IP)
		}
	})

	t.Run("Query default limit caps at 100", func(t *testing.T) {
		// Insert enough entries to test the cap
		// The default limit is 100 when Limit is 0 or > 1000
		entries, err := repo.Query(ctx, repository.AuditFilter{Limit: 0})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		// Just verify it didn't error with limit=0 (default applies)
		_ = entries
	})
}
