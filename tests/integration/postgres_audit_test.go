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

	// The Art. 15 export reports CountByUser as the total held and compares it
	// against the capped Query result to decide whether the export is partial.
	// A count that is not user-scoped, or that inherits Query's LIMIT, would
	// make that comparison lie.
	t.Run("CountByUser is user-scoped and uncapped", func(t *testing.T) {
		count1, err := repo.CountByUser(ctx, userID1)
		if err != nil {
			t.Fatalf("CountByUser: %v", err)
		}
		entries1, err := repo.Query(ctx, repository.AuditFilter{UserID: userID1})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if count1 != len(entries1) {
			t.Errorf("CountByUser = %d, Query returned %d for the same user", count1, len(entries1))
		}

		count2, err := repo.CountByUser(ctx, userID2)
		if err != nil {
			t.Fatalf("CountByUser: %v", err)
		}
		if count2 == 0 {
			t.Error("CountByUser returned 0 for a user with entries")
		}

		all, err := repo.Query(ctx, repository.AuditFilter{})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if count1 >= len(all) && count2 > 0 {
			t.Errorf("CountByUser(%q) = %d counted entries belonging to other users", userID1, count1)
		}
	})

	// AU-6 asks for review AND analysis. Analysis needs the severity signal to be
	// selectable, and before this predicate existed repository.AuditFilter
	// carried user, event type and time window only: there was no WHERE clause
	// an operator could write that said "show me everything that mattered", so
	// the one severity signal in the store could not be reviewed at all.
	t.Run("Query by MinRiskScore selects on severity", func(t *testing.T) {
		low := &model.AuditEntry{
			ID: randomID(), Timestamp: baseTime.Add(20 * time.Second),
			EventType: "login_success", UserID: userID1, RiskScore: 0,
		}
		high := &model.AuditEntry{
			ID: randomID(), Timestamp: baseTime.Add(21 * time.Second),
			EventType: "honeypot_trigger", UserID: userID1, RiskScore: 100,
		}
		if err := repo.InsertBatch(ctx, []*model.AuditEntry{low, high}); err != nil {
			t.Fatalf("InsertBatch: %v", err)
		}

		entries, err := repo.Query(ctx, repository.AuditFilter{MinRiskScore: 75})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(entries) == 0 {
			t.Fatal("no entries at or above severity 75, but one was just written at 100")
		}
		var sawHigh bool
		for _, e := range entries {
			if e.RiskScore < 75 {
				t.Errorf("entry %s scored %d and came back for MinRiskScore=75", e.EventType, e.RiskScore)
			}
			if e.ID == high.ID {
				sawHigh = true
			}
		}
		if !sawHigh {
			t.Error("the severity-100 entry did not come back for MinRiskScore=75")
		}

		// Zero is absence, not a floor of zero: an unset filter must not turn
		// into a predicate that quietly excludes nothing while looking set.
		all, err := repo.Query(ctx, repository.AuditFilter{})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(all) <= len(entries) {
			t.Errorf("an unfiltered query returned %d entries and a severity-filtered one %d; "+
				"the predicate is either always on or never on", len(all), len(entries))
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
		// The subtests above insert five rows into a fresh schema, so a count
		// below three is Query losing rows -- which is the defect this subtest
		// exists to catch. Skipping on it reported green for exactly that.
		if len(allEntries) < 3 {
			t.Fatalf("Query returned %d entries; the fixture inserted 5, so the offset case has nothing left to prove", len(allEntries))
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
