package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// GET /user/sessions listed devices, so a family whose device_id came back empty
// — which findOrCreateDevice produces whenever its lookup and its insert both
// fail, on both the password and the OAuth path — was a live, refreshable session
// that appeared nowhere and that the per-session revoke could not address.
//
// These cases pin the listing against a real Postgres, because the defect and the
// fix both live in the SQL: the NULL device_id, the DISTINCT ON that collapses a
// rotated family to one row, and the WHERE clause that has to agree with
// CountActiveFamilies about what "active" means.

// famInsert writes one refresh-token generation directly, so a test can build the
// states the repository's own Create refuses to produce (a NULL device, a used or
// revoked generation, an expired one).
func famInsert(t *testing.T, db *DB, userID, familyID, deviceID string, created time.Time, expires time.Time, used, revoked bool) string {
	t.Helper()
	id, _ := vaultcrypto.RandomUUID()
	var dev any
	if deviceID != "" {
		dev = deviceID
	}
	if _, err := db.Pool.Exec(context.Background(), `
		INSERT INTO auth.refresh_tokens
			(id, user_id, token_hash, family_id, device_id, expires_at, used, revoked, created_at, family_created_at)
		VALUES ($1, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10)`,
		id, userID, vaultcrypto.SHA256Hex(id), familyID, dev, expires, used, revoked, created, created); err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}
	return id
}

func TestRefreshTokenRepo_ListActiveFamilies(t *testing.T) {
	db := svcDocPostgres(t)
	repo := NewRefreshTokenRepo(db)
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("a family with no device is listed", func(t *testing.T) {
		u, _ := vaultcrypto.RandomUUID()
		capInsertUser(t, db, u, u+"@nodevice.test")
		fam, _ := vaultcrypto.RandomUUID()
		famInsert(t, db, u, fam, "", now, now.Add(time.Hour), false, false)

		families, err := repo.ListActiveFamilies(ctx, u)
		if err != nil {
			t.Fatalf("ListActiveFamilies: %v", err)
		}
		if len(families) != 1 {
			t.Fatalf("listed %d families, want 1: a family with a NULL device_id is a live session", len(families))
		}
		if families[0].FamilyID != fam {
			t.Errorf("FamilyID = %q, want %q", families[0].FamilyID, fam)
		}
		if families[0].DeviceID != "" {
			t.Errorf("DeviceID = %q, want empty for a NULL column", families[0].DeviceID)
		}
	})

	t.Run("a rotated family collapses to its newest live generation", func(t *testing.T) {
		u, _ := vaultcrypto.RandomUUID()
		capInsertUser(t, db, u, u+"@rotated.test")
		fam, _ := vaultcrypto.RandomUUID()
		dev := insertFamilyDevice(t, db, u)
		// The first generation is spent, as rotation leaves it, and carries the
		// family's birth date.
		famInsert(t, db, u, fam, dev, now.Add(-48*time.Hour), now.Add(time.Hour), true, false)
		famInsert(t, db, u, fam, dev, now.Add(-time.Hour), now.Add(2*time.Hour), false, false)
		famInsert(t, db, u, fam, dev, now, now.Add(3*time.Hour), false, false)

		families, err := repo.ListActiveFamilies(ctx, u)
		if err != nil {
			t.Fatalf("ListActiveFamilies: %v", err)
		}
		if len(families) != 1 {
			t.Fatalf("listed %d rows for one family, want 1", len(families))
		}
		f := families[0]
		if f.DeviceID != dev {
			t.Errorf("DeviceID = %q, want %q", f.DeviceID, dev)
		}
		if f.LastUsedAt.Before(now.Add(-time.Minute)) {
			t.Errorf("LastUsedAt = %v, want the newest generation's created_at (%v)", f.LastUsedAt, now)
		}
		// family_created_at is written once by the first token of a family and a
		// rotation cannot move it (migration 013), so the session's age is the
		// family's, not the latest refresh's.
		if !f.CreatedAt.Before(now.Add(-24 * time.Hour)) {
			t.Errorf("CreatedAt = %v, want the family's birth date ~48h ago, not the latest rotation", f.CreatedAt)
		}
	})

	t.Run("revoked, used-out and expired families are not sessions", func(t *testing.T) {
		u, _ := vaultcrypto.RandomUUID()
		capInsertUser(t, db, u, u+"@dead.test")
		revoked, _ := vaultcrypto.RandomUUID()
		spent, _ := vaultcrypto.RandomUUID()
		expired, _ := vaultcrypto.RandomUUID()
		famInsert(t, db, u, revoked, "", now, now.Add(time.Hour), false, true)
		famInsert(t, db, u, spent, "", now, now.Add(time.Hour), true, false)
		famInsert(t, db, u, expired, "", now.Add(-2*time.Hour), now.Add(-time.Hour), false, false)

		families, err := repo.ListActiveFamilies(ctx, u)
		if err != nil {
			t.Fatalf("ListActiveFamilies: %v", err)
		}
		if len(families) != 0 {
			t.Fatalf("listed %d families, want 0", len(families))
		}
		// The listing and the concurrent-session cap must agree, or a session the
		// cap counts is one the user cannot see and end.
		if n, err := repo.CountActiveFamilies(ctx, u); err != nil || n != 0 {
			t.Fatalf("CountActiveFamilies = %d (err %v), want 0 to match the listing", n, err)
		}
	})

	t.Run("another account's families are not listed", func(t *testing.T) {
		mine, _ := vaultcrypto.RandomUUID()
		theirs, _ := vaultcrypto.RandomUUID()
		capInsertUser(t, db, mine, mine+"@mine.test")
		capInsertUser(t, db, theirs, theirs+"@theirs.test")
		fam, _ := vaultcrypto.RandomUUID()
		famInsert(t, db, theirs, fam, "", now, now.Add(time.Hour), false, false)

		families, err := repo.ListActiveFamilies(ctx, mine)
		if err != nil {
			t.Fatalf("ListActiveFamilies: %v", err)
		}
		if len(families) != 0 {
			t.Fatalf("listed %d families belonging to another account", len(families))
		}
	})

	t.Run("two families sharing one device list as two sessions", func(t *testing.T) {
		u, _ := vaultcrypto.RandomUUID()
		capInsertUser(t, db, u, u+"@shared.test")
		dev := insertFamilyDevice(t, db, u)
		a, _ := vaultcrypto.RandomUUID()
		b, _ := vaultcrypto.RandomUUID()
		famInsert(t, db, u, a, dev, now.Add(-time.Hour), now.Add(time.Hour), false, false)
		famInsert(t, db, u, b, dev, now, now.Add(time.Hour), false, false)

		families, err := repo.ListActiveFamilies(ctx, u)
		if err != nil {
			t.Fatalf("ListActiveFamilies: %v", err)
		}
		if len(families) != 2 {
			t.Fatalf("listed %d sessions for two families on one device, want 2; "+
				"collapsing them means revoking one kills both", len(families))
		}
		// Newest first, so the caller's list reads the way a session list should.
		if families[0].FamilyID != b {
			t.Errorf("first row = %q, want the newest family %q", families[0].FamilyID, b)
		}
	})
}

// insertFamilyDevice writes a device row so a refresh token can reference it.
func insertFamilyDevice(t *testing.T, db *DB, userID string) string {
	t.Helper()
	id, _ := vaultcrypto.RandomUUID()
	if _, err := db.Pool.Exec(context.Background(), `
		INSERT INTO auth.devices (id, user_id, fingerprint_hash, friendly_name, first_seen_at, created_at)
		VALUES ($1, $2, $3, 'Test Device', NOW(), NOW())`,
		id, userID, vaultcrypto.SHA256Hex(id)); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return id
}

// The listing is the only page a user has for finding a session they did not
// start. A query failure must be an error, never an empty list that reads as
// "you have no other sessions".
func TestRefreshTokenRepo_ListActiveFamiliesSurfacesQueryFailures(t *testing.T) {
	families, err := NewRefreshTokenRepo(deadPool(t)).ListActiveFamilies(context.Background(), "user-1")
	if err == nil {
		t.Fatalf("an unreachable database returned a session list: %+v", families)
	}
	if !strings.Contains(err.Error(), "list active families") {
		t.Errorf("err = %v, want the listing named", err)
	}
}

// family_id is NOT NULL and is the id the revoke addresses. A row that does not
// scan must take the listing down rather than be rebuilt with an empty id, which
// would show the user a session that DELETE /user/sessions/{id} cannot match.
func TestRefreshTokenRepo_ListActiveFamiliesRefusesUnreadableRow(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "DISTINCT ON (family_id)",
		fields: activeFamilyFields(),
		rows:   [][][]byte{{nil, blobClientText(""), blobClientText(""), blobClientTimestamptz(time.Now()), blobClientTimestamptz(time.Now()), blobClientTimestamptz(time.Now())}},
	})

	families, err := NewRefreshTokenRepo(db).ListActiveFamilies(blobClientCtx(t), "user-1")
	if err == nil {
		t.Fatalf("a row with a NULL family_id was returned as a session: %+v", families)
	}
	if !strings.Contains(err.Error(), "scan active family") {
		t.Errorf("err = %v, want the scan named", err)
	}
}

// A result set that dies partway through arrives as rows first and an error
// second. Returning the prefix would hide exactly the sessions the database never
// got to, with no error at all.
func TestRefreshTokenRepo_ListActiveFamiliesRefusesTruncatedResult(t *testing.T) {
	now := time.Now()
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "DISTINCT ON (family_id)",
		fields: activeFamilyFields(),
		rows: [][][]byte{{
			blobClientText("family-1"), blobClientText(""), blobClientText(""),
			blobClientTimestamptz(now), blobClientTimestamptz(now), blobClientTimestamptz(now),
		}},
		failWith: &pgproto3.ErrorResponse{
			Severity: "ERROR", Code: "57014",
			Message: "canceling statement due to conflict with recovery",
		},
	})

	families, err := NewRefreshTokenRepo(db).ListActiveFamilies(blobClientCtx(t), "user-1")
	if err == nil {
		t.Fatalf("a truncated result set was returned as a complete session list: %+v", families)
	}
	if len(families) != 0 {
		t.Errorf("a failed listing still returned %d sessions", len(families))
	}
}

func activeFamilyFields() []pgproto3.FieldDescription {
	return []pgproto3.FieldDescription{
		blobClientField("family_id", blobClientOIDText),
		blobClientField("device_id", blobClientOIDText),
		blobClientField("client_id", blobClientOIDText),
		blobClientField("family_created_at", blobClientOIDTimestamptz),
		blobClientField("created_at", blobClientOIDTimestamptz),
		blobClientField("expires_at", blobClientOIDTimestamptz),
	}
}
