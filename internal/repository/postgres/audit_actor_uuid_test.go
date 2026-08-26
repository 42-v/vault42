package postgres

import (
	"context"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// The audit actor columns are UUID in the schema and string in Go, and three
// call sites pass a value the caller chose: the submitted client_id on a failed
// client auth, and the asserted subject on /mint and on a service document.
//
// This is the mechanism behind that, measured against a real PostgreSQL rather
// than argued: an actor id that is not a UUID does not produce a row with an
// odd value in it. It produces no row. The caller then discards the error,
// because auditing is best-effort and must never block authentication, so the
// event disappears with nothing anywhere recording that it did.
//
// Which events? The ones a caller controls. A credential spray sends
// client_id=admin, not a UUID. That is precisely the case the comment above
// auditClientAuthFailure says the audit exists to catch.
//
// actorColumns is what keeps the row: it blanks the column and moves the
// claimed value into metadata. It lives in this package, not in audit.Logger,
// for the reason audit.go gives -- the constraint is the column's.
//
// The second half is the other direction, and it is the half only a real
// PostgreSQL can settle: an id the uuid type accepts must reach the column
// unblanked, in every rendering the type accepts, and stay findable by the
// canonical one. That is what makes a shape test the wrong instrument.
func TestAuditRepo_ANonUUIDActorIsRejectedByTheColumn(t *testing.T) {
	svcDocRequireContainerRuntime(t)
	db := svcDocPostgres(t)
	repo := NewAuditRepo(db)
	ctx := context.Background()

	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}

	// What the call sites used to hand over.
	poisoned := &model.AuditEntry{
		ID:        id,
		Timestamp: time.Now(),
		EventType: "client_auth",
		ClientID:  "admin",
		IP:        "203.0.113.9",
		Metadata:  map[string]interface{}{"result": "failure", "reason": "unknown_client"},
	}
	// Straight at the column, bypassing the repository, because the repository
	// is what stops this now. If this ever succeeds, the schema changed and
	// actorColumns is guarding a constraint that no longer exists.
	_, rawErr := db.Pool.Exec(ctx,
		`INSERT INTO audit.audit_log (id, timestamp, event_type, client_id) VALUES ($1, $2, $3, $4)`,
		poisoned.ID, poisoned.Timestamp, poisoned.EventType, "admin")
	if rawErr == nil {
		t.Fatal("a non-UUID client_id was accepted by the uuid column; the schema changed " +
			"and actorColumns is guarding a constraint that no longer exists")
	}
	t.Logf("the column refuses it: %v", rawErr)

	// And through the repository it lands, which is the fix.
	if err := repo.Insert(ctx, poisoned); err != nil {
		t.Fatalf("the repository did not rescue the row: %v", err)
	}
	var rescued string
	if err := db.Pool.QueryRow(ctx,
		`SELECT metadata->>'actor_client_id_raw' FROM audit.audit_log WHERE id = $1`,
		poisoned.ID).Scan(&rescued); err != nil {
		t.Fatalf("read back the rescued row: %v", err)
	}
	if rescued != "admin" {
		t.Fatalf("metadata actor_client_id_raw = %q, want the value the caller claimed", rescued)
	}

	// The other direction: a dashless uuid is what .NET's Guid.ToString("N")
	// produces, mintSubjectRe admits it, and PostgreSQL's uuid parser accepts it
	// and stores the same sixteen bytes as the dashed form. So the row must keep
	// its actor, and must still be found by the canonical spelling -- which is
	// what CountByUser and the Art. 15 export both search by.
	id2, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	if err := repo.Insert(ctx, &model.AuditEntry{
		ID:        id2,
		Timestamp: time.Now(),
		EventType: "mint",
		UserID:    "7e2f9a102222400080000000000000ab",
		IP:        "203.0.113.9",
		Metadata:  map[string]interface{}{"result": "success"},
	}); err != nil {
		t.Fatalf("a dashless uuid was refused: %v", err)
	}

	var stored string
	if err := db.Pool.QueryRow(ctx,
		`SELECT user_id::text FROM audit.audit_log WHERE id = $1`, id2).Scan(&stored); err != nil {
		t.Fatalf("read back the dashless row: %v", err)
	}
	if stored != "7e2f9a10-2222-4000-8000-0000000000ab" {
		t.Fatalf("user_id = %q, want the canonical rendering of the same uuid. A blank "+
			"here is the regression: the row is in the table but no longer attributed, "+
			"and an append-only table cannot be repaired.", stored)
	}

	n, err := repo.CountByUser(ctx, "7e2f9a10-2222-4000-8000-0000000000ab")
	if err != nil {
		t.Fatalf("CountByUser: %v", err)
	}
	if n == 0 {
		t.Fatal("CountByUser found nothing for the canonical spelling of an id that was " +
			"written dashless, so the subject's own export would miss the row")
	}
}

// actorColumns is pure, so it is tested without a container. The behavior that
// matters is that every rendering the uuid type accepts reaches the column, and
// that a value it does not accept still leaves a row behind.
func TestActorColumns(t *testing.T) {
	const (
		ok       = "7e2f9a10-2222-4000-8000-0000000000ab"
		upper    = "7E2F9A10-2222-4000-8000-0000000000AB"
		dashless = "7e2f9a102222400080000000000000ab"
		braced   = "{7e2f9a10-2222-4000-8000-0000000000ab}"
		spaced   = "7e2f9a10-2222-4000-8000-0000000000 ab"
		short    = "7e2f9a10-2222-4000-8000-0000000000a"
	)
	cases := []struct {
		name, user, client   string
		wantUser, wantClient string
		wantUserRaw          bool
		wantClientRaw        bool
	}{
		{"both valid, untouched", ok, ok, ok, ok, false, false},
		{"both empty", "", "", "", "", false, false},
		{"a spray's client id", "", "admin", "", "", false, true},
		{"a legacy mint subject", "legacy-user-77", "", "", "", true, false},
		{"both bad", "u", "c", "", "", true, true},

		// Every one of these is a uuid the column already holds, indexes, and
		// returns dashed. A shape test blanked them into metadata, which
		// detached existing rows from their subject -- and the dashless case is
		// what .NET writes by default, on the platform this release is for.
		{"uppercase is canonicalised", upper, "", ok, "", false, false},
		{"dashless, as Guid.ToString N writes it", dashless, "", ok, "", false, false},
		{"braced", braced, "", ok, "", false, false},
		{"either column is canonicalised", dashless, upper, ok, ok, false, false},

		// Acceptance stops at 32 hex digits: a space is not punctuation the
		// parser skips, and a digit short is not a uuid.
		{"a space is not punctuation", spaced, "", "", "", true, false},
		{"one digit short", short, "", "", "", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &model.AuditEntry{
				UserID: tc.user, ClientID: tc.client,
				Metadata: map[string]interface{}{"reason": "unknown_client"},
			}
			u, c, md := actorColumns(e)
			if u != tc.wantUser || c != tc.wantClient {
				t.Fatalf("got user=%q client=%q, want %q/%q", u, c, tc.wantUser, tc.wantClient)
			}
			if _, ok := md[rawUserIDKey]; ok != tc.wantUserRaw {
				t.Errorf("%s present = %v, want %v", rawUserIDKey, ok, tc.wantUserRaw)
			}
			if _, ok := md[rawClientIDKey]; ok != tc.wantClientRaw {
				t.Errorf("%s present = %v, want %v", rawClientIDKey, ok, tc.wantClientRaw)
			}
			// A rejected id is kept as the caller wrote it, not as anything
			// normalised it: the key records what was asserted.
			if tc.wantUserRaw && md[rawUserIDKey] != tc.user {
				t.Errorf("%s = %v, want the claimed value %q", rawUserIDKey, md[rawUserIDKey], tc.user)
			}
			if tc.wantClientRaw && md[rawClientIDKey] != tc.client {
				t.Errorf("%s = %v, want the claimed value %q", rawClientIDKey, md[rawClientIDKey], tc.client)
			}
			if md["reason"] != "unknown_client" {
				t.Errorf("the caller's metadata was lost: %v", md)
			}
			// The entry belongs to the caller; a batch retry must not accumulate keys.
			if _, ok := e.Metadata[rawUserIDKey]; ok {
				t.Error("the caller's map was mutated")
			}
			if _, ok := e.Metadata[rawClientIDKey]; ok {
				t.Error("the caller's map was mutated")
			}
		})
	}
}

// A nil metadata map on a poisoned entry must still produce a map, not a panic.
func TestActorColumns_NilMetadata(t *testing.T) {
	e := &model.AuditEntry{ClientID: "admin"}
	_, c, md := actorColumns(e)
	if c != "" {
		t.Fatalf("client = %q, want blank", c)
	}
	if md[rawClientIDKey] != "admin" {
		t.Fatalf("metadata = %v", md)
	}
}
