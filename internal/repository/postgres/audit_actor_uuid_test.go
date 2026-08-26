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
// audit.Logger.normalizeActors is what keeps the row: it blanks the column and
// moves the claimed value into metadata. The second half of this test is that
// the shape it produces is one the database accepts.
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

	// What normalizeActors produces instead: the column blank, the claimed value
	// kept in metadata, everything else unchanged.
	id2, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	normalized := &model.AuditEntry{
		ID:        id2,
		Timestamp: time.Now(),
		EventType: "client_auth",
		ClientID:  "",
		IP:        "203.0.113.9",
		Metadata: map[string]interface{}{
			"result": "failure", "reason": "unknown_client",
			"actor_client_id_raw": "admin",
		},
	}
	if err := repo.Insert(ctx, normalized); err != nil {
		t.Fatalf("the normalized row was refused too, so the fix does not fix it: %v", err)
	}

	var raw string
	row := db.Pool.QueryRow(ctx,
		`SELECT metadata->>'actor_client_id_raw' FROM audit.audit_log WHERE id = $1`, id2)
	if err := row.Scan(&raw); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if raw != "admin" {
		t.Fatalf("metadata actor_client_id_raw = %q, want the value the caller claimed", raw)
	}
}

// actorColumns is pure, so it is tested without a container. The behavior that
// matters is that a legitimate row is untouched and a poisoned one survives.
func TestActorColumns(t *testing.T) {
	const ok = "7e2f9a10-2222-4000-8000-0000000000ab"
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
		{"uppercase uuid is still a uuid", "7E2F9A10-2222-4000-8000-0000000000AB", "", "7E2F9A10-2222-4000-8000-0000000000AB", "", false, false},
		{"no dashes", "7e2f9a1022224000800000000000 00ab", "", "", "", true, false},
		{"one char short", "7e2f9a10-2222-4000-8000-0000000000a", "", "", "", true, false},
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
