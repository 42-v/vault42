package postgres

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// Compile-time interface satisfaction. A signature drift here is a build
// failure rather than a runtime nil.
var _ repository.ServiceDocumentRepository = (*ServiceDocumentRepo)(nil)

// Every method has to surface a database failure rather than degrade into a
// benign-looking zero value. The consequences differ per method and each one is
// load-bearing:
//
//   - Get returning (nil, nil) reads as "no such document", so a read failure
//     would look like an absent record and a caller could recreate one it
//     already had.
//   - Upsert returning (false, nil) reads as "replaced an existing document",
//     so a failed write would be reported to the caller as a successful update.
//   - Delete returning (true, nil) reads as "removed", so a caller would be told
//     data was deleted while it was still there.
//   - CountForOwner and SumBytesForSubject returning 0 fail the quota open: a
//     caller could write past both limits during a database outage.
//   - DeleteAllForSubject returning nil reads as a completed erasure step, and
//     the cascade would move on leaving the documents in place.
func TestServiceDocumentRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewServiceDocumentRepo(deadPool(t))
	ctx := context.Background()

	if _, err := repo.Get(ctx, "client-1", "subj", "key"); err == nil {
		t.Error("Get returned no error against an unreachable database")
	}
	if _, err := repo.ListSharedByKey(ctx, "subj", "key", "client-1"); err == nil {
		t.Error("ListSharedByKey returned no error against an unreachable database")
	}

	created, err := repo.Upsert(ctx, &repository.ServiceDocument{
		ID: "doc-1", ClientID: "client-1", SubjectHash: "subj", DocKey: "key",
		DataEnc: []byte("x"), SizeBytes: 1, StoredBytes: 1, Version: 1,
	})
	if err == nil {
		t.Error("Upsert reported success against an unreachable database")
	}
	if created {
		t.Error("Upsert returned created=true on failure")
	}

	deleted, err := repo.Delete(ctx, "client-1", "subj", "key")
	if err == nil {
		t.Error("Delete reported success against an unreachable database")
	}
	if deleted {
		t.Error("Delete returned deleted=true on failure; a caller would be told data was removed")
	}

	if _, err := repo.ListByOwner(ctx, "client-1", "subj"); err == nil {
		t.Error("ListByOwner returned no error against an unreachable database")
	}
	if _, err := repo.ListSharedForSubject(ctx, "subj", "client-1"); err == nil {
		t.Error("ListSharedForSubject returned no error against an unreachable database")
	}
	if _, err := repo.ListAllForSubject(ctx, "subj"); err == nil {
		t.Error("ListAllForSubject returned no error; a data export would report no documents held")
	}

	count, err := repo.CountForOwner(ctx, "client-1", "subj")
	if err == nil {
		t.Error("CountForOwner reported success against an unreachable database")
	}
	if count != 0 {
		t.Errorf("CountForOwner returned %d on failure", count)
	}

	sum, err := repo.SumBytesForSubject(ctx, "subj")
	if err == nil {
		t.Error("SumBytesForSubject reported success against an unreachable database")
	}
	if sum != 0 {
		t.Errorf("SumBytesForSubject returned %d on failure", sum)
	}

	if err := repo.DeleteAllForSubject(ctx, "subj"); err == nil {
		t.Error("DeleteAllForSubject reported success; the erasure cascade would move on")
	}
}

// ---------------------------------------------------------------------------
// Against a real PostgreSQL
// ---------------------------------------------------------------------------
//
// The service document repository is where ownership stops being a Go
// comparison and becomes a SQL predicate, so the properties below are
// properties of the statements themselves and cannot be demonstrated against a
// fake. Three in particular:
//
//   - `created` comes from `xmax = 0`, which is true only on the INSERT branch
//     of ON CONFLICT. No fake can tell you whether that expression still
//     distinguishes an insert from an update.
//   - The metadata projection omits data_enc. Whether a listing really leaves
//     the ciphertext in the database is a property of the column list.
//   - Every read that a request path can reach carries the caller's client id
//     in its WHERE clause. A row that leaked would leak here.

const (
	svcDocPGClientA = "aaaaaaaa-0000-4000-8000-000000000001"
	svcDocPGClientB = "bbbbbbbb-0000-4000-8000-000000000002"
	svcDocPGClientC = "cccccccc-0000-4000-8000-000000000003"
)

// svcDocRequireContainerRuntime points DOCKER_HOST at a reachable container
// socket, or skips. Failing hard would make a runtime-free machine
// indistinguishable from a broken repository; the canonical coverage run
// refuses to start without a runtime, so nothing is silently skipped there.
func svcDocRequireContainerRuntime(t *testing.T) {
	t.Helper()
	if os.Getenv("SKIP_INTEGRATION") == "1" {
		t.Skip("SKIP_INTEGRATION=1")
	}
	if os.Getenv("DOCKER_HOST") != "" {
		return
	}
	candidates := []string{"/run/podman/podman.sock", "/var/run/docker.sock"}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		candidates = append([]string{runtimeDir + "/podman/podman.sock"}, candidates...)
	}
	for _, sock := range candidates {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			t.Setenv("DOCKER_HOST", "unix://"+sock)
			return
		}
	}
	t.Skip("no container runtime found; set DOCKER_HOST or start the rootless podman socket")
}

// svcDocStripRoleGrants drops the top-level GRANT/REVOKE/ALTER DEFAULT
// statements from a migration. They name roles the throwaway container has no
// reason to own, and the privilege model is asserted where it belongs, against
// the real roles in tests/integration.
func svcDocStripRoleGrants(sql string) string {
	var kept []string
	for _, line := range strings.Split(sql, "\n") {
		skip := false
		for _, prefix := range []string{"GRANT ", "REVOKE ", "ALTER DEFAULT"} {
			if strings.HasPrefix(line, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// svcDocPostgres brings up PostgreSQL, applies every migration in order and
// registers the three clients the foreign key on client_id requires.
func svcDocPostgres(t *testing.T) *DB {
	t.Helper()
	svcDocRequireContainerRuntime(t)
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("vault_svcdoc"),
		tcpostgres.WithUsername("vault_svcdoc"),
		tcpostgres.WithPassword("vault_svcdoc"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(180*time.Second),
				wait.ForListeningPort("5432/tcp").
					WithStartupTimeout(180*time.Second),
			),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	migConn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		t.Fatalf("connect for migrations: %v", err)
	}
	defer migConn.Close(ctx)

	entries, err := os.ReadDir("../../../migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, f := range files {
		sql, readErr := os.ReadFile("../../../migrations/" + f)
		if readErr != nil {
			t.Fatalf("read migration %s: %v", f, readErr)
		}
		if _, execErr := migConn.Exec(ctx, svcDocStripRoleGrants(string(sql))); execErr != nil {
			t.Fatalf("run migration %s: %v", f, execErr)
		}
	}

	for id, name := range map[string]string{
		svcDocPGClientA: "service-a",
		svcDocPGClientB: "service-b",
		svcDocPGClientC: "service-c",
	} {
		if _, err := migConn.Exec(ctx, `
			INSERT INTO auth.clients (id, name, secret_hash, role)
			VALUES ($1, $2, 'x', 'service')`, id, name); err != nil {
			t.Fatalf("register client %s: %v", name, err)
		}
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return &DB{Pool: pool}
}

func svcDocFixture(id, clientID, subjectHash, docKey string, vis repository.ServiceDocumentVisibility, body string) *repository.ServiceDocument {
	return &repository.ServiceDocument{
		ID: id, ClientID: clientID, SubjectHash: subjectHash, DocKey: docKey,
		Visibility: vis, DataEnc: []byte(body),
		SizeBytes: len(body), StoredBytes: len(body) + 28, Version: 1,
	}
}

func svcDocMustUpsert(t *testing.T, repo *ServiceDocumentRepo, doc *repository.ServiceDocument) bool {
	t.Helper()
	created, err := repo.Upsert(context.Background(), doc)
	if err != nil {
		t.Fatalf("upsert %s/%s: %v", doc.ClientID, doc.DocKey, err)
	}
	return created
}

func svcDocKeysOf(docs []*repository.ServiceDocument) []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.ClientID+"/"+d.DocKey)
	}
	return out
}

func TestServiceDocumentRepo_AgainstPostgres(t *testing.T) {
	db := svcDocPostgres(t)
	repo := NewServiceDocumentRepo(db)
	ctx := context.Background()

	t.Run("a document survives the round trip through the encrypted columns", func(t *testing.T) {
		const subj = "subject-roundtrip"
		want := svcDocFixture("11111111-0000-4000-8000-00000000aaa1", svcDocPGClientA, subj, "prefs",
			repository.VisibilityPrivate, "ciphertext-bytes")
		if created := svcDocMustUpsert(t, repo, want); !created {
			t.Fatal("a first write reported itself as a replacement")
		}

		got, err := repo.Get(ctx, svcDocPGClientA, subj, "prefs")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil {
			t.Fatal("a document written a moment ago read back as absent")
		}
		if got.ID != want.ID || got.ClientID != want.ClientID || got.SubjectHash != subj || got.DocKey != "prefs" {
			t.Errorf("identity changed in transit: %+v", got)
		}
		if string(got.DataEnc) != string(want.DataEnc) {
			t.Errorf("ciphertext = %q, want %q", got.DataEnc, want.DataEnc)
		}
		if got.Visibility != repository.VisibilityPrivate {
			t.Errorf("visibility = %d, want private", got.Visibility)
		}
		if got.SizeBytes != want.SizeBytes || got.StoredBytes != want.StoredBytes || got.Version != want.Version {
			t.Errorf("sizes changed in transit: %+v", got)
		}
		if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
			t.Errorf("timestamps not stamped: created=%v updated=%v", got.CreatedAt, got.UpdatedAt)
		}
	})

	t.Run("an absent document reads as nil and not as an error", func(t *testing.T) {
		got, err := repo.Get(ctx, svcDocPGClientA, "subject-nothing-here", "prefs")
		if err != nil {
			t.Fatalf("an absent document was reported as a failure: %v", err)
		}
		if got != nil {
			t.Fatalf("a document appeared where none was written: %+v", got)
		}
	})

	// A caller reads a nil as "no such document" and writes a fresh one. If Get
	// answered across clients, the write it triggers would land on a row another
	// service owns.
	t.Run("get never crosses the owning client", func(t *testing.T) {
		const subj = "subject-owner-scope"
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000aaa2",
			svcDocPGClientA, subj, "prefs", repository.VisibilityShared, "a-body"))

		got, err := repo.Get(ctx, svcDocPGClientB, subj, "prefs")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got != nil {
			t.Fatalf("another client's document was returned by an owner-scoped read: %+v", got)
		}
	})

	// created is read off `xmax = 0`, and the caller turns it into 201 or 200.
	// The id is deliberately not overwritten on the update branch: the AAD binds
	// to (client_id, subject_hash, doc_key), so a replacement keeps its identity
	// without a re-key.
	t.Run("a replacement updates in place, reports itself as a replacement and keeps the original id", func(t *testing.T) {
		const subj = "subject-replace"
		first := svcDocFixture("11111111-0000-4000-8000-00000000aaa3", svcDocPGClientA, subj, "prefs",
			repository.VisibilityPrivate, "first-body")
		if created := svcDocMustUpsert(t, repo, first); !created {
			t.Fatal("a first write reported itself as a replacement")
		}
		stored, err := repo.Get(ctx, svcDocPGClientA, subj, "prefs")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		firstCreatedAt := stored.CreatedAt

		second := svcDocFixture("99999999-0000-4000-8000-00000000ffff", svcDocPGClientA, subj, "prefs",
			repository.VisibilityShared, "second-body-longer")
		second.Version = 2
		if created := svcDocMustUpsert(t, repo, second); created {
			t.Fatal("a replacement reported itself as an insert; the caller would answer 201 for an overwrite")
		}

		got, err := repo.Get(ctx, svcDocPGClientA, subj, "prefs")
		if err != nil {
			t.Fatalf("get after replace: %v", err)
		}
		if got.ID != first.ID {
			t.Errorf("id = %s after a replacement, want the original %s", got.ID, first.ID)
		}
		if string(got.DataEnc) != "second-body-longer" {
			t.Errorf("ciphertext = %q, want the replacement body", got.DataEnc)
		}
		if got.Visibility != repository.VisibilityShared || got.Version != 2 || got.SizeBytes != second.SizeBytes {
			t.Errorf("replacement fields not applied: %+v", got)
		}
		if !got.CreatedAt.Equal(firstCreatedAt) {
			t.Errorf("created_at moved on a replacement: %v, want %v", got.CreatedAt, firstCreatedAt)
		}

		n, err := repo.CountForOwner(ctx, svcDocPGClientA, subj)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Fatalf("a replacement left %d rows, want 1", n)
		}
	})

	t.Run("the shared lookup by key excludes the caller and every private row", func(t *testing.T) {
		const subj = "subject-shared-by-key"
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000bbb1",
			svcDocPGClientA, subj, "flags", repository.VisibilityShared, "a-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000bbb2",
			svcDocPGClientB, subj, "flags", repository.VisibilityShared, "b-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000bbb3",
			svcDocPGClientC, subj, "flags", repository.VisibilityPrivate, "c-body"))

		docs, err := repo.ListSharedByKey(ctx, subj, "flags", svcDocPGClientA)
		if err != nil {
			t.Fatalf("list shared by key: %v", err)
		}
		if len(docs) != 1 || docs[0].ClientID != svcDocPGClientB {
			t.Fatalf("shared lookup returned %v, want only service-b's shared row", svcDocKeysOf(docs))
		}
		if string(docs[0].DataEnc) != "b-body" {
			t.Errorf("the shared lookup dropped the ciphertext it is supposed to carry: %q", docs[0].DataEnc)
		}
	})

	// A subject-wide listing that pulled every ciphertext would move megabytes to
	// build a response that discards them, and would put bodies the caller may
	// not read into a process that only asked for metadata.
	t.Run("a metadata listing leaves the ciphertext in the database and keeps the sizes", func(t *testing.T) {
		const subj = "subject-meta"
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000ccc2",
			svcDocPGClientA, subj, "second", repository.VisibilityPrivate, "second-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000ccc1",
			svcDocPGClientA, subj, "first", repository.VisibilityPrivate, "first-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000ccc3",
			svcDocPGClientB, subj, "theirs", repository.VisibilityShared, "b-body"))

		docs, err := repo.ListByOwner(ctx, svcDocPGClientA, subj)
		if err != nil {
			t.Fatalf("list by owner: %v", err)
		}
		if len(docs) != 2 {
			t.Fatalf("owned listing returned %v, want the caller's two rows", svcDocKeysOf(docs))
		}
		if docs[0].DocKey != "first" || docs[1].DocKey != "second" {
			t.Errorf("owned listing is not ordered by doc_key: %v", svcDocKeysOf(docs))
		}
		for _, d := range docs {
			if d.DataEnc != nil {
				t.Errorf("%s carried a ciphertext into a metadata listing: %q", d.DocKey, d.DataEnc)
			}
			if d.SizeBytes == 0 || d.StoredBytes == 0 || d.Version == 0 || d.CreatedAt.IsZero() {
				t.Errorf("%s lost metadata the listing is for: %+v", d.DocKey, d)
			}
		}
	})

	t.Run("the shared listing for a subject excludes the caller and every private row", func(t *testing.T) {
		const subj = "subject-shared-list"
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000ddd1",
			svcDocPGClientA, subj, "mine", repository.VisibilityShared, "a-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000ddd2",
			svcDocPGClientB, subj, "theirs", repository.VisibilityShared, "b-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000ddd3",
			svcDocPGClientB, subj, "hidden", repository.VisibilityPrivate, "b-private"))

		docs, err := repo.ListSharedForSubject(ctx, subj, svcDocPGClientA)
		if err != nil {
			t.Fatalf("list shared for subject: %v", err)
		}
		if len(docs) != 1 || docs[0].DocKey != "theirs" {
			t.Fatalf("shared listing returned %v, want only service-b's shared row", svcDocKeysOf(docs))
		}
		if docs[0].DataEnc != nil {
			t.Errorf("the shared listing carried a ciphertext: %q", docs[0].DataEnc)
		}
	})

	// The Art. 15 export is the one read that deliberately spans owning clients
	// and returns bodies: a service's privacy from other services is not privacy
	// from the data subject.
	t.Run("the export listing spans every owning client and carries the ciphertext", func(t *testing.T) {
		const subj = "subject-export"
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000eee1",
			svcDocPGClientA, subj, "prefs", repository.VisibilityPrivate, "a-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000eee2",
			svcDocPGClientB, subj, "prefs", repository.VisibilityPrivate, "b-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-00000000eee3",
			svcDocPGClientA, "subject-export-other", "prefs", repository.VisibilityPrivate, "other-body"))

		docs, err := repo.ListAllForSubject(ctx, subj)
		if err != nil {
			t.Fatalf("list all for subject: %v", err)
		}
		if len(docs) != 2 {
			t.Fatalf("export listing returned %v, want both owning clients' rows for this subject only", svcDocKeysOf(docs))
		}
		for _, d := range docs {
			if len(d.DataEnc) == 0 {
				t.Errorf("%s reached the export with no body to decrypt", d.ClientID)
			}
		}
	})

	// The count bounds one client's documents for one subject; the byte sum bounds
	// a subject's footprint across every service that writes about them. Swapping
	// the two scopes would let one service exhaust another's allowance, or let a
	// subject's total grow without limit.
	t.Run("the document count is per owner while the byte sum spans every owner", func(t *testing.T) {
		const subj = "subject-quota"
		a1 := svcDocFixture("11111111-0000-4000-8000-00000000fff1", svcDocPGClientA, subj, "one", repository.VisibilityPrivate, "a-one")
		a2 := svcDocFixture("11111111-0000-4000-8000-00000000fff2", svcDocPGClientA, subj, "two", repository.VisibilityPrivate, "a-two")
		b1 := svcDocFixture("11111111-0000-4000-8000-00000000fff3", svcDocPGClientB, subj, "one", repository.VisibilityPrivate, "b-one")
		for _, d := range []*repository.ServiceDocument{a1, a2, b1} {
			svcDocMustUpsert(t, repo, d)
		}

		n, err := repo.CountForOwner(ctx, svcDocPGClientA, subj)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 2 {
			t.Errorf("count for service-a = %d, want 2 (its own rows only)", n)
		}

		sum, err := repo.SumBytesForSubject(ctx, subj)
		if err != nil {
			t.Fatalf("sum: %v", err)
		}
		want := a1.StoredBytes + a2.StoredBytes + b1.StoredBytes
		if sum != want {
			t.Errorf("byte sum = %d, want %d across every owning client", sum, want)
		}
	})

	t.Run("the byte sum of a subject nothing was written about is zero and not an error", func(t *testing.T) {
		sum, err := repo.SumBytesForSubject(ctx, "subject-never-written")
		if err != nil {
			t.Fatalf("sum over an empty subject: %v", err)
		}
		if sum != 0 {
			t.Errorf("byte sum = %d for a subject with no documents", sum)
		}
	})

	t.Run("delete reports whether a row went and never crosses clients", func(t *testing.T) {
		const subj = "subject-delete"
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-000000010001",
			svcDocPGClientA, subj, "prefs", repository.VisibilityShared, "a-body"))

		deleted, err := repo.Delete(ctx, svcDocPGClientB, subj, "prefs")
		if err != nil {
			t.Fatalf("delete as a non-owner: %v", err)
		}
		if deleted {
			t.Fatal("a non-owner deleted another client's shared document")
		}

		deleted, err = repo.Delete(ctx, svcDocPGClientA, subj, "prefs")
		if err != nil {
			t.Fatalf("delete as the owner: %v", err)
		}
		if !deleted {
			t.Fatal("the owner's delete reported that nothing went")
		}

		deleted, err = repo.Delete(ctx, svcDocPGClientA, subj, "prefs")
		if err != nil {
			t.Fatalf("second delete: %v", err)
		}
		if deleted {
			t.Fatal("a second delete reported a row it could not have removed")
		}
	})

	// Erasure must clear every document held about a user across every owning
	// service, must leave other subjects alone, and must be safe to re-run after
	// an interrupted cascade.
	t.Run("erasure spans every owning client, spares other subjects and is idempotent", func(t *testing.T) {
		const subj = "subject-erase"
		const other = "subject-erase-bystander"
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-000000020001",
			svcDocPGClientA, subj, "prefs", repository.VisibilityPrivate, "a-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-000000020002",
			svcDocPGClientB, subj, "prefs", repository.VisibilityShared, "b-body"))
		svcDocMustUpsert(t, repo, svcDocFixture("11111111-0000-4000-8000-000000020003",
			svcDocPGClientA, other, "prefs", repository.VisibilityPrivate, "bystander"))

		if err := repo.DeleteAllForSubject(ctx, subj); err != nil {
			t.Fatalf("erasure: %v", err)
		}
		if err := repo.DeleteAllForSubject(ctx, subj); err != nil {
			t.Fatalf("erasure re-run after an interrupted cascade: %v", err)
		}

		left, err := repo.ListAllForSubject(ctx, subj)
		if err != nil {
			t.Fatalf("list after erasure: %v", err)
		}
		if len(left) != 0 {
			t.Fatalf("%v survived the erasure of their subject", svcDocKeysOf(left))
		}

		bystanders, err := repo.ListAllForSubject(ctx, other)
		if err != nil {
			t.Fatalf("list bystander: %v", err)
		}
		if len(bystanders) != 1 {
			t.Fatalf("erasure of one subject removed %d rows from another", 1-len(bystanders))
		}
	})

	// -----------------------------------------------------------------------
	// The subject write lock
	// -----------------------------------------------------------------------
	//
	// A document quota is a rule about a set of rows, and the service enforces it
	// by counting the set and then adding to it. Those are two statements, and at
	// READ COMMITTED two statements are two snapshots: a second writer that reads
	// the same count writes a DIFFERENT key, so the unique index on
	// (client_id, subject_hash, doc_key) never fires and both rows land over the
	// cap. Folding the count into the INSERT as a subquery does not help, for the
	// same reason: the subquery reads its own statement's snapshot, and Postgres
	// only re-checks a conditional write when it conflicts on a unique index.
	//
	// WithSubjectWriteLock is what closes that. The three subtests below check the
	// three things that have to hold for it to be worth anything: the window is
	// real without it, the lock removes it, and the statements a closure issues
	// really do run inside the locked transaction rather than on a second pooled
	// connection, where the lock would be protecting nothing.

	// countThenWrite is the service's write path in miniature: count what this
	// owner already holds for the subject, refuse at the cap, otherwise insert.
	// pause widens the gap between the count and the insert, so an unprotected
	// interleaving is a certainty rather than a coin flip.
	countThenWrite := func(ctx context.Context, id, clientID, subj, key string, capDocs int, pause time.Duration) error {
		n, err := repo.CountForOwner(ctx, clientID, subj)
		if err != nil {
			return fmt.Errorf("count: %w", err)
		}
		if pause > 0 {
			time.Sleep(pause)
		}
		if n >= capDocs {
			return errSvcDocTestAtCap
		}
		if _, err := repo.Upsert(ctx, svcDocFixture(id, clientID, subj, key,
			repository.VisibilityPrivate, "quota-body")); err != nil {
			return fmt.Errorf("upsert: %w", err)
		}
		return nil
	}

	// The premise. If this ever stops breaching, the sibling test below proves
	// nothing, because the database would be serializing these writers on its own.
	t.Run("two writers that count before either writes both land, which is the finding", func(t *testing.T) {
		const subj = "subject-quota-window"
		counted := make([]chan struct{}, 2)
		for i := range counted {
			counted[i] = make(chan struct{})
		}

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// Rendezvous: neither writer inserts until both have counted. No
				// sleeps and no scheduler luck, so the breach is deterministic.
				n, err := repo.CountForOwner(ctx, svcDocPGClientA, subj)
				if err != nil {
					errs[i] = err
					close(counted[i])
					return
				}
				close(counted[i])
				<-counted[1-i]
				if n >= 1 {
					errs[i] = errSvcDocTestAtCap
					return
				}
				_, errs[i] = repo.Upsert(ctx, svcDocFixture(
					fmt.Sprintf("11111111-0000-4000-8000-0000000300%02d", i+1),
					svcDocPGClientA, subj, fmt.Sprintf("doc-%d", i),
					repository.VisibilityPrivate, "quota-body"))
			}(i)
		}
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("writer %d: %v", i, err)
			}
		}
		rows, err := repo.ListAllForSubject(ctx, subj)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("the unprotected check-then-write stored %d rows under a cap of 1; "+
				"the window it is meant to demonstrate is gone, so the lock test below "+
				"could pass without the lock doing anything", len(rows))
		}
	})

	t.Run("the subject lock serializes the count against the write it authorizes", func(t *testing.T) {
		const subj = "subject-quota-locked"

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// The pause sits between the count and the insert, inside the lock.
				// Without the lock the second writer would count during the first
				// writer's pause and both would insert; with it, the second writer
				// cannot begin until the first has committed.
				errs[i] = repo.WithSubjectWriteLock(ctx, subj, func(ctx context.Context) error {
					return countThenWrite(ctx,
						fmt.Sprintf("11111111-0000-4000-8000-0000000310%02d", i+1),
						svcDocPGClientA, subj, fmt.Sprintf("doc-%d", i), 1, 200*time.Millisecond)
				})
			}(i)
		}
		wg.Wait()

		var stored, refused int
		for i, err := range errs {
			switch {
			case err == nil:
				stored++
			case errors.Is(err, errSvcDocTestAtCap):
				refused++
			default:
				t.Fatalf("writer %d failed for a reason that is not the cap: %v", i, err)
			}
		}
		if stored != 1 || refused != 1 {
			t.Errorf("two locked writers under a cap of 1 produced %d stored and %d refused, want 1 and 1", stored, refused)
		}

		rows, err := repo.ListAllForSubject(ctx, subj)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rows) != 1 {
			t.Errorf("subject holds %v under a cap of 1", svcDocKeysOf(rows))
		}
	})

	// The lock is only worth anything if the statements it protects run inside its
	// transaction. A repository that took the lock and then issued its reads on a
	// second pooled connection would hold a lock around nothing, and would also
	// read state that its own uncommitted write is not part of, which is how a
	// replacement ends up counted as a new document.
	t.Run("a closure reads its own uncommitted write and leaves nothing behind when it fails", func(t *testing.T) {
		const subj = "subject-quota-tx"
		sentinel := errors.New("closure refused after writing")

		err := repo.WithSubjectWriteLock(ctx, subj, func(ctx context.Context) error {
			if _, upErr := repo.Upsert(ctx, svcDocFixture("11111111-0000-4000-8000-000000032001",
				svcDocPGClientA, subj, "doc-rolled-back", repository.VisibilityPrivate, "body")); upErr != nil {
				return upErr
			}
			// Inside the transaction the row exists, and the count a quota decision
			// would read includes it.
			got, getErr := repo.Get(ctx, svcDocPGClientA, subj, "doc-rolled-back")
			if getErr != nil {
				return getErr
			}
			if got == nil {
				return errors.New("a read inside the lock could not see the write the same closure just made, " +
					"so it ran outside the locked transaction")
			}
			n, cntErr := repo.CountForOwner(ctx, svcDocPGClientA, subj)
			if cntErr != nil {
				return cntErr
			}
			if n != 1 {
				return fmt.Errorf("count inside the lock is %d, want 1: the count ran outside the transaction", n)
			}
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("WithSubjectWriteLock returned %v, want the closure's own error unwrapped", err)
		}

		rows, listErr := repo.ListAllForSubject(ctx, subj)
		if listErr != nil {
			t.Fatalf("list: %v", listErr)
		}
		if len(rows) != 0 {
			t.Errorf("a closure that failed left %v committed", svcDocKeysOf(rows))
		}
	})
}

// errSvcDocTestAtCap stands in for service.ErrSvcDocQuotaExceeded. The
// repository has no opinion about quotas, so the tests that exercise the lock
// bring their own cap and their own refusal.
var errSvcDocTestAtCap = errors.New("at the document cap")

// The document service does not name this type; it type-asserts the repository
// for exactly this method and falls back to a weaker in-process lock when the
// assertion fails. A rename or a signature change here would therefore break no
// build anywhere, it would quietly stop protecting anything beyond one replica.
// Pin the shape so it breaks here instead.
var _ service.SubjectWriteSerializer = (*ServiceDocumentRepo)(nil)

// ---------------------------------------------------------------------------
// Rows the schema cannot produce
// ---------------------------------------------------------------------------
//
// Every column the repository scans is NOT NULL, so a healthy database can
// never fail one of these scans. That is exactly why the branch needs a test:
// it is the only thing standing between a half-scanned row and a caller that
// treats a truncated listing as a complete one. A quota computed from a listing
// that stopped early is a quota a caller can write past, and an export that
// stopped early is an Art. 15 answer missing records. The scripted backend from
// repos_row_contract_test.go is the only way to hand the repository a NULL where
// the column forbids one.

const svcDocOIDInt2 = 21

func svcDocInt2(v int16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(v))
	return b
}

func svcDocScriptedFields(withData bool) []pgproto3.FieldDescription {
	fields := []pgproto3.FieldDescription{
		blobClientField("id", blobClientOIDVarchar),
		blobClientField("client_id", blobClientOIDVarchar),
		blobClientField("subject_hash", blobClientOIDVarchar),
		blobClientField("doc_key", blobClientOIDVarchar),
		blobClientField("visibility", svcDocOIDInt2),
	}
	if withData {
		fields = append(fields, blobClientField("data_enc", blobClientOIDBytea))
	}
	return append(fields,
		blobClientField("size_bytes", blobClientOIDInt4),
		blobClientField("stored_bytes", blobClientOIDInt4),
		blobClientField("version", blobClientOIDInt4),
		blobClientField("created_at", blobClientOIDTimestamptz),
		blobClientField("updated_at", blobClientOIDTimestamptz),
	)
}

// svcDocScriptedRowMissingSize is a row whose NOT NULL size_bytes came back
// NULL, which is what a scan target of type int cannot absorb.
func svcDocScriptedRowMissingSize(withData bool) [][]byte {
	stamped := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	values := [][]byte{
		blobClientText("11111111-0000-4000-8000-000000030001"),
		blobClientText(svcDocPGClientA),
		blobClientText("subject-scripted"),
		blobClientText("prefs"),
		svcDocInt2(int16(repository.VisibilityShared)),
	}
	if withData {
		values = append(values, []byte("ciphertext"))
	}
	return append(values,
		nil,
		blobClientInt4(64),
		blobClientInt4(1),
		blobClientTimestamptz(stamped),
		blobClientTimestamptz(stamped),
	)
}

func TestServiceDocumentRepo_ARowItCannotScanFailsTheWholeListing(t *testing.T) {
	ctx := blobClientCtx(t)

	t.Run("shared lookup by key", func(t *testing.T) {
		db := blobClientFakeDB(t, blobClientRowScript{
			match:  "service_documents",
			fields: svcDocScriptedFields(true),
			rows:   [][][]byte{svcDocScriptedRowMissingSize(true)},
		})
		docs, err := NewServiceDocumentRepo(db).ListSharedByKey(ctx, "subject-scripted", "prefs", svcDocPGClientB)
		if err == nil {
			t.Fatal("a row that could not be scanned was reported as a successful lookup")
		}
		if docs != nil {
			t.Fatalf("a failed scan returned %d documents", len(docs))
		}
	})

	t.Run("metadata listing", func(t *testing.T) {
		db := blobClientFakeDB(t, blobClientRowScript{
			match:  "service_documents",
			fields: svcDocScriptedFields(false),
			rows:   [][][]byte{svcDocScriptedRowMissingSize(false)},
		})
		docs, err := NewServiceDocumentRepo(db).ListByOwner(ctx, svcDocPGClientA, "subject-scripted")
		if err == nil {
			t.Fatal("a row that could not be scanned was reported as a complete listing")
		}
		if docs != nil {
			t.Fatalf("a failed scan returned %d documents", len(docs))
		}
	})

	t.Run("export listing", func(t *testing.T) {
		db := blobClientFakeDB(t, blobClientRowScript{
			match:  "service_documents",
			fields: svcDocScriptedFields(true),
			rows:   [][][]byte{svcDocScriptedRowMissingSize(true)},
		})
		docs, err := NewServiceDocumentRepo(db).ListAllForSubject(ctx, "subject-scripted")
		if err == nil {
			t.Fatal("a row that could not be scanned was reported as a complete export")
		}
		if docs != nil {
			t.Fatalf("a failed scan returned %d documents", len(docs))
		}
	})
}
