package postgres

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The repositories are the only place a row from the database becomes a Go value.
// Everything above them assumes that conversion either produced the whole row or an
// error, and the tests in this file are about the second half of that promise: what
// happens when the database answers with something the query did not contract for.
//
// A partially-scanned row is the dangerous outcome. A client whose secret_hash
// silently became the empty string, a catalog role whose name became "", or a
// listing that stops halfway and is returned as if it were complete are all worse
// than a hard failure, and none of them can be provoked against a healthy schema.
// So these tests talk to a scripted Postgres wire-protocol server instead: it is the
// only way to hand the repositories a NULL where the column is NOT NULL, or to cut a
// result set off mid-stream, without a database that has already been corrupted.

// Postgres type OIDs used in the scripted row descriptions.
const (
	blobClientOIDBool          = 16
	blobClientOIDBytea         = 17
	blobClientOIDInt4          = 23
	blobClientOIDText          = 25
	blobClientOIDTextArray     = 1009
	blobClientOIDVarchar       = 1043
	blobClientOIDTimestamptz   = 1184
	blobClientPostgresEpochOff = 946684800 // seconds between 1970-01-01 and 2000-01-01
)

// blobClientRowScript is the answer the fake backend gives to one query. A query is
// matched by substring, so each script names the fragment that identifies it.
type blobClientRowScript struct {
	match string
	// paramOIDs types the query's placeholders. Empty means every placeholder is
	// text, which is what a query whose arguments are all strings needs; a query
	// that binds a number has to say so or pgx has no encode plan for it.
	paramOIDs []uint32
	fields    []pgproto3.FieldDescription
	rows      [][][]byte
	failWith  *pgproto3.ErrorResponse
}

func blobClientField(name string, oid uint32) pgproto3.FieldDescription {
	return pgproto3.FieldDescription{Name: []byte(name), DataTypeOID: oid, DataTypeSize: -1, TypeModifier: -1}
}

func blobClientText(v string) []byte { return []byte(v) }

func blobClientInt4(v int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b
}

func blobClientBool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

func blobClientTimestamptz(ts time.Time) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64((ts.Unix()-blobClientPostgresEpochOff)*1_000_000))
	return b
}

// blobClientTextArray encodes a one-dimensional text[] in the binary wire format
// pgx asks for when it sees OID 1009.
func blobClientTextArray(values ...string) []byte {
	out := make([]byte, 0, 32)
	out = binary.BigEndian.AppendUint32(out, 1)                   // dimensions
	out = binary.BigEndian.AppendUint32(out, 0)                   // no nulls
	out = binary.BigEndian.AppendUint32(out, blobClientOIDText)   // element type
	out = binary.BigEndian.AppendUint32(out, uint32(len(values))) // dimension length
	out = binary.BigEndian.AppendUint32(out, 1)                   // lower bound
	for _, v := range values {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	return out
}

// blobClientFakeDB serves the scripted answers over a loopback connection and hands
// back a DB pointed at it. The pool and listener are closed with the test.
func blobClientFakeDB(t *testing.T, scripts ...blobClientRowScript) *DB {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	find := func(query string) *blobClientRowScript {
		for i := range scripts {
			if strings.Contains(query, scripts[i].match) {
				return &scripts[i]
			}
		}
		return nil
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go blobClientServeConn(conn, find)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, "postgres://scripted:scripted@"+ln.Addr().String()+"/scripted?sslmode=disable")
	if err != nil {
		_ = ln.Close()
		t.Fatalf("connect to the scripted backend: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_ = ln.Close()
	})
	return &DB{Pool: pool}
}

func blobClientServeConn(conn net.Conn, find func(string) *blobClientRowScript) {
	defer conn.Close()

	be := pgproto3.NewBackend(conn, conn)
	if _, err := be.ReceiveStartupMessage(); err != nil {
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.ParameterStatus{Name: "DateStyle", Value: "ISO, MDY"})
	be.Send(&pgproto3.ParameterStatus{Name: "TimeZone", Value: "UTC"})
	be.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	be.Send(&pgproto3.ParameterStatus{Name: "integer_datetimes", Value: "on"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return
	}

	statements := map[string]string{}
	portal := ""

	unscripted := func(query string) {
		be.Send(&pgproto3.ErrorResponse{
			Severity: "ERROR", Code: "42601",
			Message: "the scripted backend was asked an unscripted query: " + query,
		})
	}

	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Parse:
			statements[m.Name] = m.Query
			be.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Describe:
			query := statements[m.Name]
			script := find(query)
			oids := make([]uint32, strings.Count(query, "$"))
			for i := range oids {
				oids[i] = blobClientOIDText
			}
			if script != nil && len(script.paramOIDs) == len(oids) {
				oids = script.paramOIDs
			}
			be.Send(&pgproto3.ParameterDescription{ParameterOIDs: oids})
			switch {
			case script == nil:
				unscripted(query)
			case len(script.fields) == 0:
				be.Send(&pgproto3.NoData{})
			default:
				be.Send(&pgproto3.RowDescription{Fields: script.fields})
			}
		case *pgproto3.Bind:
			portal = statements[m.PreparedStatement]
			be.Send(&pgproto3.BindComplete{})
		case *pgproto3.Execute:
			script := find(portal)
			if script == nil {
				unscripted(portal)
				break
			}
			for _, row := range script.rows {
				be.Send(&pgproto3.DataRow{Values: row})
			}
			if script.failWith != nil {
				be.Send(script.failWith)
				break
			}
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		case *pgproto3.Query:
			// pgx sends begin, commit and rollback on the simple protocol
			// because they carry no arguments, so a transaction test scripts
			// them by name the same way it scripts a statement.
			if script := find(m.String); script != nil && script.failWith != nil {
				be.Send(script.failWith)
			} else {
				be.Send(&pgproto3.CommandComplete{CommandTag: []byte(strings.ToUpper(strings.TrimSpace(m.String)))})
			}
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Sync:
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

func blobClientCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func blobClientBlobFields(withData bool) []pgproto3.FieldDescription {
	fields := []pgproto3.FieldDescription{
		blobClientField("id", blobClientOIDVarchar),
		blobClientField("pseudonym_id", blobClientOIDVarchar),
		blobClientField("ref_hash", blobClientOIDVarchar),
		blobClientField("label_enc", blobClientOIDBytea),
	}
	if withData {
		fields = append(fields, blobClientField("data_enc", blobClientOIDBytea))
	}
	return append(fields,
		blobClientField("size_bytes", blobClientOIDInt4),
		blobClientField("stored_bytes", blobClientOIDInt4),
		blobClientField("checksum", blobClientOIDVarchar),
		blobClientField("created_at", blobClientOIDTimestamptz),
	)
}

// ref_hash is the only thing that makes a blob a named one: List reports a blob as
// named when it is set, replacing a named blob deletes by it, and DownloadNamed
// finds nothing without it. It is also the one nullable column in the table, read
// through a pointer, so dropping the value on the way out of the row would not fail
// anything loudly. It would just turn every named document into an anonymous one.
func TestBlobRepo_NamedRowKeepsItsReference(t *testing.T) {
	const refHash = "ref-hash-of-config-json"
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	row := func(withData bool) [][]byte {
		values := [][]byte{
			blobClientText("blob-1"),
			blobClientText("pseudo-1"),
			blobClientText(refHash),
			[]byte("label-ciphertext"),
		}
		if withData {
			values = append(values, []byte("data-ciphertext"))
		}
		return append(values,
			blobClientInt4(11),
			blobClientInt4(64),
			blobClientText("sha256:abc"),
			blobClientTimestamptz(created),
		)
	}

	db := blobClientFakeDB(t,
		blobClientRowScript{
			match:  "WHERE id = $1 AND pseudonym_id = $2",
			fields: blobClientBlobFields(true),
			rows:   [][][]byte{row(true)},
		},
		blobClientRowScript{
			match:  "ORDER BY created_at DESC",
			fields: blobClientBlobFields(false),
			rows:   [][][]byte{row(false)},
		},
	)
	repo := NewBlobRepo(db)
	ctx := blobClientCtx(t)

	blob, err := repo.GetByIDAndPseudonym(ctx, "blob-1", "pseudo-1")
	if err != nil {
		t.Fatalf("GetByIDAndPseudonym: %v", err)
	}
	if blob == nil {
		t.Fatal("GetByIDAndPseudonym returned no blob for a row the database sent")
	}
	if blob.RefHash != refHash {
		t.Errorf("RefHash = %q, want %q; a named blob read by ID came back unnamed", blob.RefHash, refHash)
	}

	blobs, err := repo.ListByPseudonym(ctx, "pseudo-1")
	if err != nil {
		t.Fatalf("ListByPseudonym: %v", err)
	}
	if len(blobs) != 1 {
		t.Fatalf("ListByPseudonym returned %d blobs, want 1", len(blobs))
	}
	if blobs[0].RefHash != refHash {
		t.Errorf("listed RefHash = %q, want %q; the listing would report a named blob as anonymous", blobs[0].RefHash, refHash)
	}
}

// checksum is NOT NULL and is what a download is verified against. A NULL arriving
// there means the row is not what the query promised, and the listing has to stop:
// scanning on and returning the blobs it managed to read would show the user a
// document list that silently lost entries.
func TestBlobRepo_ListRefusesUnreadableRow(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "ORDER BY created_at DESC",
		fields: blobClientBlobFields(false),
		rows: [][][]byte{{
			blobClientText("blob-1"),
			blobClientText("pseudo-1"),
			nil,
			nil,
			blobClientInt4(11),
			blobClientInt4(64),
			nil, // checksum
			blobClientTimestamptz(time.Now()),
		}},
	})

	blobs, err := NewBlobRepo(db).ListByPseudonym(blobClientCtx(t), "pseudo-1")
	if err == nil {
		t.Fatalf("a row that could not be read was accepted: %+v", blobs)
	}
	if !strings.Contains(err.Error(), "scan blob") {
		t.Errorf("err = %v, want a scan failure", err)
	}
	if blobs != nil {
		t.Errorf("a failed listing still returned %d blobs", len(blobs))
	}
}

func blobClientClientFields() []pgproto3.FieldDescription {
	return []pgproto3.FieldDescription{
		blobClientField("id", blobClientOIDVarchar),
		blobClientField("name", blobClientOIDVarchar),
		blobClientField("secret_hash", blobClientOIDVarchar),
		blobClientField("role", blobClientOIDVarchar),
		blobClientField("scopes", blobClientOIDTextArray),
		blobClientField("redirect_uris", blobClientOIDTextArray),
		blobClientField("active", blobClientOIDBool),
		blobClientField("created_at", blobClientOIDTimestamptz),
		blobClientField("updated_at", blobClientOIDTimestamptz),
	}
}

func blobClientClientRow(id, name, secretHash string, active bool) [][]byte {
	now := time.Now()
	var hash []byte
	if secretHash != "" {
		hash = blobClientText(secretHash)
	}
	return [][]byte{
		blobClientText(id),
		blobClientText(name),
		hash,
		blobClientText("frontend"),
		blobClientTextArray("user:read"),
		blobClientTextArray(),
		blobClientBool(active),
		blobClientTimestamptz(now),
		blobClientTimestamptz(now),
	}
}

// The client list is what an operator revokes service credentials from. A row that
// does not scan must take the whole listing down: a client silently rebuilt with an
// empty secret hash, or one dropped from the list entirely, is a service credential
// nobody knows is there.
func TestClientRepo_ListRefusesUnreadableRow(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "FROM auth.clients ORDER BY name",
		fields: blobClientClientFields(),
		rows:   [][][]byte{blobClientClientRow("client-1", "frontend", "", true)},
	})

	clients, err := NewClientRepo(db).List(blobClientCtx(t))
	if err == nil {
		t.Fatalf("a client row that could not be read was accepted: %+v", clients)
	}
	if !strings.Contains(err.Error(), "scan client") {
		t.Errorf("err = %v, want a scan failure", err)
	}
	if clients != nil {
		t.Errorf("a failed listing still returned %d clients", len(clients))
	}
}

// A result set that dies partway through arrives as rows first and an error second.
// If only the rows were looked at, List would return the prefix it managed to read
// and no error at all, and an operator auditing service credentials would be looking
// at a list that quietly omits the clients the database never got to.
func TestClientRepo_ListRefusesTruncatedResult(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "FROM auth.clients ORDER BY name",
		fields: blobClientClientFields(),
		rows: [][][]byte{
			blobClientClientRow("client-1", "frontend", "$argon2id$a", true),
			blobClientClientRow("client-2", "worker", "$argon2id$b", true),
		},
		failWith: &pgproto3.ErrorResponse{
			Severity: "ERROR", Code: "57014",
			Message: "canceling statement due to conflict with recovery",
		},
	})

	clients, err := NewClientRepo(db).List(blobClientCtx(t))
	if err == nil {
		t.Fatalf("a truncated result set was returned as a complete client list: %+v", clients)
	}
	if len(clients) != 0 {
		t.Errorf("a failed listing still returned %d clients", len(clients))
	}
}

func blobClientAppRoleFields() []pgproto3.FieldDescription {
	return []pgproto3.FieldDescription{
		blobClientField("name", blobClientOIDVarchar),
		blobClientField("namespace", blobClientOIDVarchar),
		blobClientField("description", blobClientOIDVarchar),
		blobClientField("reserved", blobClientOIDBool),
		blobClientField("created_at", blobClientOIDTimestamptz),
	}
}

// The role catalog is what user roles are validated against before they are written
// into a JWT. A row that does not scan must fail the listing rather than be skipped:
// a catalog missing a role rejects legitimate roles, and one that scanned half a row
// would put an empty role name into the set of valid roles.
func TestAppRoleRepo_ListRefusesUnreadableRow(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "FROM auth.app_roles ORDER BY name",
		fields: blobClientAppRoleFields(),
		rows: [][][]byte{{
			blobClientText("moderator"),
			blobClientText("legacy"),
			nil, // description
			blobClientBool(false),
			blobClientTimestamptz(time.Now()),
		}},
	})

	roles, err := NewAppRoleRepo(db).List(blobClientCtx(t))
	if err == nil {
		t.Fatalf("an app_role row that could not be read was accepted: %+v", roles)
	}
	if !strings.Contains(err.Error(), "scan app_role") {
		t.Errorf("err = %v, want a scan failure", err)
	}
	if roles != nil {
		t.Errorf("a failed listing still returned %d roles", len(roles))
	}
}

// ListNames feeds role validation directly. An unreadable name must abort the call,
// because the alternative is a list containing "" as a valid role name.
func TestAppRoleRepo_ListNamesRefusesUnreadableRow(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "SELECT name FROM auth.app_roles",
		fields: []pgproto3.FieldDescription{blobClientField("name", blobClientOIDVarchar)},
		rows:   [][][]byte{{nil}},
	})

	names, err := NewAppRoleRepo(db).ListNames(blobClientCtx(t))
	if err == nil {
		t.Fatalf("an unreadable role name was accepted: %q", names)
	}
	if !strings.Contains(err.Error(), "scan app_role name") {
		t.Errorf("err = %v, want a scan failure", err)
	}
	for _, n := range names {
		if n == "" {
			t.Error("an empty role name was returned as a valid catalog role")
		}
	}
}

// Delete reads the role first and only then removes it. The read succeeding says
// nothing about the write: the server runs as a least-privilege role that is granted
// SELECT on the catalog and nothing else, so a rejected DELETE is the expected
// production failure. Reporting it as a successful deletion would leave an operator
// believing a role they revoked is gone while it is still valid in every new token.
func TestAppRoleRepo_DeleteSurfacesRejectedWrite(t *testing.T) {
	db := blobClientFakeDB(t,
		blobClientRowScript{
			match:  "SELECT name, namespace, description, reserved, created_at",
			fields: blobClientAppRoleFields(),
			rows: [][][]byte{{
				blobClientText("moderator"),
				blobClientText("legacy"),
				blobClientText("Forum moderator"),
				blobClientBool(false),
				blobClientTimestamptz(time.Now()),
			}},
		},
		blobClientRowScript{
			match: "DELETE FROM auth.app_roles",
			failWith: &pgproto3.ErrorResponse{
				Severity: "ERROR", Code: "42501",
				Message: "permission denied for table app_roles",
			},
		},
	)

	err := NewAppRoleRepo(db).Delete(blobClientCtx(t), "moderator")
	if err == nil {
		t.Fatal("a rejected DELETE was reported as a successful role deletion")
	}
	if !strings.Contains(err.Error(), "delete app_role") {
		t.Errorf("err = %v, want the delete failure to be surfaced", err)
	}
}
