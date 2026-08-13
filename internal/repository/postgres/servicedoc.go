package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/42-v/vault42/internal/repository"
)

// serviceDocumentColumns is the full projection including the ciphertext.
const serviceDocumentColumns = `id, client_id, subject_hash, doc_key, visibility,
	data_enc, size_bytes, stored_bytes, version, created_at, updated_at`

// serviceDocumentMetaColumns omits data_enc. Listing endpoints return metadata
// only, and a subject-wide listing that pulled every ciphertext would move
// megabytes to build a response that discards them.
const serviceDocumentMetaColumns = `id, client_id, subject_hash, doc_key, visibility,
	size_bytes, stored_bytes, version, created_at, updated_at`

// svcDocAdvisoryLockClass namespaces this store's advisory locks. Advisory
// locks share one cluster-wide space with every other user of the mechanism, so
// the two-key form is used with a fixed first key ("SVCD" in ASCII) and the
// subject in the second. Without the namespace, some unrelated code hashing an
// unrelated string to the same number would silently serialize against document
// writes, or worse, be serialized by them.
const svcDocAdvisoryLockClass = 0x53564344

// svcDocTxKey carries the transaction a subject lock was taken in. It is an
// unexported empty struct type, so no other package can put a value under this
// key and nothing can collide with it.
type svcDocTxKey struct{}

// svcDocQuerier is the subset of pgx both *pgxpool.Pool and pgx.Tx satisfy.
// Every statement in this file goes through it, so a query issued inside a
// subject lock runs in that lock's transaction and a query issued outside runs
// on the pool, without either call site knowing which.
type svcDocQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ServiceDocumentRepo implements repository.ServiceDocumentRepository.
type ServiceDocumentRepo struct {
	db *DB
}

// NewServiceDocumentRepo creates a new PostgreSQL-backed service document repository.
func NewServiceDocumentRepo(db *DB) *ServiceDocumentRepo {
	return &ServiceDocumentRepo{db: db}
}

// q returns the transaction this call belongs to, or the pool when it belongs to
// none. Reaching for r.db.Pool directly inside a subject lock would run the
// statement on a second connection, outside the locked transaction, which is the
// bug this file exists to close; going through q makes that impossible to do by
// accident.
func (r *ServiceDocumentRepo) q(ctx context.Context) svcDocQuerier {
	if tx, ok := ctx.Value(svcDocTxKey{}).(pgx.Tx); ok {
		return tx
	}
	return r.db.Pool
}

// WithSubjectWriteLock runs fn as the only service-document write in flight for
// subjectHash, anywhere in the fleet. It implements the optional capability the
// document service looks for (service.SubjectWriteSerializer); the service holds
// the quota policy, this holds the mutual exclusion.
//
// Why a lock rather than a conditional write. The obvious-looking alternative is
// to fold the quota into the write statement:
//
//	INSERT ... SELECT ... WHERE (SELECT count(*) ...) < cap
//
// and treat zero rows affected as a refusal. That does not work here. At READ
// COMMITTED each statement reads from the snapshot it started with, so two
// concurrent INSERTs of DIFFERENT keys both evaluate their subquery against the
// pre-write state, both find room, and both insert. Postgres only re-checks a
// conditional write when it collides on a unique index, and distinct keys never
// collide. A cross-row aggregate guard is a write-skew anomaly, and MVCC does
// not prevent write skew below SERIALIZABLE. The conditional write would look
// like a fix, pass a sequential test, and leave the finding standing.
//
// SERIALIZABLE would be sound, but it converts contention into serialization
// failures the whole write path would then have to retry, and the retry loop is
// more machinery and more failure modes than an explicit lock.
//
// pg_advisory_xact_lock is held to the end of the transaction and released by
// COMMIT or ROLLBACK, including the implicit rollback when a backend dies, so no
// crash can strand it. hashtext folds the subject into 32 bits: two subjects can
// collide and then wait for each other needlessly, but one subject can never map
// to two lock words, and only the second of those would matter. hashtext's exact
// values are not guaranteed stable across major versions, which is fine because
// nothing persists them; all that is required is that every backend on one
// cluster agrees at one moment.
func (r *ServiceDocumentRepo) WithSubjectWriteLock(ctx context.Context, subjectHash string, fn func(context.Context) error) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin service document subject lock: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // rollback after commit is a no-op

	// Taken before anything is read. A lock taken after the count would be a
	// lock around nothing: the number it is meant to protect was already read.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`,
		svcDocAdvisoryLockClass, subjectHash); err != nil {
		return fmt.Errorf("lock service document subject: %w", err)
	}

	if err := fn(context.WithValue(ctx, svcDocTxKey{}, tx)); err != nil {
		// Returned exactly as fn produced it. The caller matches sentinel errors
		// against this value to decide an HTTP status, so wrapping it here would
		// change what a rejected caller sees depending on which layer refused.
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit service document write: %w", err)
	}
	return nil
}

func scanServiceDocument(row pgx.Row) (*repository.ServiceDocument, error) {
	var d repository.ServiceDocument
	err := row.Scan(&d.ID, &d.ClientID, &d.SubjectHash, &d.DocKey, &d.Visibility,
		&d.DataEnc, &d.SizeBytes, &d.StoredBytes, &d.Version, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// Get returns one document owned by clientID, or nil, nil if absent.
func (r *ServiceDocumentRepo) Get(ctx context.Context, clientID, subjectHash, docKey string) (*repository.ServiceDocument, error) {
	doc, err := scanServiceDocument(r.q(ctx).QueryRow(ctx, `
		SELECT `+serviceDocumentColumns+`
		FROM objects.service_documents
		WHERE client_id = $1 AND subject_hash = $2 AND doc_key = $3`,
		clientID, subjectHash, docKey))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get service document: %w", err)
	}
	return doc, nil
}

// ListSharedByKey returns every shared document at (subjectHash, docKey) not
// owned by excludeClientID.
func (r *ServiceDocumentRepo) ListSharedByKey(ctx context.Context, subjectHash, docKey, excludeClientID string) ([]*repository.ServiceDocument, error) {
	rows, err := r.q(ctx).Query(ctx, `
		SELECT `+serviceDocumentColumns+`
		FROM objects.service_documents
		WHERE subject_hash = $1 AND doc_key = $2 AND visibility = 1 AND client_id <> $3
		ORDER BY client_id`,
		subjectHash, docKey, excludeClientID)
	if err != nil {
		return nil, fmt.Errorf("list shared service documents by key: %w", err)
	}
	defer rows.Close()

	var docs []*repository.ServiceDocument
	for rows.Next() {
		doc, scanErr := scanServiceDocument(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan shared service document: %w", scanErr)
		}
		docs = append(docs, doc)
	}
	return docs, rows.Err()
}

// Upsert creates or fully replaces a document.
//
// created comes from `xmax = 0`, which is true only on the INSERT branch of
// ON CONFLICT: a row the statement inserted has no updating transaction stamped
// on it. Reading the tag's RowsAffected cannot distinguish the two branches,
// and a preceding SELECT would race with a concurrent writer.
//
// id is not overwritten on the update branch. The ciphertext AAD binds to
// (client_id, subject_hash, doc_key) rather than to the surrogate id, so a
// replacement does not need a fresh id to stay bound, and keeping the id stable
// means a document's identity survives being rewritten.
func (r *ServiceDocumentRepo) Upsert(ctx context.Context, doc *repository.ServiceDocument) (bool, error) {
	var created bool
	err := r.q(ctx).QueryRow(ctx, `
		INSERT INTO objects.service_documents
			(id, client_id, subject_hash, doc_key, visibility, data_enc, size_bytes, stored_bytes, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (client_id, subject_hash, doc_key) DO UPDATE SET
			visibility   = EXCLUDED.visibility,
			data_enc     = EXCLUDED.data_enc,
			size_bytes   = EXCLUDED.size_bytes,
			stored_bytes = EXCLUDED.stored_bytes,
			version      = EXCLUDED.version,
			updated_at   = NOW()
		RETURNING (xmax = 0)`,
		doc.ID, doc.ClientID, doc.SubjectHash, doc.DocKey, doc.Visibility,
		doc.DataEnc, doc.SizeBytes, doc.StoredBytes, doc.Version,
	).Scan(&created)
	if err != nil {
		return false, fmt.Errorf("upsert service document: %w", err)
	}
	return created, nil
}

// Delete removes one document owned by clientID.
func (r *ServiceDocumentRepo) Delete(ctx context.Context, clientID, subjectHash, docKey string) (bool, error) {
	tag, err := r.q(ctx).Exec(ctx, `
		DELETE FROM objects.service_documents
		WHERE client_id = $1 AND subject_hash = $2 AND doc_key = $3`,
		clientID, subjectHash, docKey)
	if err != nil {
		return false, fmt.Errorf("delete service document: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r *ServiceDocumentRepo) listMeta(ctx context.Context, what, query string, args ...any) ([]*repository.ServiceDocument, error) {
	rows, err := r.q(ctx).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", what, err)
	}
	defer rows.Close()

	var docs []*repository.ServiceDocument
	for rows.Next() {
		var d repository.ServiceDocument
		if scanErr := rows.Scan(&d.ID, &d.ClientID, &d.SubjectHash, &d.DocKey, &d.Visibility,
			&d.SizeBytes, &d.StoredBytes, &d.Version, &d.CreatedAt, &d.UpdatedAt); scanErr != nil {
			return nil, fmt.Errorf("scan %s: %w", what, scanErr)
		}
		docs = append(docs, &d)
	}
	return docs, rows.Err()
}

// ListByOwner returns the caller's own documents for a subject, without data_enc.
func (r *ServiceDocumentRepo) ListByOwner(ctx context.Context, clientID, subjectHash string) ([]*repository.ServiceDocument, error) {
	return r.listMeta(ctx, "owned service documents", `
		SELECT `+serviceDocumentMetaColumns+`
		FROM objects.service_documents
		WHERE client_id = $1 AND subject_hash = $2
		ORDER BY doc_key`, clientID, subjectHash)
}

// ListSharedForSubject returns shared documents for a subject owned by other clients.
func (r *ServiceDocumentRepo) ListSharedForSubject(ctx context.Context, subjectHash, excludeClientID string) ([]*repository.ServiceDocument, error) {
	return r.listMeta(ctx, "shared service documents", `
		SELECT `+serviceDocumentMetaColumns+`
		FROM objects.service_documents
		WHERE subject_hash = $1 AND visibility = 1 AND client_id <> $2
		ORDER BY client_id, doc_key`, subjectHash, excludeClientID)
}

// ListAllForSubject returns every document for a subject across all owning
// clients, with data_enc, for the Art. 15 export.
func (r *ServiceDocumentRepo) ListAllForSubject(ctx context.Context, subjectHash string) ([]*repository.ServiceDocument, error) {
	rows, err := r.q(ctx).Query(ctx, `
		SELECT `+serviceDocumentColumns+`
		FROM objects.service_documents
		WHERE subject_hash = $1
		ORDER BY client_id, doc_key`, subjectHash)
	if err != nil {
		return nil, fmt.Errorf("list service documents for subject: %w", err)
	}
	defer rows.Close()

	var docs []*repository.ServiceDocument
	for rows.Next() {
		doc, scanErr := scanServiceDocument(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan service document for subject: %w", scanErr)
		}
		docs = append(docs, doc)
	}
	return docs, rows.Err()
}

// CountForOwner returns how many documents clientID holds for a subject.
func (r *ServiceDocumentRepo) CountForOwner(ctx context.Context, clientID, subjectHash string) (int, error) {
	var n int
	err := r.q(ctx).QueryRow(ctx, `
		SELECT COALESCE(COUNT(*), 0) FROM objects.service_documents
		WHERE client_id = $1 AND subject_hash = $2`, clientID, subjectHash).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count service documents: %w", err)
	}
	return n, nil
}

// SumBytesForSubject returns the total stored bytes held for a subject across
// every owning client.
func (r *ServiceDocumentRepo) SumBytesForSubject(ctx context.Context, subjectHash string) (int, error) {
	var n int
	err := r.q(ctx).QueryRow(ctx, `
		SELECT COALESCE(SUM(stored_bytes), 0) FROM objects.service_documents
		WHERE subject_hash = $1`, subjectHash).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("sum service document bytes: %w", err)
	}
	return n, nil
}

// DeleteAllForSubject removes every document for a subject across all owning
// clients. Unlike Delete it does not report whether anything went: account
// erasure must succeed for a subject no service ever wrote a document about,
// and the cascade is re-run after an interruption.
func (r *ServiceDocumentRepo) DeleteAllForSubject(ctx context.Context, subjectHash string) error {
	_, err := r.q(ctx).Exec(ctx, `
		DELETE FROM objects.service_documents WHERE subject_hash = $1`, subjectHash)
	if err != nil {
		return fmt.Errorf("delete all service documents for subject: %w", err)
	}
	return nil
}
