package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

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

// ServiceDocumentRepo implements repository.ServiceDocumentRepository.
type ServiceDocumentRepo struct {
	db *DB
}

// NewServiceDocumentRepo creates a new PostgreSQL-backed service document repository.
func NewServiceDocumentRepo(db *DB) *ServiceDocumentRepo {
	return &ServiceDocumentRepo{db: db}
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
	doc, err := scanServiceDocument(r.db.Pool.QueryRow(ctx, `
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
	rows, err := r.db.Pool.Query(ctx, `
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
	err := r.db.Pool.QueryRow(ctx, `
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
	tag, err := r.db.Pool.Exec(ctx, `
		DELETE FROM objects.service_documents
		WHERE client_id = $1 AND subject_hash = $2 AND doc_key = $3`,
		clientID, subjectHash, docKey)
	if err != nil {
		return false, fmt.Errorf("delete service document: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r *ServiceDocumentRepo) listMeta(ctx context.Context, what, query string, args ...any) ([]*repository.ServiceDocument, error) {
	rows, err := r.db.Pool.Query(ctx, query, args...)
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
	rows, err := r.db.Pool.Query(ctx, `
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
	err := r.db.Pool.QueryRow(ctx, `
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
	err := r.db.Pool.QueryRow(ctx, `
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
	_, err := r.db.Pool.Exec(ctx, `
		DELETE FROM objects.service_documents WHERE subject_hash = $1`, subjectHash)
	if err != nil {
		return fmt.Errorf("delete all service documents for subject: %w", err)
	}
	return nil
}
