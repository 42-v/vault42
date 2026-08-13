package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode/utf8"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/repository"
)

// Service documents are a namespaced arbitrary-JSON store with an ownership
// axis: a registered service client writes documents scoped to (itself, a
// subject, a key), and by default nothing else can read them.
//
// Security invariants enforced in this file:
//
//   - Documents are AES-GCM encrypted at rest, never plaintext JSONB. Every
//     at-rest store in vault42 is encrypted, and these documents hold data a
//     service wrote about a user; a plaintext column here would be the product's
//     first plaintext personal-data column.
//   - The AAD binds a ciphertext to its owning client, its subject and its key,
//     so a row copied between clients, subjects or keys fails to decrypt rather
//     than silently changing owner.
//   - The subject is stored as an HMAC pseudonym, so the table does not
//     enumerate which users a service holds records about.
//   - A document body is validated by a token walk before any unmarshal. A
//     64 KiB body of nested array openers is tens of thousands of levels deep
//     and blows the stack during unmarshal; depth has to be bounded on the
//     token stream, before the decoder ever builds a value.
//   - Ownership is a SQL predicate on every request-path read, not a comparison
//     the caller performs after fetching a row.

// GlobalSubject is the sentinel path segment for documents that belong to a
// service rather than to any user: feature flags, per-service settings.
//
// It is a sentinel rather than a NULL subject because Postgres treats NULLs as
// distinct in a unique index, so a nullable column would silently permit
// duplicate (client_id, NULL, doc_key) rows. It cannot collide with a real
// subject: svcDocSubjectCharset requires a subject to start with an
// alphanumeric, and this one starts with an underscore.
const GlobalSubject = "_global"

// Service document limits that are not operator-tunable.
const (
	// svcDocMaxDepth bounds nesting. 32 is far beyond any configuration document
	// and shallow enough that the validating walk cannot exhaust the stack.
	svcDocMaxDepth = 32
	// svcDocMaxKeys bounds decode cost independently of byte size: a document of
	// tiny keys is cheap in bytes and expensive in allocations.
	svcDocMaxKeys = 1024
	// svcDocMaxKeyLen bounds the document key, matching the column width.
	svcDocMaxKeyLen = 128
	// svcDocMaxSubjectLen bounds the subject path segment before it is hashed.
	svcDocMaxSubjectLen = 128
)

// Sentinel errors returned by ServiceDocumentService. The handler maps these to
// status codes; nothing else about a failure reaches the caller.
var (
	// ErrSvcDocInvalidKey is returned for a document key outside the charset.
	ErrSvcDocInvalidKey = errors.New("invalid document key")
	// ErrSvcDocInvalidSubject is returned for a subject outside the charset.
	ErrSvcDocInvalidSubject = errors.New("invalid document subject")
	// ErrSvcDocInvalidDocument is returned for a body that is not a JSON object,
	// is too deeply nested, carries duplicate keys, or is not valid UTF-8.
	ErrSvcDocInvalidDocument = errors.New("invalid document")
	// ErrSvcDocTooLarge is returned when a document exceeds the per-document cap.
	ErrSvcDocTooLarge = errors.New("document too large")
	// ErrSvcDocQuotaExceeded is returned when a write would breach the document
	// count or the per-subject byte quota.
	ErrSvcDocQuotaExceeded = errors.New("document quota exceeded")
	// ErrSvcDocNotFound is returned when no readable document exists.
	ErrSvcDocNotFound = errors.New("document not found")
	// ErrSvcDocAmbiguous is returned when more than one other client publishes a
	// shared document at the requested key and the caller named no owner.
	ErrSvcDocAmbiguous = errors.New("ambiguous document")
	// ErrSvcDocSharedDisabled is returned when a shared write is attempted while
	// the shared visibility tier is switched off.
	ErrSvcDocSharedDisabled = errors.New("shared visibility disabled")
	// ErrSvcDocUnknownOwner is returned when a named owner is not a registered client.
	ErrSvcDocUnknownOwner = errors.New("unknown document owner")
)

var (
	// svcDocKeyRe mirrors the CHECK constraint in migration 014 and the identity
	// store's dynamicKeyRe, extended with '_' and '-'.
	svcDocKeyRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
	// svcDocSubjectCharset is deliberately narrow. The subject is caller-supplied
	// and goes into an HMAC input, so it is constrained to characters that cannot
	// be confused with a delimiter and cannot carry control bytes into a log.
	svcDocSubjectCharset = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)
)

// ServiceDocumentConfig holds the operator-tunable limits.
type ServiceDocumentConfig struct {
	// MaxDocumentBytes caps one document's canonical encoded size.
	MaxDocumentBytes int
	// MaxDocsPerSubject caps how many documents one client holds for one subject.
	MaxDocsPerSubject int
	// QuotaBytesPerSubject caps the stored bytes held for one subject across
	// every owning client, so one user's footprint is bounded no matter how many
	// services write about them.
	QuotaBytesPerSubject int
	// SharedEnabled gates the shared visibility tier. Off means a service can
	// keep private state but no service can read another's documents, which is a
	// separate operator decision from enabling the store at all.
	SharedEnabled bool
}

// ServiceDocumentMetrics is the subset of the metrics collector this service
// records to. It is an interface so the service does not depend on the
// collector, and so a deployment with metrics disabled passes nil.
type ServiceDocumentMetrics interface {
	RecordSvcDocWrite()
	RecordSvcDocRead()
	RecordSvcDocRejected()
}

// ServiceDocumentService stores and retrieves encrypted, service-scoped JSON
// documents.
type ServiceDocumentService struct {
	repo       repository.ServiceDocumentRepository
	clients    repository.ClientRepository
	masterKey  []byte
	hmacSecret []byte
	cfg        ServiceDocumentConfig
	metrics    ServiceDocumentMetrics
}

// NewServiceDocumentService creates a service document service. clients may be
// nil, in which case owner names are omitted from listings and exports rather
// than the operation failing. metrics may be nil.
func NewServiceDocumentService(
	repo repository.ServiceDocumentRepository,
	clients repository.ClientRepository,
	masterKey, hmacSecret []byte,
	cfg ServiceDocumentConfig,
	metrics ServiceDocumentMetrics,
) *ServiceDocumentService {
	return &ServiceDocumentService{
		repo: repo, clients: clients,
		masterKey: masterKey, hmacSecret: hmacSecret,
		cfg: cfg, metrics: metrics,
	}
}

// MaxDocumentBytes exposes the per-document cap so the handler can size its own
// body reader from the same number the service validates against.
func (s *ServiceDocumentService) MaxDocumentBytes() int { return s.cfg.MaxDocumentBytes }

// SharedEnabled reports whether the shared visibility tier is available.
func (s *ServiceDocumentService) SharedEnabled() bool { return s.cfg.SharedEnabled }

// SubjectPseudonym computes the deterministic pseudonym for a user ID. The
// erasure cascade derives the same value to find every document written about
// an erased account, so this derivation and the one in ErasureService must stay
// identical.
func (s *ServiceDocumentService) SubjectPseudonym(userID string) string {
	return vaultcrypto.HMACSign([]byte(userID+":svcdoc"), s.hmacSecret)
}

// subjectHash maps a path subject segment to its stored pseudonym, resolving
// the global sentinel to its own fixed value.
func (s *ServiceDocumentService) subjectHash(subject string) string {
	if subject == GlobalSubject {
		return vaultcrypto.HMACSign([]byte(GlobalSubject+":svcdoc:global"), s.hmacSecret)
	}
	return s.SubjectPseudonym(subject)
}

// docAAD binds a ciphertext to its owning client, its subject and its key. It is
// a superset of the blob AAD: adding the client dimension means a row moved
// between services fails to decrypt, and adding the key means a row moved
// between keys does too. The surrogate id is deliberately absent so a
// replacement keeps its identity without needing a re-key.
func docAAD(clientID, subjectHash, docKey string) []byte {
	return []byte("svcdoc:" + clientID + ":" + subjectHash + ":" + docKey)
}

// ServiceDocumentMeta is the metadata view of a document. It never carries the
// body.
type ServiceDocumentMeta struct {
	Key         string    `json:"key"`
	Owner       string    `json:"owner,omitempty"`
	OwnerID     string    `json:"owner_id"`
	Visibility  string    `json:"visibility"`
	SizeBytes   int       `json:"size_bytes"`
	StoredBytes int       `json:"stored_bytes"`
	Mine        bool      `json:"mine"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ServiceDocumentQuota summarizes a subject's document usage, mirroring the
// blob quota shape.
type ServiceDocumentQuota struct {
	UsedBytes int `json:"used_bytes"`
	MaxBytes  int `json:"max_bytes"`
	UsedCount int `json:"used_count"`
	MaxCount  int `json:"max_count"`
}

// ServiceDocumentExport is one document as it appears in a data export: the
// decrypted body, plus who wrote it.
type ServiceDocumentExport struct {
	Key        string          `json:"key"`
	Owner      string          `json:"owner,omitempty"`
	OwnerID    string          `json:"owner_id"`
	Visibility string          `json:"visibility"`
	SizeBytes  int             `json:"size_bytes"`
	Document   json.RawMessage `json:"document"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// VisibilityName renders the wire form of a visibility tier. The wire form is a
// string enum, not a boolean, so a later tier is an added value rather than a
// changed field type.
func VisibilityName(v repository.ServiceDocumentVisibility) string {
	if v == repository.VisibilityShared {
		return "shared"
	}
	return "private"
}

// ParseVisibility maps the wire form to the stored tier. An empty value is
// private: the default on every write is the closed one.
func ParseVisibility(s string) (repository.ServiceDocumentVisibility, bool) {
	switch s {
	case "", "private":
		return repository.VisibilityPrivate, true
	case "shared":
		return repository.VisibilityShared, true
	default:
		return repository.VisibilityPrivate, false
	}
}

// Put validates, canonicalises, encrypts and stores a document. It is a full
// replace: there is no merge, so a caller that wants to change one field reads,
// edits and writes the whole document.
func (s *ServiceDocumentService) Put(
	ctx context.Context, clientID, subject, docKey string,
	raw []byte, visibility repository.ServiceDocumentVisibility,
) (*ServiceDocumentMeta, bool, error) {
	if err := ValidateDocKey(docKey); err != nil {
		s.rejected()
		return nil, false, err
	}
	if err := ValidateSubject(subject); err != nil {
		s.rejected()
		return nil, false, err
	}
	if visibility == repository.VisibilityShared && !s.cfg.SharedEnabled {
		s.rejected()
		return nil, false, ErrSvcDocSharedDisabled
	}

	canonical, err := s.canonicalize(raw)
	if err != nil {
		s.rejected()
		return nil, false, err
	}

	subjHash := s.subjectHash(subject)

	// Quota is checked against the state the write would produce, so a
	// replacement is not charged twice and does not consume a document slot it
	// already holds.
	existing, err := s.repo.Get(ctx, clientID, subjHash, docKey)
	if err != nil {
		return nil, false, fmt.Errorf("svcdoc load existing: %w", err)
	}

	enc, err := vaultcrypto.Encrypt(canonical, s.masterKey, docAAD(clientID, subjHash, docKey))
	if err != nil {
		return nil, false, fmt.Errorf("svcdoc encrypt: %w", err)
	}

	if err := s.checkQuota(ctx, clientID, subjHash, existing, len(enc)); err != nil {
		s.rejected()
		return nil, false, err
	}

	var id string
	if existing != nil {
		id = existing.ID
	} else {
		id, err = vaultcrypto.RandomUUID()
		if err != nil {
			return nil, false, fmt.Errorf("svcdoc uuid: %w", err)
		}
	}

	doc := &repository.ServiceDocument{
		ID:          id,
		ClientID:    clientID,
		SubjectHash: subjHash,
		DocKey:      docKey,
		Visibility:  visibility,
		DataEnc:     enc,
		SizeBytes:   len(canonical),
		StoredBytes: len(enc),
		Version:     1,
	}
	created, err := s.repo.Upsert(ctx, doc)
	if err != nil {
		return nil, false, fmt.Errorf("svcdoc store: %w", err)
	}
	if s.metrics != nil {
		s.metrics.RecordSvcDocWrite()
	}

	now := time.Now().UTC()
	meta := &ServiceDocumentMeta{
		Key:         docKey,
		OwnerID:     clientID,
		Visibility:  VisibilityName(visibility),
		SizeBytes:   doc.SizeBytes,
		StoredBytes: doc.StoredBytes,
		Mine:        true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if existing != nil {
		meta.CreatedAt = existing.CreatedAt
	}
	return meta, created, nil
}

// checkQuota rejects a write that would breach the document count for this
// (client, subject) or the byte budget for this subject across every client.
// Both are evaluated before the row is written; there is no compensating delete.
func (s *ServiceDocumentService) checkQuota(
	ctx context.Context, clientID, subjHash string,
	existing *repository.ServiceDocument, newStored int,
) error {
	if existing == nil {
		count, err := s.repo.CountForOwner(ctx, clientID, subjHash)
		if err != nil {
			return fmt.Errorf("svcdoc count: %w", err)
		}
		if count >= s.cfg.MaxDocsPerSubject {
			return ErrSvcDocQuotaExceeded
		}
	}

	used, err := s.repo.SumBytesForSubject(ctx, subjHash)
	if err != nil {
		return fmt.Errorf("svcdoc quota: %w", err)
	}
	if existing != nil {
		used -= existing.StoredBytes
	}
	if used+newStored > s.cfg.QuotaBytesPerSubject {
		return ErrSvcDocQuotaExceeded
	}
	return nil
}

// Get returns a readable document body.
//
// Resolution order is the caller's own document first, then a shared document
// published by another client. owner optionally names the publishing client so
// a caller can disambiguate; without it, two clients sharing the same key
// produce ErrSvcDocAmbiguous rather than an arbitrary pick.
//
// A document owned by another client that is NOT shared is reported as absent,
// never as forbidden. The alternative turns the store into an oracle for
// "does service X hold a record at key K about user U", which is exactly the
// question the pseudonymised subject exists to make unanswerable.
func (s *ServiceDocumentService) Get(ctx context.Context, clientID, subject, docKey, owner string) (json.RawMessage, *ServiceDocumentMeta, error) {
	if err := ValidateDocKey(docKey); err != nil {
		return nil, nil, err
	}
	if err := ValidateSubject(subject); err != nil {
		return nil, nil, err
	}
	subjHash := s.subjectHash(subject)

	doc, err := s.resolve(ctx, clientID, subjHash, docKey, owner)
	if err != nil {
		return nil, nil, err
	}

	plaintext, err := vaultcrypto.Decrypt(doc.DataEnc, s.masterKey, docAAD(doc.ClientID, doc.SubjectHash, doc.DocKey))
	if err != nil {
		return nil, nil, fmt.Errorf("svcdoc decrypt: %w", err)
	}
	if s.metrics != nil {
		s.metrics.RecordSvcDocRead()
	}

	meta := s.metaOf(ctx, doc, clientID)
	return json.RawMessage(plaintext), meta, nil
}

// resolve picks the single document a caller may read at a key.
func (s *ServiceDocumentService) resolve(ctx context.Context, clientID, subjHash, docKey, owner string) (*repository.ServiceDocument, error) {
	if owner == "" {
		own, err := s.repo.Get(ctx, clientID, subjHash, docKey)
		if err != nil {
			return nil, fmt.Errorf("svcdoc get: %w", err)
		}
		if own != nil {
			return own, nil
		}
	}

	if owner != "" {
		ownerID, err := s.resolveOwnerID(ctx, owner)
		if err != nil {
			return nil, err
		}
		doc, err := s.repo.Get(ctx, ownerID, subjHash, docKey)
		if err != nil {
			return nil, fmt.Errorf("svcdoc get by owner: %w", err)
		}
		// A named owner that is not the caller only ever yields a shared row.
		if doc == nil || (doc.ClientID != clientID && doc.Visibility != repository.VisibilityShared) {
			return nil, ErrSvcDocNotFound
		}
		return doc, nil
	}

	shared, err := s.repo.ListSharedByKey(ctx, subjHash, docKey, clientID)
	if err != nil {
		return nil, fmt.Errorf("svcdoc get shared: %w", err)
	}
	switch len(shared) {
	case 0:
		return nil, ErrSvcDocNotFound
	case 1:
		return shared[0], nil
	default:
		return nil, ErrSvcDocAmbiguous
	}
}

// resolveOwnerID maps a client name to its id. Names are the human-facing
// handle in the listing response, so the read path accepts the same value it
// hands out rather than requiring the caller to know a UUID.
func (s *ServiceDocumentService) resolveOwnerID(ctx context.Context, owner string) (string, error) {
	if s.clients == nil {
		return "", ErrSvcDocUnknownOwner
	}
	c, err := s.clients.GetByName(ctx, owner)
	if err != nil {
		return "", fmt.Errorf("svcdoc resolve owner: %w", err)
	}
	if c == nil {
		return "", ErrSvcDocUnknownOwner
	}
	return c.ID, nil
}

// Delete removes the caller's own document. A client can never delete another
// client's row, shared or not.
func (s *ServiceDocumentService) Delete(ctx context.Context, clientID, subject, docKey string) error {
	if err := ValidateDocKey(docKey); err != nil {
		return err
	}
	if err := ValidateSubject(subject); err != nil {
		return err
	}
	deleted, err := s.repo.Delete(ctx, clientID, s.subjectHash(subject), docKey)
	if err != nil {
		return fmt.Errorf("svcdoc delete: %w", err)
	}
	if !deleted {
		return ErrSvcDocNotFound
	}
	return nil
}

// List returns metadata for the caller's own documents plus the shared
// documents other clients hold for the same subject, and the subject's quota
// position. Bodies are never returned by a listing.
func (s *ServiceDocumentService) List(ctx context.Context, clientID, subject string) ([]*ServiceDocumentMeta, *ServiceDocumentQuota, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, nil, err
	}
	subjHash := s.subjectHash(subject)

	own, err := s.repo.ListByOwner(ctx, clientID, subjHash)
	if err != nil {
		return nil, nil, fmt.Errorf("svcdoc list own: %w", err)
	}
	shared, err := s.repo.ListSharedForSubject(ctx, subjHash, clientID)
	if err != nil {
		return nil, nil, fmt.Errorf("svcdoc list shared: %w", err)
	}
	usedBytes, err := s.repo.SumBytesForSubject(ctx, subjHash)
	if err != nil {
		return nil, nil, fmt.Errorf("svcdoc list quota: %w", err)
	}

	metas := make([]*ServiceDocumentMeta, 0, len(own)+len(shared))
	for _, d := range own {
		metas = append(metas, s.metaOf(ctx, d, clientID))
	}
	for _, d := range shared {
		metas = append(metas, s.metaOf(ctx, d, clientID))
	}

	quota := &ServiceDocumentQuota{
		UsedBytes: usedBytes,
		MaxBytes:  s.cfg.QuotaBytesPerSubject,
		UsedCount: len(own),
		MaxCount:  s.cfg.MaxDocsPerSubject,
	}
	return metas, quota, nil
}

// ExportForSubject returns every document held for a user, decrypted, for the
// Art. 15 export.
//
// It returns bodies rather than metadata, which is a deliberate divergence from
// the blob section of the export. Blobs are opaque files the user uploaded
// themselves; service documents are bounded structured records a service wrote
// ABOUT the user, which is squarely the personal data undergoing processing.
// Private documents are included: a service's privacy from other services is
// not privacy from the data subject. Global documents are excluded: they are
// not attached to any subject and exporting them would hand one service's
// configuration to every user who asks.
//
// A document that fails to decrypt is skipped rather than failing the whole
// export: one unreadable row must not deny a subject the rest of their data.
func (s *ServiceDocumentService) ExportForSubject(ctx context.Context, userID string) ([]*ServiceDocumentExport, error) {
	subjHash := s.SubjectPseudonym(userID)
	docs, err := s.repo.ListAllForSubject(ctx, subjHash)
	if err != nil {
		return nil, fmt.Errorf("svcdoc export: %w", err)
	}

	out := make([]*ServiceDocumentExport, 0, len(docs))
	for _, d := range docs {
		plaintext, decErr := vaultcrypto.Decrypt(d.DataEnc, s.masterKey, docAAD(d.ClientID, d.SubjectHash, d.DocKey))
		if decErr != nil {
			continue
		}
		out = append(out, &ServiceDocumentExport{
			Key:        d.DocKey,
			Owner:      s.ownerName(ctx, d.ClientID),
			OwnerID:    d.ClientID,
			Visibility: VisibilityName(d.Visibility),
			SizeBytes:  d.SizeBytes,
			Document:   json.RawMessage(plaintext),
			CreatedAt:  d.CreatedAt,
			UpdatedAt:  d.UpdatedAt,
		})
	}
	return out, nil
}

// DeleteAllForSubject removes every document held about a user, across every
// owning service. Called by the erasure cascade; idempotent.
func (s *ServiceDocumentService) DeleteAllForSubject(ctx context.Context, userID string) error {
	return s.repo.DeleteAllForSubject(ctx, s.SubjectPseudonym(userID))
}

func (s *ServiceDocumentService) metaOf(ctx context.Context, d *repository.ServiceDocument, callerID string) *ServiceDocumentMeta {
	return &ServiceDocumentMeta{
		Key:         d.DocKey,
		Owner:       s.ownerName(ctx, d.ClientID),
		OwnerID:     d.ClientID,
		Visibility:  VisibilityName(d.Visibility),
		SizeBytes:   d.SizeBytes,
		StoredBytes: d.StoredBytes,
		Mine:        d.ClientID == callerID,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
	}
}

// ownerName resolves a client id to its registered name. A lookup failure
// degrades to an empty name rather than failing the request: the id is already
// in the response and the name is a convenience.
func (s *ServiceDocumentService) ownerName(ctx context.Context, clientID string) string {
	if s.clients == nil {
		return ""
	}
	c, err := s.clients.GetByID(ctx, clientID)
	if err != nil || c == nil {
		return ""
	}
	return c.Name
}

func (s *ServiceDocumentService) rejected() {
	if s.metrics != nil {
		s.metrics.RecordSvcDocRejected()
	}
}

// ValidateDocKey checks a document key against the same shape the migration's
// CHECK constraint enforces, so a bad key is a 400 rather than a constraint
// violation surfacing as a 500.
func ValidateDocKey(key string) error {
	if key == "" || len(key) > svcDocMaxKeyLen || !svcDocKeyRe.MatchString(key) {
		return ErrSvcDocInvalidKey
	}
	return nil
}

// ValidateSubject checks a subject path segment. The global sentinel is
// accepted verbatim; anything else must match the narrow subject charset.
func ValidateSubject(subject string) error {
	if subject == GlobalSubject {
		return nil
	}
	if subject == "" || len(subject) > svcDocMaxSubjectLen || !svcDocSubjectCharset.MatchString(subject) {
		return ErrSvcDocInvalidSubject
	}
	return nil
}

// canonicalize validates a submitted document and returns its canonical
// encoding. Validation runs entirely on the token stream first; nothing is
// unmarshalled until the body is known to be a bounded, well-formed object.
func (s *ServiceDocumentService) canonicalize(raw []byte) ([]byte, error) {
	if len(raw) > s.cfg.MaxDocumentBytes {
		return nil, ErrSvcDocTooLarge
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, ErrSvcDocInvalidDocument
	}
	// Checked on the raw bytes, because the JSON decoder replaces invalid UTF-8
	// with U+FFFD as it reads: by the time a token is in hand the evidence is
	// gone, and the document would round-trip differently than it was submitted.
	if !utf8.Valid(raw) {
		return nil, ErrSvcDocInvalidDocument
	}
	if err := ValidateDocumentStructure(raw); err != nil {
		return nil, err
	}

	var decoded map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers are carried as literals so a large integer or a high-precision
	// decimal is stored exactly as written rather than round-tripped through a
	// float64 and silently changed.
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, ErrSvcDocInvalidDocument
	}
	// Trailing content after the object is a second document, not whitespace.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrSvcDocInvalidDocument
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// HTML escaping off: it would rewrite '<', '>' and '&' inside string values
	// into their \u00xx forms, so a stored document would not match what the
	// service submitted. Nothing renders these bodies as HTML.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(decoded); err != nil {
		return nil, ErrSvcDocInvalidDocument
	}
	canonical := bytes.TrimRight(buf.Bytes(), "\n")

	if len(canonical) > s.cfg.MaxDocumentBytes {
		return nil, ErrSvcDocTooLarge
	}
	return canonical, nil
}

// ValidateDocumentStructure walks a document's token stream and rejects
// anything the store will not hold.
//
// The walk exists because encoding/json has no depth limit and no duplicate-key
// rejection. A 64 KiB body of '[' characters is roughly 32 thousand nesting
// levels; unmarshalling it recurses that deep and takes the process down. And a
// document with a repeated key decodes last-wins, so it round-trips differently
// than it was submitted, which is a correctness bug on its own and a signature-bypass
// primitive if anything downstream ever verifies a body it also parses.
//
// json.Decoder.Token keeps its own iterative parse state, so reading the stream
// costs no stack; only this function's own recursion does, and that is bounded
// by the depth check below at svcDocMaxDepth frames.
func ValidateDocumentStructure(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return ErrSvcDocInvalidDocument
	}
	delim, ok := tok.(json.Delim)
	// The top level must be an object. An array or a scalar leaves no room for a
	// future merge-patch endpoint and makes the stored shape unpredictable.
	if !ok || delim != '{' {
		return ErrSvcDocInvalidDocument
	}

	keys := 0
	if err := walkDocObject(dec, 1, &keys); err != nil {
		return err
	}
	// The closing brace of the top-level object.
	if _, err := dec.Token(); err != nil {
		return ErrSvcDocInvalidDocument
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrSvcDocInvalidDocument
	}
	return nil
}

// walkDocObject consumes an object's members. The opening brace has already
// been read; the closing brace is left for the caller.
func walkDocObject(dec *json.Decoder, depth int, keys *int) error {
	if depth > svcDocMaxDepth {
		return ErrSvcDocInvalidDocument
	}
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return ErrSvcDocInvalidDocument
		}
		key, ok := tok.(string)
		if !ok {
			return ErrSvcDocInvalidDocument
		}
		if _, dup := seen[key]; dup {
			return ErrSvcDocInvalidDocument
		}
		seen[key] = struct{}{}

		*keys++
		if *keys > svcDocMaxKeys {
			return ErrSvcDocInvalidDocument
		}
		if err := walkDocValue(dec, depth, keys); err != nil {
			return err
		}
	}
	return nil
}

// walkDocArray consumes an array's elements. The opening bracket has already
// been read; the closing bracket is left for the caller.
func walkDocArray(dec *json.Decoder, depth int, keys *int) error {
	if depth > svcDocMaxDepth {
		return ErrSvcDocInvalidDocument
	}
	for dec.More() {
		if err := walkDocValue(dec, depth, keys); err != nil {
			return err
		}
	}
	return nil
}

// walkDocValue consumes exactly one value, descending into containers.
func walkDocValue(dec *json.Decoder, depth int, keys *int) error {
	tok, err := dec.Token()
	if err != nil {
		return ErrSvcDocInvalidDocument
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		if err := walkDocObject(dec, depth+1, keys); err != nil {
			return err
		}
	case '[':
		if err := walkDocArray(dec, depth+1, keys); err != nil {
			return err
		}
	default:
		// A bare '}' or ']' here means the stream is not well formed.
		return ErrSvcDocInvalidDocument
	}
	if _, err := dec.Token(); err != nil {
		return ErrSvcDocInvalidDocument
	}
	return nil
}
