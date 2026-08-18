package service

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// Sentinel errors returned by BlobService methods.
var (
	ErrBlobTooSmall  = errors.New("blob too small")
	ErrBlobTooLarge  = errors.New("blob too large")
	ErrQuotaExceeded = errors.New("storage quota exceeded")
	ErrBlobNotFound  = errors.New("blob not found")
)

// BlobConfig holds blob storage limits.
type BlobConfig struct {
	MinBlobSize     int // min single blob size in bytes
	MaxBlobSize     int // max single blob size in bytes
	MaxBlobsPerUser int // max number of blobs per user
	QuotaBytes      int // total storage quota per user in bytes
}

// BlobService manages encrypted blob storage.
type BlobService struct {
	repo       repository.BlobRepository
	masterKey  []byte
	hmacSecret []byte
	config     BlobConfig
}

// NewBlobService creates a new blob service.
func NewBlobService(repo repository.BlobRepository, masterKey, hmacSecret []byte, cfg BlobConfig) *BlobService {
	return &BlobService{repo: repo, masterKey: masterKey, hmacSecret: hmacSecret, config: cfg}
}

// Pseudonym computes the deterministic pseudonym for a user ID.

// blobDataAAD and blobLabelAAD build the additional authenticated data that
// binds a blob's ciphertext to its id and its owner.
//
// The two namespaces are NOT prefix-free. blobDataAAD is "<id>:<pseudonym>" and
// blobLabelAAD is "label:<id>:<pseudonym>", so a blob whose id were literally
// "label:X" would produce the same AAD as the LABEL of blob "X", and the two
// ciphertexts could be exchanged without AES-GCM noticing.
//
// What closes that is the id being a server-generated UUID, which contains no
// colon. That is a real guarantee but it was an incidental one: nothing said so,
// and nothing checked it. These helpers state it and enforce it.
//
// The AAD format itself is deliberately unchanged. A length-prefixed or
// domain-tagged encoding would be the better construction on a blank sheet, and
// adopting one now would make every blob already in the database undecryptable,
// which is a worse outcome than a weakness that cannot currently be reached.
func blobAADSafeID(id string) bool {
	return !strings.Contains(id, ":")
}

// errBlobIDNamespace is returned when a blob id would make the data and label
// AAD namespaces ambiguous.
var errBlobIDNamespace = errors.New("blob: id must not contain ':'")

func blobDataAAD(id, pseudo string) ([]byte, error) {
	if !blobAADSafeID(id) {
		return nil, errBlobIDNamespace
	}
	return []byte(id + ":" + pseudo), nil
}

func blobLabelAAD(id, pseudo string) ([]byte, error) {
	if !blobAADSafeID(id) {
		return nil, errBlobIDNamespace
	}
	return []byte("label:" + id + ":" + pseudo), nil
}

func (s *BlobService) Pseudonym(userID string) string {
	return vaultcrypto.HMACSign([]byte(userID+":objects"), s.hmacSecret)
}

// refHash computes a deterministic, non-reversible hash of a reference name
// scoped to a pseudonym, suitable for DB lookup without storing plaintext names.
func (s *BlobService) refHash(name, pseudo string) string {
	return vaultcrypto.HMACSign([]byte("ref:"+name+":"+pseudo), s.hmacSecret)
}

// Upload compresses, encrypts, and stores a blob for a user.
func (s *BlobService) Upload(ctx context.Context, userID string, data []byte, label string) (*model.Blob, error) {
	return s.uploadInternal(ctx, userID, data, label, "")
}

// UploadNamed compresses, encrypts, and stores a named blob for a user.
// If a blob with the same name already exists, it is replaced (delete + insert).
func (s *BlobService) UploadNamed(ctx context.Context, userID string, data []byte, name string) (*model.Blob, error) {
	return s.uploadInternal(ctx, userID, data, name, name)
}

// uploadInternal is the shared implementation for Upload and UploadNamed.
func (s *BlobService) uploadInternal(ctx context.Context, userID string, data []byte, label, refName string) (*model.Blob, error) {
	if s.config.MinBlobSize > 0 && len(data) < s.config.MinBlobSize {
		return nil, ErrBlobTooSmall
	}
	if len(data) > s.config.MaxBlobSize {
		return nil, ErrBlobTooLarge
	}

	pseudo := s.Pseudonym(userID)

	// The row a named upload would replace is LOADED here, not deleted.
	//
	// It used to be deleted at this point, so that the quota below would not
	// charge a replacement twice. The effect was that a replacement the quota
	// then refused had already destroyed the blob it was replacing: an oversized
	// backup came back as "409 quota_exceeded" and the previous backup was gone,
	// with no second copy anywhere and nothing in the response saying so. The
	// discount that delete existed to provide is arithmetic, and arithmetic does
	// not have to happen before the decision it feeds.
	var (
		rh       string
		existing *model.Blob
	)
	if refName != "" {
		rh = s.refHash(refName, pseudo)
		var getErr error
		existing, getErr = s.repo.GetByRefAndPseudonym(ctx, rh, pseudo)
		if getErr != nil {
			return nil, fmt.Errorf("blob replace lookup: %w", getErr)
		}
	}

	// Check quota before processing
	quota, err := s.repo.GetQuota(ctx, pseudo)
	if err != nil {
		return nil, fmt.Errorf("blob quota check: %w", err)
	}
	// A replacement already holds one slot and one copy of the bytes, so both
	// are discounted before the incoming object is charged. This is what the
	// pre-emptive delete was buying, without the data loss.
	usedCount, usedBytes := quota.UsedCount, quota.UsedBytes
	if existing != nil {
		usedCount--
		usedBytes -= existing.StoredBytes
	}
	if usedCount >= s.config.MaxBlobsPerUser {
		return nil, ErrQuotaExceeded
	}

	// Compress (deflate — stdlib, no external deps)
	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("blob compress init: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("blob compress write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("blob compress close: %w", err)
	}

	// Check byte quota (using compressed+encrypted estimate: compressed size + AES overhead ~28 bytes)
	estimatedStored := compressed.Len() + 28
	if usedBytes+estimatedStored > s.config.QuotaBytes {
		return nil, ErrQuotaExceeded
	}

	// Compute checksum of original data
	hash := sha256.Sum256(data)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	// Generate blob ID before encryption so it can be used as AAD
	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("blob uuid: %w", err)
	}

	// AAD binds ciphertext to this specific blob + owner
	dataAAD, err := blobDataAAD(id, pseudo)
	if err != nil {
		return nil, err
	}

	// Encrypt compressed data
	dataEnc, err := vaultcrypto.Encrypt(compressed.Bytes(), s.masterKey, dataAAD)
	if err != nil {
		return nil, fmt.Errorf("blob encrypt: %w", err)
	}

	// Encrypt label if provided
	var labelEnc []byte
	if label != "" {
		labelAAD, aadErr := blobLabelAAD(id, pseudo)
		if aadErr != nil {
			return nil, aadErr
		}
		labelEnc, err = vaultcrypto.Encrypt([]byte(label), s.masterKey, labelAAD)
		if err != nil {
			return nil, fmt.Errorf("blob label encrypt: %w", err)
		}
	}

	blob := &model.Blob{
		ID:          id,
		PseudonymID: pseudo,
		RefHash:     rh,
		LabelEnc:    labelEnc,
		DataEnc:     dataEnc,
		SizeBytes:   len(data),
		StoredBytes: len(dataEnc),
		Checksum:    checksum,
		CreatedAt:   time.Now(),
	}

	// The replaced row goes now, one step before the insert that supersedes it.
	// Everything that can refuse this upload — both quotas, compression,
	// entropy, both encryptions — has already run, so the only failure left
	// after this line is the insert itself, and that one is compensated below.
	if rh != "" {
		// Best-effort delete — ignore "not found" (first upload for this name).
		_ = s.repo.DeleteByRefAndPseudonym(ctx, rh, pseudo)
	}

	if err := s.repo.Create(ctx, blob); err != nil {
		s.restoreReplaced(ctx, existing)
		return nil, fmt.Errorf("blob store: %w", err)
	}

	return blob, nil
}

// restoreReplaced puts back the row a replacement deleted when the replacement
// itself could not be written.
//
// Without it the last remaining window is real: the old blob is gone, the new
// one never landed, and the caller is told only that their upload failed. The
// row is still in memory because the quota discount needed it, so putting it
// back costs one insert.
//
// If that insert fails too the object is genuinely lost, and this is the only
// place that can say so — the caller's error describes the upload, not the
// destruction of what it was replacing.
func (s *BlobService) restoreReplaced(ctx context.Context, existing *model.Blob) {
	if existing == nil {
		return
	}
	if err := s.repo.Create(ctx, existing); err != nil {
		log.Printf("ERROR: blob: FAILED to restore the replaced blob after the replacement write "+
			"failed; the stored object is gone: id=%s pseudonym=%s: %v",
			existing.ID, existing.PseudonymID, err)
	}
}

// Download retrieves, decrypts, and decompresses a blob by ID.
func (s *BlobService) Download(ctx context.Context, userID, blobID string) (data []byte, label string, checksum string, err error) {
	pseudo := s.Pseudonym(userID)
	blob, err := s.repo.GetByIDAndPseudonym(ctx, blobID, pseudo)
	if err != nil {
		return nil, "", "", fmt.Errorf("blob get: %w", err)
	}
	return s.decryptBlob(blob, pseudo)
}

// DownloadNamed retrieves, decrypts, and decompresses a blob by reference name.
func (s *BlobService) DownloadNamed(ctx context.Context, userID, name string) (data []byte, label string, checksum string, err error) {
	pseudo := s.Pseudonym(userID)
	rh := s.refHash(name, pseudo)
	blob, err := s.repo.GetByRefAndPseudonym(ctx, rh, pseudo)
	if err != nil {
		return nil, "", "", fmt.Errorf("blob get by ref: %w", err)
	}
	return s.decryptBlob(blob, pseudo)
}

// decryptBlob decrypts and decompresses a blob retrieved from the repository.
func (s *BlobService) decryptBlob(blob *model.Blob, pseudo string) (data []byte, label string, checksum string, err error) {
	if blob == nil {
		return nil, "", "", nil
	}

	// Decrypt (AAD must match what was used during encryption)
	dataAAD, err := blobDataAAD(blob.ID, pseudo)
	if err != nil {
		return nil, "", "", err
	}
	compressed, err := vaultcrypto.Decrypt(blob.DataEnc, s.masterKey, dataAAD)
	if err != nil {
		return nil, "", "", fmt.Errorf("blob decrypt: %w", err)
	}
	// The compressed plaintext is the user's blob. It is ours, it does not
	// escape this function, and the decompressor is finished with it by the time
	// this runs (AR-25, ASVS V8.3.2).
	defer config.ZeroBytes(compressed)

	// Decompress with size limit to prevent decompression bombs.
	// 10 MB is generous for user blobs but prevents unbounded memory use.
	const maxDecompressedSize = 10 * 1024 * 1024 // 10 MB
	r := flate.NewReader(bytes.NewReader(compressed))
	decompressed, err := io.ReadAll(io.LimitReader(r, maxDecompressedSize+1))
	r.Close() // #nosec G104 -- decompressor close after data fully read
	if err == nil && len(decompressed) > maxDecompressedSize {
		return nil, "", "", fmt.Errorf("blob decompress: exceeds maximum decompressed size (%d bytes)", maxDecompressedSize)
	}
	if err != nil {
		return nil, "", "", fmt.Errorf("blob decompress: %w", err)
	}

	// Decrypt label
	if len(blob.LabelEnc) > 0 {
		labelAAD, aadErr := blobLabelAAD(blob.ID, pseudo)
		if aadErr != nil {
			return nil, "", "", aadErr
		}
		labelBytes, err := vaultcrypto.Decrypt(blob.LabelEnc, s.masterKey, labelAAD)
		if err != nil {
			return nil, "", "", fmt.Errorf("blob label decrypt: %w", err)
		}
		// string() copies, so the label survives the wipe.
		label = string(labelBytes)
		config.ZeroBytes(labelBytes)
	}

	return decompressed, label, blob.Checksum, nil
}

// List returns blob metadata for a user.
func (s *BlobService) List(ctx context.Context, userID string) ([]*BlobMeta, *BlobQuotaInfo, error) {
	pseudo := s.Pseudonym(userID)

	blobs, err := s.repo.ListByPseudonym(ctx, pseudo)
	if err != nil {
		return nil, nil, fmt.Errorf("blob list: %w", err)
	}

	quota, err := s.repo.GetQuota(ctx, pseudo)
	if err != nil {
		return nil, nil, fmt.Errorf("blob quota: %w", err)
	}

	metas := make([]*BlobMeta, 0, len(blobs))
	for _, b := range blobs {
		meta := &BlobMeta{
			ID:          b.ID,
			Named:       b.RefHash != "",
			SizeBytes:   b.SizeBytes,
			StoredBytes: b.StoredBytes,
			Checksum:    b.Checksum,
			CreatedAt:   b.CreatedAt,
		}
		// Decrypt label for listing
		if len(b.LabelEnc) > 0 {
			labelAAD, aadErr := blobLabelAAD(b.ID, pseudo)
			if aadErr != nil {
				continue
			}
			labelBytes, err := vaultcrypto.Decrypt(b.LabelEnc, s.masterKey, labelAAD)
			if err == nil {
				meta.Label = string(labelBytes)
				// Wiped here rather than deferred: this runs once per blob in
				// the listing, and a defer would hold every label until the
				// whole list is built.
				config.ZeroBytes(labelBytes)
			}
		}
		metas = append(metas, meta)
	}

	quotaInfo := &BlobQuotaInfo{
		UsedBytes: quota.UsedBytes,
		MaxBytes:  s.config.QuotaBytes,
		UsedCount: quota.UsedCount,
		MaxCount:  s.config.MaxBlobsPerUser,
	}

	return metas, quotaInfo, nil
}

// Delete removes a blob by ID for a user.
func (s *BlobService) Delete(ctx context.Context, userID, blobID string) error {
	err := s.repo.Delete(ctx, blobID, s.Pseudonym(userID))
	if err != nil && err.Error() == "blob not found" {
		return ErrBlobNotFound
	}
	return err
}

// DeleteNamed removes a blob by reference name for a user.
func (s *BlobService) DeleteNamed(ctx context.Context, userID, name string) error {
	pseudo := s.Pseudonym(userID)
	rh := s.refHash(name, pseudo)
	err := s.repo.DeleteByRefAndPseudonym(ctx, rh, pseudo)
	if err != nil && err.Error() == "blob not found" {
		return ErrBlobNotFound
	}
	return err
}

// BlobMeta is the decrypted metadata returned to clients.
type BlobMeta struct {
	ID          string    `json:"id"`
	Label       string    `json:"label,omitempty"`
	Named       bool      `json:"named"`
	SizeBytes   int       `json:"size_bytes"`
	StoredBytes int       `json:"stored_bytes"`
	Checksum    string    `json:"checksum"`
	CreatedAt   time.Time `json:"created_at"`
}

// BlobQuotaInfo summarizes quota usage.
type BlobQuotaInfo struct {
	UsedBytes int `json:"used_bytes"`
	MaxBytes  int `json:"max_bytes"`
	UsedCount int `json:"used_count"`
	MaxCount  int `json:"max_count"`
}
