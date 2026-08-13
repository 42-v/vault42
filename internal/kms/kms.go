// Package kms implements vault42's KEK envelope-unwrap oracle: the primitive
// behind POST /kms/unwrap. It is the KMS Decrypt half of an envelope-encryption
// scheme — a caller holds a wrapped key and asks vault42 to unwrap it; vault42
// holds the Key-Encryption-Key (KEK) and never releases it.
//
// Design (built on the existing internal/crypto AEAD primitive, not new crypto):
//
//   - A single KMS root secret is provisioned to vault42 (KMS_ROOT_KEY_FILE).
//     Per-kid KEKs are derived from it with HKDF-SHA256 and a versioned,
//     domain-separated info label. This keeps the KMS keyspace cryptographically
//     separate from the master key (which encrypts TOTP/identity/blob at rest)
//     while supporting rotation and multiple wrapped artifacts by kid without
//     provisioning a new secret per kid.
//
//   - Wrap/Unwrap use AES-256-GCM (crypto.Encrypt/Decrypt): an authenticated
//     AEAD, never a raw unauthenticated cipher. The kid is bound as GCM AAD so a
//     ciphertext wrapped under one kid cannot be opened under another even if the
//     derived keys somehow collided.
//
//   - Unwrap is oracle-resistant: every failure mode (unknown-shape kid,
//     malformed envelope, tampered ciphertext, wrong KEK) collapses to a single
//     opaque ErrUnwrap. No branch reveals which check failed, and key material is
//     never returned in, or derivable from, an error.
package kms

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"sync"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// kekInfoPrefix is the HKDF domain-separation label for KEK derivation. It is
// versioned (v1) so a future KDF or construction change can coexist with
// already-wrapped deploy artifacts under a new label without ambiguity.
const kekInfoPrefix = "vault42/kms/kek/v1/"

// kekSize is the AES-256 KEK length in bytes.
const kekSize = 32

// minRootBytes is the minimum accepted KMS root secret length. HKDF accepts
// variable-length input keying material, but we require at least 256 bits of
// entropy in the root.
const minRootBytes = 32

// ErrUnwrap is the single, opaque error returned for EVERY unwrap failure —
// malformed envelope, tampered ciphertext, or wrong KEK. Callers (and, through
// them, network attackers) cannot distinguish the failure modes, so the
// endpoint cannot be used as a decryption oracle.
var ErrUnwrap = errors.New("kms: unwrap failed")

// ErrClosed is returned by Wrap once the Service has been closed. Unwrap
// collapses it into ErrUnwrap like every other failure, so the oracle property
// is unchanged; Wrap is not attacker-facing and says what actually happened.
var ErrClosed = errors.New("kms: service is closed")

// Service derives per-kid KEKs from a KMS root secret and wraps/unwraps key
// envelopes under them. Derivation allocates fresh buffers per call, and the
// root is guarded against Close, so the type is safe for concurrent use
// including during shutdown.
type Service struct {
	// mu guards root against Close. Close zeroes the secret every other method
	// derives from, so "immutable after construction" was true only until the
	// first shutdown: a request in flight when the process caught SIGTERM read
	// the root while Close wrote it.
	//
	// A read lock is the right shape rather than an atomic swap, because the
	// derivation has to complete against a root that is still whole. Holding it
	// for the HKDF call is cheap; Close is once per process.
	mu     sync.RWMutex
	root   []byte // copy of the KMS root secret; wiped by Close, never logged
	closed bool
}

// New returns a Service over a copy of root. root must be at least 32 bytes.
// The caller may zero its own copy after New returns.
func New(root []byte) (*Service, error) {
	if len(root) < minRootBytes {
		return nil, errors.New("kms: root key must be at least 32 bytes")
	}
	return &Service{root: append([]byte(nil), root...)}, nil
}

// deriveKEK derives the 32-byte AES-256 KEK for kid via HKDF-SHA256. The kid is
// carried in the HKDF info, so each kid yields an independent KEK.
//
// The closed check is not defensive tidiness, it is the whole control. Wiping
// the root leaves 32 zero bytes, which is a perfectly valid HKDF input, so
// without this a closed Service kept deriving and Wrap kept returning envelopes
// that looked correct. Those envelopes were sealed under HKDF over an all-zero
// root, which means anyone who constructs a Service over 32 zero bytes can open
// them. Failing closed here is what stops a shutdown race turning into
// permanently readable ciphertext.
func (s *Service) deriveKEK(kid string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	return hkdf.Key(sha256.New, s.root, nil, kekInfoPrefix+kid, kekSize)
}

// Wrap seals plaintext under the KEK for kid, returning the envelope
// (nonce || AES-256-GCM ciphertext, with kid as AAD). This is the inverse of
// Unwrap; it lets deploy tooling and tests produce artifacts the oracle accepts.
func (s *Service) Wrap(kid string, plaintext []byte) ([]byte, error) {
	if kid == "" {
		return nil, errors.New("kms: empty kid")
	}
	kek, err := s.deriveKEK(kid)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)
	return vaultcrypto.Encrypt(plaintext, kek, []byte(kid))
}

// Unwrap opens an envelope produced by Wrap and returns the plaintext key.
// Every failure — empty kid, key-derivation failure, malformed/tampered
// ciphertext, or wrong KEK — is collapsed to ErrUnwrap so the endpoint reveals
// only success/failure, never the reason. AES-GCM's tag verification is
// constant-time, and no plaintext is ever emitted on failure.
func (s *Service) Unwrap(kid string, envelope []byte) ([]byte, error) {
	if kid == "" {
		return nil, ErrUnwrap
	}
	kek, err := s.deriveKEK(kid)
	if err != nil {
		return nil, ErrUnwrap
	}
	defer wipe(kek)
	plaintext, err := vaultcrypto.Decrypt(envelope, kek, []byte(kid))
	if err != nil {
		return nil, ErrUnwrap
	}
	return plaintext, nil
}

// Close zeroes the root secret and marks the Service unusable.
//
// It takes the write lock, so it cannot land midway through a derivation, and
// it is idempotent because shutdown paths call it from more than one defer.
func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	wipe(s.root)
}

// wipe overwrites b with zeros to shorten the in-memory lifetime of key material.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
