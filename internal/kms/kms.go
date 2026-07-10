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

// Service derives per-kid KEKs from a KMS root secret and wraps/unwraps key
// envelopes under them. It is safe for concurrent use: the root is immutable
// after construction and derivation allocates fresh buffers per call.
type Service struct {
	root []byte // copy of the KMS root secret; wiped by Close, never logged
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
func (s *Service) deriveKEK(kid string) ([]byte, error) {
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

// Close zeroes the root secret. After Close the Service must not be used.
func (s *Service) Close() {
	wipe(s.root)
}

// wipe overwrites b with zeros to shorten the in-memory lifetime of key material.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
