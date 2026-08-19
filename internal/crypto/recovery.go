package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"strings"
)

// Recovery escrow uses hybrid asymmetric encryption so the server can WRITE
// recovery records (with a public key) but cannot READ them back: only the
// holder of the offline private key can decrypt. This protects deleted users'
// emails from a compromised server or database while still allowing an operator
// to restore them from backup.
//
// Scheme:
//  1. A fresh random AES-256 key encrypts the plaintext with AES-256-GCM
//     (reusing Encrypt, which prepends a random nonce).
//  2. The AES key is wrapped with RSA-OAEP(SHA-256) under the recovery public key.
//
// BOTH layers are bound to the escrow row the blob belongs to. The binding is
// the AES-GCM AAD and the RSA-OAEP label at the same time, so a blob lifted out
// of one auth.account_recovery row and dropped into another fails at the key
// unwrap, before any AES key exists to try.
//
// This is not decoration. auth.account_recovery keeps deleted_at, deleted_by and
// reason as ordinary columns next to the ciphertext, and cmd/recover joins the
// decrypted profile to those columns to produce each recovered account. Before
// the binding existed nothing tied the two halves together: anyone who could
// write the table could move a payload from one row to another, and the recovery
// tool would report the move as fact - the wrong person recorded as erased at the
// wrong time, by the wrong admin, for the wrong reason, with no error anywhere.
//
// Serialization, bound format (self-describing):
//
//	[ "V42R" : 4 ][ 0x02 : 1 ][ len(wrappedKey) : 4 ][ wrappedKey ][ nonce || ciphertext ]
//
// Serialization, legacy format written before the binding existed:
//
//	[ len(wrappedKey) : 4 ][ wrappedKey ][ nonce || ciphertext ]
//
// The two are told apart by the magic and never by trial decryption. A legacy
// blob's first four bytes are a big-endian RSA-OAEP ciphertext length, which is
// the modulus size in bytes: 0x00000100 for RSA-2048, 0x00000200 for RSA-4096.
// The leading byte is 0x00 for every RSA key up to 4 194 304 bits, and 'V' is
// 0x56, so the two framings cannot be confused in either direction. In
// particular a bound blob cannot be downgraded by stripping its header: the
// remaining bytes read as a legacy blob whose declared wrapped-key length runs
// past the end of the buffer, which openRecovery refuses.

const recoveryAESKeySize = 32

const (
	// recoveryMagic marks the bound format. See the framing note above for why
	// it can never collide with a legacy blob's length prefix.
	recoveryMagic = "V42R"

	// recoveryVersionBound is the only bound version that exists. A blob
	// carrying the magic with any other version byte is refused outright rather
	// than treated as legacy, so a future format can never be silently read as
	// an older, weaker one.
	recoveryVersionBound = 0x02

	// recoveryHeaderLen covers the magic and the version byte. The wrapped-key
	// length prefix that follows is shared with the legacy framing, which is why
	// both formats hand the same tail to openRecovery.
	recoveryHeaderLen = len(recoveryMagic) + 1
)

const (
	// recoveryBindingDomain namespaces the binding so the bytes cannot be
	// mistaken for, or reused as, a context from any other subsystem.
	recoveryBindingDomain = "vault42/recovery/v2\x00"

	// The two layers get distinct contexts derived from the same binding.
	// Feeding one layer's context to the other is then a decrypt failure rather
	// than a silent success, which is what catches a future refactor that
	// crosses the wires.
	recoveryLabelTag = "oaep\x00"
	recoveryAADTag   = "gcm\x00"
)

// RecoveryFormat names which escrow serialization a stored blob uses. It exists
// so cmd/recover can report per record which format it read, and so that the
// legacy path is a decision the tool makes explicitly and logs, rather than a
// fallback it stumbles into after a failed decrypt.
type RecoveryFormat int

const (
	// RecoveryFormatUnknown is a blob that is neither framing: too short to
	// classify, or carrying the magic with an unrecognized version.
	RecoveryFormatUnknown RecoveryFormat = iota
	// RecoveryFormatBound is the current format, sealed to a row binding.
	RecoveryFormatBound
	// RecoveryFormatLegacy is the pre-binding format: nil OAEP label, no AAD,
	// and a payload that does not name its own subject.
	RecoveryFormatLegacy
)

func (f RecoveryFormat) String() string {
	switch f {
	case RecoveryFormatBound:
		return "bound"
	case RecoveryFormatLegacy:
		return "legacy"
	case RecoveryFormatUnknown:
		return "unknown"
	default:
		// A value outside the enum, which only a cast can produce. It reads the
		// same as Unknown here rather than panicking, because this String is
		// called from error paths that are already reporting something wrong.
		return "unknown"
	}
}

// RecoveryBlobFormat classifies a stored escrow blob by its framing alone. It
// never touches a key, so it is safe to call on hostile input before deciding
// what to do with it.
func RecoveryBlobFormat(blob []byte) RecoveryFormat {
	if len(blob) < 4 {
		return RecoveryFormatUnknown
	}
	if string(blob[:len(recoveryMagic)]) != recoveryMagic {
		return RecoveryFormatLegacy
	}
	if len(blob) < recoveryHeaderLen || blob[len(recoveryMagic)] != recoveryVersionBound {
		return RecoveryFormatUnknown
	}
	return RecoveryFormatBound
}

// RecoveryBinding builds the context bytes an escrow blob is sealed to, from the
// two columns of auth.account_recovery that identify the row: its primary key
// and the subject pseudonym.
//
// It must produce identical bytes on the write side (internal/service/erasure.go,
// which holds the values before they reach the database) and on the read side
// (cmd/recover, which reads them back out of the row). A divergence between the
// two does not misbehave subtly: every record stops decrypting, which is the
// whole recoverability of every erasure. That is why this lives here, called from
// both sides, rather than being spelled out twice.
//
// Two normalisations earn their keep:
//
//   - recordID is lowercased. It is written as a Go string and read back through
//     PostgreSQL's UUID type, which has its own canonical text output. A producer
//     that ever emitted uppercase hex would seal blobs no reader could open,
//     because PostgreSQL would hand the reader the lowercase form of the same
//     UUID. Case is not meaningful in a UUID, so folding it costs nothing and
//     removes the trap.
//   - The fields are NUL-separated and domain-prefixed. Plain concatenation would
//     let a record id ending in part of a pseudonym produce the same bytes as a
//     different (id, pseudonym) pair; neither value can contain a NUL, so the
//     encoding is unambiguous.
func RecoveryBinding(recordID, pseudonym string) []byte {
	return []byte(recoveryBindingDomain + strings.ToLower(recordID) + "\x00" + pseudonym)
}

func recoveryLabel(binding []byte) []byte {
	return append([]byte(recoveryLabelTag), binding...)
}

func recoveryAAD(binding []byte) []byte {
	return append([]byte(recoveryAADTag), binding...)
}

// EncryptRecovery encrypts plaintext for recovery escrow under the given RSA
// public key, sealed to binding. The returned blob can only be decrypted with
// the matching private key AND the same binding, via DecryptRecovery.
//
// binding is a required argument rather than a variadic option on purpose. The
// vulnerability this function was rewritten to fix was precisely an optional AAD
// that a call site did not pass, and an optional binding would leave that door
// open for the next caller. There is deliberately no way to write an unbound
// escrow record from this package any more.
func EncryptRecovery(pub *rsa.PublicKey, plaintext, binding []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("recovery: nil public key")
	}
	if len(binding) == 0 {
		return nil, errors.New("recovery: empty binding")
	}

	aesKey := make([]byte, recoveryAESKeySize)
	// crypto/rand.Read has no error path to handle: since Go 1.24 a Reader
	// failure calls the runtime fatal handler and terminates the process
	// instead of returning ($GOROOT/src/crypto/rand/rand.go). The recoverable
	// entropy failure for this function is the GCM nonce draw inside Encrypt,
	// which goes through io.ReadFull(rand.Reader, ...) and is handled below.
	_, _ = rand.Read(aesKey)

	aesBlob, err := Encrypt(plaintext, aesKey, recoveryAAD(binding))
	if err != nil {
		return nil, fmt.Errorf("recovery: aes encrypt: %w", err)
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, recoveryLabel(binding))
	if err != nil {
		return nil, fmt.Errorf("recovery: wrap aes key: %w", err)
	}

	// wrappedKey is an RSA-OAEP ciphertext, bounded by the key size in bytes; the
	// guard makes the uint32 length-prefix conversion provably safe.
	if len(wrappedKey) > math.MaxUint32 {
		return nil, errors.New("recovery: wrapped key too large")
	}
	out := make([]byte, recoveryHeaderLen+4+len(wrappedKey)+len(aesBlob))
	copy(out, recoveryMagic)
	out[len(recoveryMagic)] = recoveryVersionBound
	binary.BigEndian.PutUint32(out[recoveryHeaderLen:], uint32(len(wrappedKey))) // #nosec G115 -- bounded by the check above
	copy(out[recoveryHeaderLen+4:], wrappedKey)
	copy(out[recoveryHeaderLen+4+len(wrappedKey):], aesBlob)
	return out, nil
}

// DecryptRecovery is the inverse of EncryptRecovery. It is used by the offline
// recovery tool (cmd/recover), never by the running server, which holds no
// private key.
//
// It reads the bound format only. A legacy blob is refused here and must go
// through DecryptRecoveryLegacy, so the caller can never open one without
// knowing that is what it did.
func DecryptRecovery(priv *rsa.PrivateKey, blob, binding []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("recovery: nil private key")
	}
	if len(binding) == 0 {
		return nil, errors.New("recovery: empty binding")
	}
	if RecoveryBlobFormat(blob) != RecoveryFormatBound {
		return nil, errors.New("recovery: not a bound escrow blob")
	}
	return openRecovery(priv, blob[recoveryHeaderLen:], recoveryLabel(binding), recoveryAAD(binding))
}

// DecryptRecoveryLegacy reads an escrow record written before the payload was
// bound to its row: nil OAEP label, no AAD, and a profile that does not name its
// own subject.
//
// It exists for one reason. Escrow records already in auth.account_recovery are
// the only recoverable copy of the accounts they describe, and refusing to read
// them would destroy the recoverability of every erasure performed before the
// binding shipped - the exact opposite of what this subsystem is for.
//
// It is bounded on three sides, deliberately:
//
//   - The name. Every legacy read in the tree is one grep away, and there is one
//     caller (cmd/recover). There is no legacy WRITER anywhere in the product:
//     nothing can create a new unbound record.
//   - The clock. auth.account_recovery is swept by VAULT_RECOVERY_RETENTION_DAYS.
//     Once the last record written before the binding shipped has aged past that
//     horizon, this function and its call site can be deleted outright, and the
//     tests that pin the legacy framing go with them.
//   - The operator. cmd/recover --allow-legacy=false refuses these records, so a
//     deployment that believes it has no legacy rows left can prove it before
//     the code is removed.
//
// What it cannot do is verify anything. A legacy blob is not bound to its row,
// so a record read through this path carries no evidence that its deleted_at,
// deleted_by and reason belong to the profile inside it. Callers must say so.
func DecryptRecoveryLegacy(priv *rsa.PrivateKey, blob []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("recovery: nil private key")
	}
	if RecoveryBlobFormat(blob) != RecoveryFormatLegacy {
		return nil, errors.New("recovery: not a legacy escrow blob")
	}
	// The explicit nils are the legacy format: these records were sealed with a
	// nil OAEP label and no AAD, so nothing else can open them. Passing the
	// arguments rather than omitting them keeps this call visible to the AEAD
	// census in tests/attack, which is what stops an unbound call site from
	// reappearing unnoticed somewhere it is not wanted.
	return openRecovery(priv, blob, nil, nil)
}

// openRecovery is the shared tail of both formats: a big-endian wrapped-key
// length, the OAEP ciphertext, then the AES-GCM blob. label and aad are what
// separates a bound record from a legacy one; everything else about the two is
// identical, so the parsing and the bounds checks live in one place and cannot
// drift apart between the paths.
func openRecovery(priv *rsa.PrivateKey, body, label, aad []byte) ([]byte, error) {
	if len(body) < 4 {
		return nil, errors.New("recovery: blob too short")
	}

	wrappedLen := binary.BigEndian.Uint32(body[:4])
	// Compared in uint64 because the declared length is four bytes of
	// attacker-controlled big-endian: on a 32-bit build an int conversion could
	// wrap and turn a hostile length into a passing check.
	//
	// Written as an addition rather than as len(body)-4 so that neither side of
	// the comparison converts a value that could be negative. uint64(wrappedLen)
	// is at most 2^32-1 and adding 4 cannot overflow a uint64, and len is
	// non-negative by definition, so the safety is visible to a reader and to
	// gosec instead of resting on the bounds check three lines above.
	if uint64(wrappedLen)+4 > uint64(len(body)) {
		return nil, errors.New("recovery: corrupt blob (wrapped key length)")
	}
	wrappedKey := body[4 : 4+wrappedLen]
	aesBlob := body[4+wrappedLen:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrappedKey, label)
	if err != nil {
		return nil, fmt.Errorf("recovery: unwrap aes key: %w", err)
	}

	plaintext, err := Decrypt(aesBlob, aesKey, aad)
	if err != nil {
		return nil, fmt.Errorf("recovery: aes decrypt: %w", err)
	}
	return plaintext, nil
}

// LoadRSAPublicKeyPEM parses an RSA public key from PEM data. It accepts both
// PKIX ("BEGIN PUBLIC KEY") and PKCS#1 ("BEGIN RSA PUBLIC KEY") encodings.
func LoadRSAPublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("recovery: no PEM block found in public key")
	}

	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("recovery: public key is not RSA")
		}
		return key, nil
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("recovery: parse public key: %w", err)
	}
	return key, nil
}

// LoadRSAPrivateKeyPEM parses an RSA private key from PEM data. It accepts both
// PKCS#8 ("BEGIN PRIVATE KEY") and PKCS#1 ("BEGIN RSA PRIVATE KEY") encodings.
// Used by the offline recovery tool.
func LoadRSAPrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("recovery: no PEM block found in private key")
	}

	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("recovery: private key is not RSA")
		}
		return key, nil
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("recovery: parse private key: %w", err)
	}
	return key, nil
}
