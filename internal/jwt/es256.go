package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// VerifyES256 verifies an ES256 signature. Returns nil on success.
// Handles both raw R||S (64 bytes for P-256) and ASN.1 DER signature formats.
func VerifyES256(signingString string, sig []byte, key *ecdsa.PublicKey) error {
	if key == nil {
		return fmt.Errorf("%w: nil public key", ErrInvalidKeyType)
	}

	hash := sha256.Sum256([]byte(signingString))

	// Determine signature format
	derSig := sig
	if isRawRS(sig, key.Curve) {
		// Convert raw R||S to ASN.1 DER
		var err error
		derSig, err = rawRSToDER(sig)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrTokenSignatureInvalid, err)
		}
	}

	if !ecdsa.VerifyASN1(key, hash[:], derSig) {
		return ErrTokenSignatureInvalid
	}
	return nil
}

// isRawRS checks if the signature is in raw R||S format (64 bytes for P-256).
func isRawRS(sig []byte, curve elliptic.Curve) bool {
	byteLen := (curve.Params().BitSize + 7) / 8
	return len(sig) == 2*byteLen
}

// rawRSToDER converts a raw R||S signature (64 bytes) to ASN.1 DER format.
func rawRSToDER(sig []byte) ([]byte, error) {
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])

	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}
