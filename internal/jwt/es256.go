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
//
// RFC 7515 §3.4 mandates the raw R‖S form for JWS, and that is what vault42
// emits. This function additionally accepts ASN.1 DER because the ES256 tokens
// it must verify include DPoP proofs and third-party OIDC ID tokens produced by
// libraries and HSMs that hand back the DER form their signing API returns.
// Rejecting those would fail interoperability, not close an attack.
//
// The discriminator is length alone: [isRawRS] treats a signature of exactly
// twice the curve's coordinate size as raw. A DER signature that happens to be
// 64 bytes is therefore misclassified, reinterpreted as R‖S, and fails
// verification. That direction is safe, because the only path out of this
// function is ecdsa.VerifyASN1 over a signature the caller must have produced
// with the private key: a misclassified signature is rejected, never accepted.
//
// The curve is pinned to P-256 because RFC 7518 §3.4 assigns exactly that curve
// to the ES256 identifier. Without the pin the expected raw signature length is
// derived from whatever curve the caller's key sits on, so a P-384 key verifies
// a 96-byte signature under a header that still says ES256. The ES256 path is
// reached from DPoP, where the proof carries its own key in the jwk header and
// the binding to the access token is the RFC 7638 thumbprint of that key; the
// thumbprint covers the curve name, so accepting a curve the algorithm did not
// name puts vault42 and every conforming relying party into disagreement about
// which proofs are valid.
func VerifyES256(signingString string, sig []byte, key *ecdsa.PublicKey) error {
	if key == nil {
		return fmt.Errorf("%w: nil public key", ErrInvalidKeyType)
	}
	// A nil Curve compares unequal here rather than being dereferenced.
	if key.Curve != elliptic.P256() {
		return fmt.Errorf("%w: ES256 requires a P-256 key", ErrInvalidKeyType)
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
