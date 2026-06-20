package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

const (
	// DPoPMaxAge is the maximum age of a DPoP proof (5 minutes).
	DPoPMaxAge = 5 * time.Minute
	// DPoPMaxSize is the maximum DPoP proof size in bytes.
	DPoPMaxSize = 4 * 1024
)

// DPoPClaims represents claims in a DPoP proof JWT (RFC 9449).
type DPoPClaims struct {
	vjwt.RegisteredClaims
	HTM string `json:"htm"`           // HTTP method
	HTU string `json:"htu"`           // HTTP URI
	ATH string `json:"ath,omitempty"` // access token hash (for resource requests)
}

// ValidateDPoPProof validates a DPoP proof JWT per RFC 9449.
// Returns the JWK thumbprint of the proof's public key and the JTI claim for replay prevention.
func ValidateDPoPProof(proofString, httpMethod, httpURI string, accessTokenHash string) (string, string, error) {
	if len(proofString) > DPoPMaxSize {
		return "", "", errors.New("dpop: proof exceeds maximum size")
	}

	// Parse without validation first to extract the public key from header
	unverified, err := vjwt.ParseUnverified(proofString, &DPoPClaims{})
	if err != nil {
		return "", "", fmt.Errorf("dpop: parse: %w", err)
	}

	// Must be typ: dpop+jwt
	typ, _ := unverified.Header["typ"].(string)
	if typ != "dpop+jwt" {
		return "", "", errors.New("dpop: invalid typ header")
	}

	// Must NOT have kid header (DPoP proofs carry the key in jwk header)
	if _, hasKid := unverified.Header["kid"]; hasKid {
		return "", "", errors.New("dpop: kid header not allowed in DPoP proof")
	}

	// Extract public key from jwk header
	jwkRaw, ok := unverified.Header["jwk"]
	if !ok {
		return "", "", errors.New("dpop: missing jwk header")
	}

	pubKey, err := parseJWKHeader(jwkRaw)
	if err != nil {
		return "", "", fmt.Errorf("dpop: %w", err)
	}

	// Now verify the signature with the extracted public key
	claims := &DPoPClaims{}
	_, err = vjwt.ParseWithClaims(proofString, claims, func(t *vjwt.Token) (any, error) {
		return pubKey, nil
	}, vjwt.WithValidMethods([]string{"RS256", "ES256"}))
	if err != nil {
		return "", "", fmt.Errorf("dpop: verify: %w", err)
	}

	// Validate htm (HTTP method)
	if claims.HTM != httpMethod {
		return "", "", fmt.Errorf("dpop: htm mismatch: got %q, want %q", claims.HTM, httpMethod)
	}

	// Validate htu (HTTP URI)
	if claims.HTU != httpURI {
		return "", "", fmt.Errorf("dpop: htu mismatch: got %q, want %q", claims.HTU, httpURI)
	}

	// Validate age
	if claims.IssuedAt == nil {
		return "", "", errors.New("dpop: missing iat claim")
	}
	age := time.Since(claims.IssuedAt.Time)
	if age > DPoPMaxAge || age < -DPoPMaxAge {
		return "", "", errors.New("dpop: proof too old or too far in future")
	}

	// Validate jti presence
	if claims.ID == "" {
		return "", "", errors.New("dpop: missing jti claim")
	}

	// Validate ath (access token hash) if provided — constant-time to prevent timing leaks
	if accessTokenHash != "" && !SecureCompare(claims.ATH, accessTokenHash) {
		return "", "", errors.New("dpop: ath mismatch")
	}

	// Compute JWK thumbprint (RFC 7638)
	thumbprint, err := ComputeJWKThumbprint(pubKey)
	if err != nil {
		return "", "", fmt.Errorf("dpop: thumbprint: %w", err)
	}

	return thumbprint, claims.ID, nil
}

// ComputeJWKThumbprint computes the RFC 7638 JWK Thumbprint of a public key.
func ComputeJWKThumbprint(key crypto.PublicKey) (string, error) {
	var thumbprintInput string

	switch k := key.(type) {
	case *rsa.PublicKey:
		n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(encodeRSAExponent(k.E))
		// RFC 7638: members sorted lexicographically
		thumbprintInput = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)
	case *ecdsa.PublicKey:
		crv := k.Curve.Params().Name
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		// Use ecdh bridge to get SEC1 uncompressed bytes (0x04 || X || Y, each padded to byteLen).
		ecdhPub, err := k.ECDH()
		if err != nil {
			return "", fmt.Errorf("ecdsa→ecdh: %w", err)
		}
		raw := ecdhPub.Bytes()
		if len(raw) != 1+2*byteLen || raw[0] != 0x04 {
			return "", fmt.Errorf("unexpected ecdh pub length %d", len(raw))
		}
		x := base64.RawURLEncoding.EncodeToString(raw[1 : 1+byteLen])
		y := base64.RawURLEncoding.EncodeToString(raw[1+byteLen:])
		thumbprintInput = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, crv, x, y)
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}

	hash := sha256.Sum256([]byte(thumbprintInput))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// parseJWKHeader extracts a public key from a JWK header value.
func parseJWKHeader(jwkRaw interface{}) (crypto.PublicKey, error) {
	jwkMap, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid jwk header format")
	}

	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("marshal jwk: %w", err)
	}

	var jwk struct {
		KTY string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		CRV string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("unmarshal jwk: %w", err)
	}

	switch jwk.KTY {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("decode n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("decode e: %w", err)
		}
		n := new(big.Int).SetBytes(nBytes)
		if n.BitLen() < 2048 {
			return nil, errors.New("RSA key too small: minimum 2048 bits required")
		}
		// Upper bound: a self-signed DPoP proof carries an attacker-chosen
		// modulus; cap it to avoid an algorithmic-complexity DoS on verify (L2).
		if n.BitLen() > 4096 {
			return nil, errors.New("RSA key too large: maximum 4096 bits allowed")
		}
		eBig := new(big.Int).SetBytes(eBytes)
		if !eBig.IsInt64() || eBig.Int64() < 3 || eBig.Int64() > 1<<31-1 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{
			N: n,
			E: int(eBig.Int64()),
		}, nil
	case "EC":
		var curve elliptic.Curve
		switch jwk.CRV {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported curve: %s", jwk.CRV)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("decode x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("decode y: %w", err)
		}
		key := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		if _, err := key.ECDH(); err != nil {
			return nil, errors.New("EC point not on curve")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
}
