package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func mustECPubDER(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal ec pkix: %v", err)
	}
	return der
}

func TestEncryptRecoveryRoundTrip(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte(`{"email":"user@example.com","roles":["user"]}`)

	blob, err := EncryptRecovery(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := DecryptRecovery(priv, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptRecoveryWrongKeyFails(t *testing.T) {
	priv1, _ := GenerateRSAKeyPair()
	priv2, _ := GenerateRSAKeyPair()

	blob, err := EncryptRecovery(&priv1.PublicKey, []byte("user@example.com"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptRecovery(priv2, blob); err == nil {
		t.Fatal("expected decryption with a different key to fail")
	}
}

func TestLoadRSAPublicAndPrivateKeyPEM(t *testing.T) {
	priv, _ := GenerateRSAKeyPair()

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustPKCS8(t, priv),
	})
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: mustPKIX(t, &priv.PublicKey),
	})

	loadedPub, err := LoadRSAPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("load public: %v", err)
	}
	loadedPriv, err := LoadRSAPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("load private: %v", err)
	}

	// End-to-end through the parsed keys.
	blob, err := EncryptRecovery(loadedPub, []byte("user@example.com"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := DecryptRecovery(loadedPriv, blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != "user@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadRSAKeyPEM_PKCS1Fallback(t *testing.T) {
	priv, _ := GenerateRSAKeyPair()

	// PKCS#1 encodings ("RSA PRIVATE KEY" / "RSA PUBLIC KEY") exercise the
	// fallback branch after the PKCS#8/PKIX parse fails.
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey)})

	gotPriv, err := LoadRSAPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("load PKCS1 private: %v", err)
	}
	if gotPriv.N.Cmp(priv.N) != 0 {
		t.Error("loaded PKCS1 private key does not match")
	}
	gotPub, err := LoadRSAPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("load PKCS1 public: %v", err)
	}
	if gotPub.N.Cmp(priv.N) != 0 {
		t.Error("loaded PKCS1 public key does not match")
	}
}

func TestLoadRSAKeyPEM_Errors(t *testing.T) {
	t.Run("no PEM block", func(t *testing.T) {
		if _, err := LoadRSAPublicKeyPEM([]byte("not pem")); err == nil {
			t.Error("LoadRSAPublicKeyPEM(garbage) = nil error")
		}
		if _, err := LoadRSAPrivateKeyPEM([]byte("not pem")); err == nil {
			t.Error("LoadRSAPrivateKeyPEM(garbage) = nil error")
		}
	})

	t.Run("malformed key bytes", func(t *testing.T) {
		bad := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")})
		if _, err := LoadRSAPublicKeyPEM(bad); err == nil {
			t.Error("LoadRSAPublicKeyPEM(bad DER) = nil error")
		}
		badPriv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")})
		if _, err := LoadRSAPrivateKeyPEM(badPriv); err == nil {
			t.Error("LoadRSAPrivateKeyPEM(bad DER) = nil error")
		}
	})

	t.Run("non-RSA key rejected", func(t *testing.T) {
		// An EC public key parses as PKIX but is not *rsa.PublicKey.
		ecDER := mustECPubDER(t)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})
		if _, err := LoadRSAPublicKeyPEM(pemBytes); err == nil {
			t.Error("LoadRSAPublicKeyPEM(EC key) = nil error, want non-RSA rejection")
		}
	})
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return b
}

func mustPKIX(t *testing.T, k *rsa.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return b
}
