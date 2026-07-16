package crypto

import (
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

// Entropy failure is the one failure mode every random-material generator
// shares, and none of these paths had a test. A generator that returned its
// zero value with a nil error would hand out an all-zero GCM nonce, token,
// UUID, or TOTP secret; each test pins that the error surfaces and the
// returned value is empty.

// errCryptoEntropy is what the scripted reader returns once its budget is
// spent.
var errCryptoEntropy = errors.New("entropy exhausted")

// cryptoScriptedReader stands in for crypto/rand.Reader: it serves whole
// reads until the budget is spent, then fails. While it is installed, only
// code paths whose crypto/rand.Read calls are fully covered by the budget may
// run: rand.Read is process-fatal on a failing Reader; only direct
// io.ReadFull(rand.Reader, ...) callers get the error back.
type cryptoScriptedReader struct {
	reads int
}

func (r *cryptoScriptedReader) Read(p []byte) (int, error) {
	if r.reads <= 0 {
		return 0, errCryptoEntropy
	}
	r.reads--
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

// cryptoSwapRandReader installs r as crypto/rand.Reader and restores the
// original when the test ends. internal/crypto has no parallel tests, so the
// global swap cannot race.
func cryptoSwapRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	old := rand.Reader
	rand.Reader = r
	t.Cleanup(func() { rand.Reader = old })
}

// A zero nonce with a nil error would be catastrophic for GCM: every call
// would reuse the same nonce under the same key.
func TestEncrypt_NonceEntropyFailure(t *testing.T) {
	cryptoSwapRandReader(t, &cryptoScriptedReader{reads: 0})

	ct, err := Encrypt([]byte("plaintext"), make([]byte, 32))
	if err == nil {
		t.Fatal("expected an error when nonce generation fails")
	}
	if !strings.Contains(err.Error(), "generate nonce") {
		t.Errorf("error = %v, want generate nonce", err)
	}
	if ct != nil {
		t.Error("ciphertext returned despite a nonce generation failure")
	}
}

func TestRandomBytes_EntropyFailure(t *testing.T) {
	cryptoSwapRandReader(t, &cryptoScriptedReader{reads: 0})

	b, err := RandomBytes(32)
	if !errors.Is(err, errCryptoEntropy) {
		t.Fatalf("error = %v, want the wrapped entropy failure", err)
	}
	if !strings.Contains(err.Error(), "crypto/rand:") {
		t.Errorf("error = %v, want crypto/rand: prefix", err)
	}
	if b != nil {
		t.Error("bytes returned despite an entropy failure")
	}
}

// RandomHex feeds tokens and client secrets; an empty string with a nil error
// would be stored as a credential.
func TestRandomHex_EntropyFailure(t *testing.T) {
	cryptoSwapRandReader(t, &cryptoScriptedReader{reads: 0})

	s, err := RandomHex(16)
	if err == nil {
		t.Fatal("expected an error when entropy fails")
	}
	if s != "" {
		t.Errorf("hex = %q, want empty on entropy failure", s)
	}
}

func TestRandomUUID_EntropyFailure(t *testing.T) {
	cryptoSwapRandReader(t, &cryptoScriptedReader{reads: 0})

	s, err := RandomUUID()
	if err == nil {
		t.Fatal("expected an error when entropy fails")
	}
	if s != "" {
		t.Errorf("uuid = %q, want empty on entropy failure", s)
	}
}

// An all-zero TOTP secret enrolled with a nil error would be guessable by
// anyone.
func TestGenerateTOTPSecret_EntropyFailure(t *testing.T) {
	cryptoSwapRandReader(t, &cryptoScriptedReader{reads: 0})

	s, err := GenerateTOTPSecret()
	if err == nil {
		t.Fatal("expected an error when entropy fails")
	}
	if s != "" {
		t.Errorf("secret = %q, want empty on entropy failure", s)
	}
}

// EncryptRecovery draws the AES key via rand.Read (the one budgeted read),
// then Encrypt draws the GCM nonce, which is where the failure lands. No
// escrow blob may be produced from a broken entropy source.
func TestEncryptRecovery_NonceEntropyFailure(t *testing.T) {
	priv, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cryptoSwapRandReader(t, &cryptoScriptedReader{reads: 1})

	blob, err := EncryptRecovery(&priv.PublicKey, []byte("erased account payload"))
	if err == nil {
		t.Fatal("expected an error when nonce generation fails")
	}
	if !strings.Contains(err.Error(), "recovery: aes encrypt") {
		t.Errorf("error = %v, want recovery: aes encrypt", err)
	}
	if blob != nil {
		t.Error("blob returned despite an entropy failure")
	}
}
