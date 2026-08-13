package attack

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// The recovery escrow is the one place in vault42 where a deleted user's email
// survives the deletion. It is written by the server with a public key and read
// only by cmd/recover with the offline private key, so the confidentiality
// design is sound. These tests go after the parts that are not confidentiality:
// integrity, failing closed, and what the error strings say.

// escrowKey is generated once per run. 2048 bits keeps the suite fast; the
// findings do not depend on the modulus size.
var escrowKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// recoveryPayload mirrors the struct internal/service/erasure.go marshals into
// the escrow. Copied rather than imported because the real one is unexported.
// The two fields at the top are the ones this file exists for: before the fix
// the payload was Email, CreatedAt, Roles and DisplayName and nothing else, so a
// decrypted record could not say who it was about.
type recoveryPayload struct {
	Version     int       `json:"v"`
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	Roles       []string  `json:"roles"`
	DisplayName string    `json:"display_name"`
}

// Two escrow rows, standing in for two erasures. The values only have to be
// distinct and shaped like the columns; the real ones are a v4 UUID and an
// HMAC-SHA256 hex digest.
const (
	rowAlice = "6b1f5a2c-9e37-4a1d-8f02-11bb22cc33dd"
	rowBob   = "6b1f5a2c-9e37-4a1d-8f02-44ee55ff6600"
	pseAlice = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	pseBob   = "0f9e8d7c6b5a49382716051423324150607f8e9dacbbcadb0e1f2a3b4c5d6e7f"
)

// FINDING, now fixed: the escrow blob was bound to nothing.
//
// internal/crypto/recovery.go:49 used to be the only AES-GCM call in the product
// that passed no AAD:
//
//	aesBlob, err := Encrypt(plaintext, aesKey)
//
// Every other call site bound its ciphertext to something that identifies the
// row it lives in: the keystore binds the kid, the identity store binds the
// pseudonym, service documents bind client, subject and key, the admin TOTP
// secret binds the admin id. The escrow bound nothing, the RSA-OAEP wrap used a
// nil label, and the marshalled payload carried no user id either.
//
// auth.account_recovery stores deleted_at, deleted_by and reason as ordinary
// columns beside the ciphertext, and cmd/recover joins the decrypted payload to
// those columns to produce each output record. With nothing tying the two halves
// together, anyone who could write the table could move a payload from one row
// to another and the recovery tool would report the move as fact.
//
// The test used to demonstrate that swap and fail while it succeeded. It now
// runs the same swap and demands that it fails: the payload is sealed to the
// (record id, pseudonym) of its own row on both crypto layers, so a moved
// payload does not survive the RSA-OAEP unwrap and no AES key is ever derived
// from it.
func TestRecoveryAttack_EscrowPayloadIsNotBoundToItsRow(t *testing.T) {
	marshal := func(userID, email, display string) []byte {
		b, err := json.Marshal(recoveryPayload{
			Version:     2,
			UserID:      userID,
			Email:       email,
			CreatedAt:   time.Unix(1700000000, 0).UTC(),
			Roles:       []string{"user"},
			DisplayName: display,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	aliceBinding := vaultcrypto.RecoveryBinding(rowAlice, pseAlice)
	bobBinding := vaultcrypto.RecoveryBinding(rowBob, pseBob)

	// Two erasures, escrowed the way the service does it.
	alice, err := vaultcrypto.EncryptRecovery(&escrowKey.PublicKey, marshal("user-alice", "alice@example.com", "Alice"), aliceBinding)
	if err != nil {
		t.Fatalf("EncryptRecovery(alice): %v", err)
	}
	bob, err := vaultcrypto.EncryptRecovery(&escrowKey.PublicKey, marshal("user-bob", "bob@example.com", "Bob"), bobBinding)
	if err != nil {
		t.Fatalf("EncryptRecovery(bob): %v", err)
	}

	// Baseline. Each record opens under its own row, or the swap below would
	// "fail" for a reason that has nothing to do with the binding.
	for name, own := range map[string]struct {
		blob    []byte
		binding []byte
	}{"alice": {alice, aliceBinding}, "bob": {bob, bobBinding}} {
		if _, err := vaultcrypto.DecryptRecovery(escrowKey, own.blob, own.binding); err != nil {
			t.Fatalf("%s's record does not open under its own row: %v", name, err)
		}
	}

	// The attack: swap the two payload columns. Every other column, including
	// deleted_at, deleted_by and reason, stays where it was.
	swaps := map[string]struct {
		blob    []byte
		binding []byte
	}{
		"alice's row now holds bob's payload": {bob, aliceBinding},
		"bob's row now holds alice's payload": {alice, bobBinding},
	}
	for name, swap := range swaps {
		plain, err := vaultcrypto.DecryptRecovery(escrowKey, swap.blob, swap.binding)
		if err == nil {
			var got recoveryPayload
			_ = json.Unmarshal(plain, &got) // #nosec G104 -- the failure is already reported below
			t.Errorf("%s and decrypts cleanly as %q: the payload is still movable between "+
				"escrow rows, so cmd/recover will attribute it to the wrong "+
				"deleted_at/deleted_by/reason with no error", name, got.Email)
		}
		if len(plain) != 0 {
			t.Errorf("%s: a refused swap returned %d bytes of plaintext", name, len(plain))
		}
	}

	// The payload also has to name its own subject. The binding stops a swap; the
	// user id is what lets a recovered record be restored at all, since the row
	// identifies its subject only by an HMAC pseudonym the offline tool cannot
	// invert.
	var probe map[string]any
	plain, err := vaultcrypto.DecryptRecovery(escrowKey, alice, aliceBinding)
	if err != nil {
		t.Fatalf("DecryptRecovery: %v", err)
	}
	if err := json.Unmarshal(plain, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := probe["user_id"]; !ok {
		t.Errorf("the escrow payload carries only %v: no subject identifier, so a decrypted "+
			"record cannot be cross-checked against the row it came from or restored to the "+
			"account it describes", keysOf(probe))
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Failing closed. A wrong key, a corrupted blob or a truncated blob must yield
// no plaintext at all, not a prefix of one, and must not panic the offline tool
// on a row an attacker planted.
func TestRecoveryAttack_WrongKeyAndCorruptionFailClosed(t *testing.T) {
	secret := []byte(`{"v":2,"user_id":"user-victim","email":"victim@example.com","display_name":"Victim","roles":["user"]}`)
	binding := vaultcrypto.RecoveryBinding(rowAlice, pseAlice)
	blob, err := vaultcrypto.EncryptRecovery(&escrowKey.PublicKey, secret, binding)
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	t.Run("wrong private key", func(t *testing.T) {
		plain, err := vaultcrypto.DecryptRecovery(other, blob, binding)
		if err == nil {
			t.Fatalf("a foreign key decrypted the escrow: %q", plain)
		}
		if len(plain) != 0 {
			t.Errorf("failed decrypt still returned %d bytes", len(plain))
		}
		assertNoLeak(t, err.Error(), secret)
	})

	t.Run("nil private key", func(t *testing.T) {
		if _, err := vaultcrypto.DecryptRecovery(nil, blob, binding); err == nil {
			t.Error("a nil key was accepted")
		}
	})

	// Truncation at every offset. The length prefix is four bytes of
	// attacker-controlled big-endian, so the slice arithmetic downstream is
	// the thing under test as much as the crypto.
	t.Run("truncation at every offset", func(t *testing.T) {
		for i := 0; i < len(blob); i++ { // len(blob) itself is the intact blob
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("truncating to %d bytes panicked the recovery tool: %v", i, r)
					}
				}()
				plain, err := vaultcrypto.DecryptRecovery(escrowKey, blob[:i], binding)
				if err == nil {
					t.Errorf("a blob truncated to %d bytes decrypted: %q", i, plain)
				}
				if len(plain) != 0 {
					t.Errorf("truncation to %d returned %d bytes of plaintext", i, len(plain))
				}
			}()
		}
	})

	// Extension. Trailing bytes land inside the AES-GCM region and must fail
	// tag verification rather than being ignored.
	t.Run("length extension", func(t *testing.T) {
		for _, extra := range [][]byte{{0}, {0xFF}, make([]byte, 64), make([]byte, 4096)} {
			extended := append(append([]byte(nil), blob...), extra...)
			if plain, err := vaultcrypto.DecryptRecovery(escrowKey, extended, binding); err == nil {
				t.Errorf("appending %d bytes still decrypted: %q", len(extra), plain)
			}
		}
	})

	// Every byte flipped, one at a time.
	t.Run("single byte corruption", func(t *testing.T) {
		for i := range blob {
			corrupt := append([]byte(nil), blob...)
			corrupt[i] ^= 0xFF
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("corrupting byte %d panicked: %v", i, r)
					}
				}()
				if plain, err := vaultcrypto.DecryptRecovery(escrowKey, corrupt, binding); err == nil {
					t.Errorf("corrupting byte %d still decrypted: %q", i, plain)
				}
			}()
		}
	})

	// The declared wrapped-key length drives the split between the OAEP
	// ciphertext and the AES blob. Hostile values must be refused by the guard in
	// openRecovery, not by a runtime bounds panic in the offline tool. In the
	// bound framing the prefix sits after the 4-byte magic and the version byte.
	t.Run("hostile wrapped-key length prefix", func(t *testing.T) {
		const lenPrefixOffset = 5
		for _, declared := range []uint32{
			0, 1, 255,
			uint32(len(blob)) - 4, // exactly the remainder: leaves an empty AES blob
			uint32(len(blob)) - 3, // one past
			uint32(len(blob)),
			0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
		} {
			forged := append([]byte(nil), blob...)
			binary.BigEndian.PutUint32(forged[lenPrefixOffset:], declared)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("declared length %d panicked the recovery tool: %v", declared, r)
					}
				}()
				if plain, err := vaultcrypto.DecryptRecovery(escrowKey, forged, binding); err == nil {
					t.Errorf("declared length %d produced plaintext: %q", declared, plain)
				}
			}()
		}
	})

	// A blob shorter than the length prefix itself.
	t.Run("runt blobs", func(t *testing.T) {
		for _, b := range [][]byte{nil, {}, {0}, {0, 0}, {0, 0, 0}, {0, 0, 0, 0}} {
			if plain, err := vaultcrypto.DecryptRecovery(escrowKey, b, binding); err == nil {
				t.Errorf("a %d-byte blob decrypted: %q", len(b), plain)
			}
		}
	})
}

// The error strings cmd/recover prints to stderr. They are written by an
// operator-facing tool on a trusted host, but a support transcript is a common
// way for such output to escape, so they must not carry key material or
// plaintext.
func TestRecoveryAttack_ErrorsCarryNoKeyMaterialOrPlaintext(t *testing.T) {
	secret := []byte(`{"v":2,"user_id":"user-canary","email":"leak-canary@example.com"}`)
	binding := vaultcrypto.RecoveryBinding(rowAlice, pseAlice)
	blob, err := vaultcrypto.EncryptRecovery(&escrowKey.PublicKey, secret, binding)
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	corrupt := append([]byte(nil), blob...)
	corrupt[len(corrupt)-1] ^= 0xFF

	badLength := append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(badLength[5:], 0xFFFFFFFF)

	cases := map[string][]byte{
		"corrupt tag":   corrupt,
		"truncated":     blob[:len(blob)/2],
		"runt":          {0, 0, 0, 0, 1},
		"empty":         {},
		"bad length":    badLength,
		"foreign wrap":  blob,
		"foreign row":   blob,
		"legacy framed": blob[5:],
	}

	for name, b := range cases {
		key := escrowKey
		bind := binding
		switch name {
		case "foreign wrap":
			key = other
		case "foreign row":
			bind = vaultcrypto.RecoveryBinding(rowBob, pseBob)
		}
		_, err := vaultcrypto.DecryptRecovery(key, b, bind)
		if err == nil {
			continue
		}
		msg := err.Error()
		t.Logf("%-12s -> %s", name, msg)
		assertNoLeak(t, msg, secret)

		// The private key's secret components must never appear either.
		for _, limb := range []string{
			escrowKey.D.String(),
			escrowKey.Primes[0].String(),
			escrowKey.Primes[1].String(),
		} {
			if strings.Contains(msg, limb) {
				t.Errorf("%s: error message contains RSA private key material", name)
			}
		}
	}
}

// assertNoLeak fails if msg quotes any recognisable run of the plaintext.
func assertNoLeak(t *testing.T, msg string, secret []byte) {
	t.Helper()
	if strings.Contains(msg, string(secret)) {
		t.Errorf("error message contains the plaintext: %s", msg)
	}
	// Substrings long enough to be meaningful, not so short they false-positive.
	for _, needle := range []string{"leak-canary", "victim@example.com", "@example.com"} {
		if strings.Contains(msg, needle) {
			t.Errorf("error message leaks plaintext fragment %q: %s", needle, msg)
		}
	}
}

// A fresh AES key per record means two escrows of identical content produce
// unrelated ciphertexts, so the table does not reveal which deleted users
// shared an attribute. Checked because the AES key is drawn with rand.Read
// whose error is deliberately discarded (recovery.go:47), and a silently
// constant key would show up exactly here.
func TestRecoveryAttack_IdenticalPayloadsDoNotProduceIdenticalBlobs(t *testing.T) {
	payload := []byte(`{"v":2,"user_id":"user-same","email":"same@example.com","display_name":"Same"}`)
	// Same payload AND the same binding, which is the harder case: a scheme that
	// derived the AES key from the binding rather than from entropy would
	// produce identical blobs here and identical ones only here.
	binding := vaultcrypto.RecoveryBinding(rowAlice, pseAlice)

	seen := map[string]bool{}
	const runs = 16
	for i := 0; i < runs; i++ {
		blob, err := vaultcrypto.EncryptRecovery(&escrowKey.PublicKey, payload, binding)
		if err != nil {
			t.Fatalf("EncryptRecovery: %v", err)
		}
		// The AES-GCM region starts after the framing header and the wrapped key.
		const lenPrefixOffset = 5
		wrappedLen := binary.BigEndian.Uint32(blob[lenPrefixOffset:])
		aesRegion := string(blob[lenPrefixOffset+4+wrappedLen:])
		if seen[aesRegion] {
			t.Fatal("two escrows of the same payload produced the same AES-GCM region: " +
				"the per-record key or the nonce is not random")
		}
		seen[aesRegion] = true
	}
	t.Logf("%d escrows of identical content produced %d distinct ciphertexts", runs, len(seen))
}

// PEM loading, reached by cmd/recover with an operator-supplied --key path. A
// malformed file must produce an error, never a panic, and never a partially
// initialised key that would later be used to decrypt.
func TestRecoveryAttack_MalformedPEMIsRejected(t *testing.T) {
	inputs := map[string]string{
		"empty":              "",
		"not pem":            "this is not a key",
		"empty pem block":    "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
		"garbage body":       "-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----\n",
		"public key as priv": "-----BEGIN PUBLIC KEY-----\nQUJDRA==\n-----END PUBLIC KEY-----\n",
		"truncated header":   "-----BEGIN PRIVATE KEY-----\n",
	}

	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", name, r)
				}
			}()
			if key, err := vaultcrypto.LoadRSAPrivateKeyPEM([]byte(in)); err == nil {
				t.Errorf("accepted a malformed private key: %v", key)
			}
			if key, err := vaultcrypto.LoadRSAPublicKeyPEM([]byte(in)); err == nil {
				t.Errorf("accepted a malformed public key: %v", key)
			}
		})
	}
}
