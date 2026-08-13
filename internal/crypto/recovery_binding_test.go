package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

// The escrow blob used to be bound to nothing. A payload could be lifted out of
// one auth.account_recovery row and dropped into another, and cmd/recover would
// decrypt it and print it beside the second row's deleted_at, deleted_by and
// reason without a murmur: the wrong person, recorded as erased at the wrong
// time by the wrong admin for the wrong reason, in the one document an
// investigator would treat as authoritative.
//
// These tests hold the binding down at the primitive level. The row-level and
// tool-level versions live in tests/attack and cmd/recover; this file is about
// the two things only this package can guarantee - that the binding reaches both
// crypto layers, and that the legacy framing stays readable for exactly as long
// as it needs to.

// bindingKey is generated once. 2048 bits keeps the file fast and none of the
// findings depend on the modulus size.
var bindingKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

const (
	rowA = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	rowB = "3f2504e0-4f89-41d3-9a0c-0305e82c3302"
	pseA = "7b1f0c2e9d4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4"
	pseB = "0e1d2c3b4a5968778695a4b3c2d1e0f9887766554433221100ffeeddccbbaa99"
)

// The property the whole change exists for: a blob only opens under the binding
// it was sealed to. Every axis is exercised separately because they fail for
// different reasons and a fix that covered only one would look identical from
// outside.
func TestRecoveryBinding_BlobOnlyOpensUnderItsOwnBinding(t *testing.T) {
	secret := []byte(`{"v":2,"user_id":"user-a","email":"alice@example.invalid"}`)
	sealed, err := EncryptRecovery(&bindingKey.PublicKey, secret, RecoveryBinding(rowA, pseA))
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}

	got, err := DecryptRecovery(bindingKey, sealed, RecoveryBinding(rowA, pseA))
	if err != nil {
		t.Fatalf("the blob does not open under its own binding, so nothing below is meaningful: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip returned %q, want %q", got, secret)
	}

	wrong := map[string][]byte{
		"another row, same subject":    RecoveryBinding(rowB, pseA),
		"same row id, another subject": RecoveryBinding(rowA, pseB),
		"another row entirely":         RecoveryBinding(rowB, pseB),
		"no record id":                 RecoveryBinding("", pseA),
		"no pseudonym":                 RecoveryBinding(rowA, ""),
		"raw binding, undomained":      []byte(rowA + "\x00" + pseA),
	}
	for name, binding := range wrong {
		plain, err := DecryptRecovery(bindingKey, sealed, binding)
		if err == nil {
			t.Errorf("%s: the payload opened under a foreign binding, so it can still be "+
				"moved between escrow rows: %q", name, plain)
		}
		if len(plain) != 0 {
			t.Errorf("%s: a failed decrypt returned %d bytes of plaintext", name, len(plain))
		}
	}
}

// The binding has to reach BOTH layers. Binding only the AES-GCM AAD would leave
// the RSA-OAEP wrap swappable, and binding only the label would leave the
// ciphertext swappable under a correctly-wrapped key. This test opens the
// envelope by hand and checks each layer separately, because from the outside a
// half-fix and a whole fix are indistinguishable.
func TestRecoveryBinding_ReachesBothCryptoLayers(t *testing.T) {
	binding := RecoveryBinding(rowA, pseA)
	sealed, err := EncryptRecovery(&bindingKey.PublicKey, []byte("erased account payload"), binding)
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}

	wrappedLen := binary.BigEndian.Uint32(sealed[recoveryHeaderLen:])
	wrapped := sealed[recoveryHeaderLen+4 : recoveryHeaderLen+4+int(wrappedLen)]
	aesBlob := sealed[recoveryHeaderLen+4+int(wrappedLen):]

	t.Run("OAEP label", func(t *testing.T) {
		if _, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, bindingKey, wrapped, nil); err == nil {
			t.Error("the wrapped AES key unwraps with a nil label: the RSA layer is unbound, " +
				"so an attacker who swaps a payload still gets a usable key")
		}
		if _, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, bindingKey, wrapped, recoveryLabel(RecoveryBinding(rowB, pseB))); err == nil {
			t.Error("the wrapped AES key unwraps under another row's label")
		}
		if _, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, bindingKey, wrapped, recoveryLabel(binding)); err != nil {
			t.Errorf("the wrapped AES key does not unwrap under its own label: %v", err)
		}
	})

	t.Run("GCM AAD", func(t *testing.T) {
		aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, bindingKey, wrapped, recoveryLabel(binding))
		if err != nil {
			t.Fatalf("unwrap: %v", err)
		}
		if _, err := Decrypt(aesBlob, aesKey, nil); err == nil {
			t.Error("the AES-GCM layer opens with no AAD: internal/crypto/recovery.go is back to " +
				"being the one AEAD call site in the product that binds no context")
		}
		if _, err := Decrypt(aesBlob, aesKey, recoveryAAD(RecoveryBinding(rowB, pseB))); err == nil {
			t.Error("the AES-GCM layer opens under another row's AAD")
		}
		if _, err := Decrypt(aesBlob, aesKey, recoveryAAD(binding)); err != nil {
			t.Errorf("the AES-GCM layer does not open under its own AAD: %v", err)
		}
	})

	// The two layers get different context bytes derived from the same binding.
	// If a refactor ever crossed the wires, this is where it shows up as a
	// failure rather than as a silent success.
	if bytes.Equal(recoveryLabel(binding), recoveryAAD(binding)) {
		t.Error("the OAEP label and the GCM AAD are the same bytes: the two layers are not domain-separated")
	}
}

// An empty binding is refused rather than treated as "no binding". Accepting it
// would restore the original vulnerability through the front door, since a
// caller that has not yet worked out what to bind to would get an unbound record
// and no error.
func TestRecoveryBinding_EmptyBindingIsRefused(t *testing.T) {
	for _, binding := range [][]byte{nil, {}} {
		if _, err := EncryptRecovery(&bindingKey.PublicKey, []byte("payload"), binding); err == nil {
			t.Error("EncryptRecovery accepted an empty binding, so an unbound escrow record can be written again")
		}
	}

	sealed, err := EncryptRecovery(&bindingKey.PublicKey, []byte("payload"), RecoveryBinding(rowA, pseA))
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}
	for _, binding := range [][]byte{nil, {}} {
		if _, err := DecryptRecovery(bindingKey, sealed, binding); err == nil {
			t.Error("DecryptRecovery accepted an empty binding")
		}
	}
}

// RecoveryBinding is an encoding, and an encoding that is not injective is a
// binding an attacker can shift. Concatenating the two fields without a
// separator would let a record id that ends in the head of a pseudonym produce
// the same bytes as a different (id, pseudonym) pair, which would put two rows
// back into the same equivalence class.
func TestRecoveryBinding_IsUnambiguous(t *testing.T) {
	seen := map[string][2]string{}
	pairs := [][2]string{
		{"a", "bc"},
		{"ab", "c"},
		{"abc", ""},
		{"", "abc"},
		{"a", "b"},
		{"ab", ""},
		{rowA, pseA},
		{rowB, pseA},
		{rowA, pseB},
	}
	for _, pair := range pairs {
		key := string(RecoveryBinding(pair[0], pair[1]))
		if prev, ok := seen[key]; ok {
			t.Errorf("(%q,%q) and (%q,%q) produce the same binding: the field boundary can be shifted",
				prev[0], prev[1], pair[0], pair[1])
		}
		seen[key] = pair
	}

	// The domain prefix keeps these bytes out of every other subsystem's context
	// namespace, so a value from elsewhere cannot be replayed as an escrow
	// binding.
	if !strings.HasPrefix(string(RecoveryBinding(rowA, pseA)), "vault42/recovery/") {
		t.Error("the binding is not namespaced to this subsystem")
	}
}

// A UUID is case-insensitive, but the write side holds it as a Go string and the
// read side gets it back through PostgreSQL's UUID type, which emits lowercase.
// A producer that ever wrote uppercase would seal records the recovery tool could
// never open, and the failure would surface as "every erasure since <date> is
// unrecoverable" rather than as a bug report. Folding case here removes the
// trap; the pseudonym is TEXT and round-trips exactly, so it is left alone.
func TestRecoveryBinding_RecordIDCaseDoesNotSplitTheBinding(t *testing.T) {
	upper := strings.ToUpper(rowA)
	if upper == rowA {
		t.Fatal("the fixture has no letters to change case, so this test proves nothing")
	}
	if !bytes.Equal(RecoveryBinding(upper, pseA), RecoveryBinding(rowA, pseA)) {
		t.Error("the same UUID in a different case produces a different binding")
	}

	sealed, err := EncryptRecovery(&bindingKey.PublicKey, []byte("payload"), RecoveryBinding(upper, pseA))
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}
	if _, err := DecryptRecovery(bindingKey, sealed, RecoveryBinding(rowA, pseA)); err != nil {
		t.Errorf("a record sealed with an uppercase id does not open with the lowercase id "+
			"PostgreSQL hands back: %v", err)
	}

	// Case folding must not reach the pseudonym: it is a hex HMAC that arrives
	// verbatim from a TEXT column, and folding it would merge distinct subjects.
	if bytes.Equal(RecoveryBinding(rowA, strings.ToUpper(pseA)), RecoveryBinding(rowA, pseA)) {
		t.Error("the pseudonym is case-folded, which merges bindings that must stay distinct")
	}
}

// ---------------------------------------------------------------------------
// Legacy compatibility
// ---------------------------------------------------------------------------

// sealLegacy builds an escrow blob in the pre-binding format: a bare
// wrapped-key length prefix, an RSA-OAEP wrap under a nil label, and an AES-GCM
// blob with no AAD.
//
// It is spelled out by hand rather than produced by a legacy encryptor because
// no legacy encryptor exists any more, deliberately: nothing in the product can
// write an unbound escrow record. The cost is this fixture, which is also the
// benefit - the format that has to keep being readable is written down in one
// place instead of living only in rows nobody can regenerate. cmd/recover and
// tests/attack carry their own copy for the same reason.
func sealLegacy(t *testing.T, pub *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()

	aesKey := make([]byte, recoveryAESKeySize)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("aes key: %v", err)
	}
	aesBlob, err := Encrypt(plaintext, aesKey)
	if err != nil {
		t.Fatalf("legacy aes encrypt: %v", err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		t.Fatalf("legacy wrap: %v", err)
	}

	out := make([]byte, 4+len(wrapped)+len(aesBlob))
	binary.BigEndian.PutUint32(out[:4], uint32(len(wrapped))) // #nosec G115 -- a 2048-bit wrap is 256 bytes
	copy(out[4:], wrapped)
	copy(out[4+len(wrapped):], aesBlob)
	return out
}

// Records already in auth.account_recovery are the only recoverable copy of the
// accounts they describe. If this test fails, the change has destroyed the
// recoverability of every erasure performed before it shipped.
func TestRecoveryLegacy_PreBindingRecordsStillOpen(t *testing.T) {
	secret := []byte(`{"email":"legacy@example.invalid","display_name":"Legacy"}`)
	blob := sealLegacy(t, &bindingKey.PublicKey, secret)

	if got := RecoveryBlobFormat(blob); got != RecoveryFormatLegacy {
		t.Fatalf("format = %v, want legacy: a stored record is not being recognized for what it is", got)
	}
	got, err := DecryptRecoveryLegacy(bindingKey, blob)
	if err != nil {
		t.Fatalf("a pre-binding escrow record no longer opens: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("legacy round trip returned %q, want %q", got, secret)
	}
}

// The two paths are exclusive in both directions. Neither can be reached by
// accident, so the tool always knows which one it used and can say so.
func TestRecoveryLegacy_FormatsAreNotInterchangeable(t *testing.T) {
	binding := RecoveryBinding(rowA, pseA)
	bound, err := EncryptRecovery(&bindingKey.PublicKey, []byte("payload"), binding)
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}
	legacy := sealLegacy(t, &bindingKey.PublicKey, []byte("payload"))

	if _, err := DecryptRecoveryLegacy(bindingKey, bound); err == nil {
		t.Error("a bound record was read down the legacy path, which would drop its binding silently")
	}
	if _, err := DecryptRecovery(bindingKey, legacy, binding); err == nil {
		t.Error("a legacy record was accepted by the bound path, which would report an unverified " +
			"attribution as a verified one")
	}
	if got := RecoveryBlobFormat(bound); got != RecoveryFormatBound {
		t.Errorf("bound blob classified as %v", got)
	}
}

// Stripping the bound header is the obvious downgrade: leave the wrapped key and
// the ciphertext, drop the magic, and hope the reader falls back to the format
// with no binding. The framing makes that structurally impossible, and this test
// says so out loud because the guarantee is not obvious from reading either
// function.
func TestRecoveryLegacy_BoundRecordCannotBeDowngraded(t *testing.T) {
	bound, err := EncryptRecovery(&bindingKey.PublicKey, []byte("payload"), RecoveryBinding(rowA, pseA))
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}

	stripped := bytes.Clone(bound[recoveryHeaderLen:])
	if got := RecoveryBlobFormat(stripped); got != RecoveryFormatLegacy {
		t.Fatalf("format = %v: the header-stripped blob is not even reaching the legacy path, "+
			"so this test is not exercising the downgrade it claims to", got)
	}
	if plain, err := DecryptRecoveryLegacy(bindingKey, stripped); err == nil {
		t.Errorf("stripping the bound header downgraded the record to the unbound format: %q", plain)
	}
}

// Framing classification runs on hostile input before any key is touched, so it
// must be total: no panic, no index out of range, and no blob that is both.
func TestRecoveryBlobFormat_ClassifiesHostileInput(t *testing.T) {
	tests := []struct {
		name string
		blob []byte
		want RecoveryFormat
	}{
		{"nil", nil, RecoveryFormatUnknown},
		{"empty", []byte{}, RecoveryFormatUnknown},
		{"one byte", []byte{'V'}, RecoveryFormatUnknown},
		{"three bytes", []byte("V42"), RecoveryFormatUnknown},
		{"magic with no version", []byte(recoveryMagic), RecoveryFormatUnknown},
		{"magic, unknown version", append([]byte(recoveryMagic), 0x03), RecoveryFormatUnknown},
		{"magic, legacy-looking version", append([]byte(recoveryMagic), 0x01), RecoveryFormatUnknown},
		{"magic and version", append([]byte(recoveryMagic), recoveryVersionBound), RecoveryFormatBound},
		{"zeroes", make([]byte, 64), RecoveryFormatLegacy},
		{"rsa-2048 length prefix", []byte{0x00, 0x00, 0x01, 0x00}, RecoveryFormatLegacy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("classifying %q panicked: %v", tc.blob, r)
				}
			}()
			if got := RecoveryBlobFormat(tc.blob); got != tc.want {
				t.Errorf("format = %v, want %v", got, tc.want)
			}
		})
	}

	// The names are printed by cmd/recover into every output line and into its
	// stderr diagnostics, so they are contract, not debug output. "unknown" in
	// particular has to render as something rather than as an empty string,
	// because it is what an operator sees for a record the tool could not even
	// classify.
	for format, want := range map[RecoveryFormat]string{
		RecoveryFormatBound:   "bound",
		RecoveryFormatLegacy:  "legacy",
		RecoveryFormatUnknown: "unknown",
		RecoveryFormat(99):    "unknown",
	} {
		if got := format.String(); got != want {
			t.Errorf("RecoveryFormat(%d).String() = %q, want %q", format, got, want)
		}
	}

	// A blob that classifies as bound but holds nothing after the header: the
	// framing check passes and the length prefix is not there to read. This is
	// the smallest hostile input that reaches openRecovery, and it must produce
	// an error rather than an index out of range in an offline tool an operator
	// is pointing at a damaged backup.
	for i := 0; i <= 4; i++ {
		runt := append([]byte(recoveryMagic), recoveryVersionBound)
		runt = append(runt, make([]byte, i)...)
		if _, err := DecryptRecovery(bindingKey, runt, RecoveryBinding(rowA, pseA)); err == nil {
			t.Errorf("a bound blob with %d bytes of body decrypted", i)
		}
	}

	// A blob carrying the magic but an unrecognized version is refused by both
	// readers rather than being guessed at. A future format must never be
	// readable as this one.
	future := append([]byte(recoveryMagic), 0x03)
	future = append(future, make([]byte, 300)...)
	if _, err := DecryptRecovery(bindingKey, future, RecoveryBinding(rowA, pseA)); err == nil {
		t.Error("a record from an unknown future format was read as the current one")
	}
	if _, err := DecryptRecoveryLegacy(bindingKey, future); err == nil {
		t.Error("a record from an unknown future format was read as legacy")
	}
}

// Error strings from either path are printed by an offline operator tool and end
// up in tickets. Neither the plaintext nor the private key may appear in them,
// whichever framing produced the failure.
func TestRecoveryBinding_ErrorsCarryNoSecrets(t *testing.T) {
	secret := []byte(`{"email":"binding-canary@example.invalid"}`)
	bound, err := EncryptRecovery(&bindingKey.PublicKey, secret, RecoveryBinding(rowA, pseA))
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}
	legacy := sealLegacy(t, &bindingKey.PublicKey, secret)

	corruptBound := bytes.Clone(bound)
	corruptBound[len(corruptBound)-1] ^= 0xFF

	msgs := []string{}
	for _, err := range []error{
		second(DecryptRecovery(bindingKey, bound, RecoveryBinding(rowB, pseB))),
		second(DecryptRecovery(bindingKey, corruptBound, RecoveryBinding(rowA, pseA))),
		second(DecryptRecovery(bindingKey, legacy, RecoveryBinding(rowA, pseA))),
		second(DecryptRecoveryLegacy(bindingKey, bound)),
		second(DecryptRecoveryLegacy(bindingKey, legacy[:len(legacy)/2])),
	} {
		if err == nil {
			t.Fatal("a case that must fail did not, so the leak check below is vacuous")
		}
		msgs = append(msgs, err.Error())
	}

	for _, msg := range msgs {
		for _, needle := range []string{"binding-canary", "@example.invalid", string(secret)} {
			if strings.Contains(msg, needle) {
				t.Errorf("error message leaks plaintext %q: %s", needle, msg)
			}
		}
		for _, limb := range []string{
			bindingKey.D.String(),
			bindingKey.Primes[0].String(),
			bindingKey.Primes[1].String(),
		} {
			if strings.Contains(msg, limb) {
				t.Errorf("error message contains RSA private key material: %s", msg)
			}
		}
		// The binding is built from a pseudonym and a row id. Neither is an
		// identity, but echoing them back would still put a correlatable handle
		// into an operator's terminal for no benefit.
		for _, needle := range []string{pseA, pseB} {
			if strings.Contains(msg, needle) {
				t.Errorf("error message echoes the subject pseudonym: %s", msg)
			}
		}
	}
}

// second discards a decrypt's plaintext so a table of failing calls reads as a
// list of errors. It is only ever used on calls that must fail.
func second(_ []byte, err error) error { return err }
