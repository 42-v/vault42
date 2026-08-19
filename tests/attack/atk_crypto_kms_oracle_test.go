package attack

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/42-v/vault42/internal/kms"
)

// kmsRoot is a fixed 32-byte KMS root secret. Fixed rather than random so a
// failure reproduces byte for byte; nothing in these tests depends on it being
// unpredictable, only on it being the length the constructor demands.
var kmsRoot = bytes.Repeat([]byte{0xA5}, 32)

func newKMS(t *testing.T) *kms.Service {
	t.Helper()
	svc, err := kms.New(kmsRoot)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	return svc
}

// The package doc on internal/kms claims the Service "is safe for concurrent
// use: the root is immutable after construction and derivation allocates fresh
// buffers per call". Close falsifies the first half of that sentence. It writes
// zeros over s.root with no lock and no happens-before edge to any in-flight
// Unwrap, while deriveKEK reads the same backing array to seed HKDF.
//
// This is not a theoretical interleaving. Unwrap is served from an HTTP handler
// goroutine and Close runs on the shutdown path, so any request still in the
// handler when the process starts draining races the wipe. The read is of live
// key material, which is exactly the memory a race detector exists to protect.
//
// The test drives the same two calls the server does and asserts nothing about
// the result: under -race the detector reports the write/read pair and fails
// the test on its own. Without -race it passes, which is the honest outcome:
// the finding is a data race, not a wrong answer.
func TestKMSAttack_CloseRacesUnwrapOnRootSecret(t *testing.T) {
	svc := newKMS(t)

	env, err := svc.Wrap("kid-race", []byte("data-root-material"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	var wg sync.WaitGroup
	// Enough concurrent unwraps that at least one is inside deriveKEK when the
	// wipe lands. One would usually be enough; this makes the schedule reliable.
	const readers = 64
	wg.Add(readers + 1)

	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			// Result deliberately ignored: after Close the derived KEK is
			// wrong and the unwrap fails, which is not what is under test.
			_, _ = svc.Unwrap("kid-race", env)
		}()
	}
	go func() {
		defer wg.Done()
		svc.Close()
	}()

	wg.Wait()
}

// The same race reached through the wrap half of the interface. Wrap is not
// exposed over HTTP today, but it is exported, deploy tooling calls it, and it
// reads the identical unsynchronized field.
func TestKMSAttack_CloseRacesWrapOnRootSecret(t *testing.T) {
	svc := newKMS(t)

	var wg sync.WaitGroup
	const writers = 64
	wg.Add(writers + 1)

	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			_, _ = svc.Wrap("kid-race", []byte("data-root-material"))
		}()
	}
	go func() {
		defer wg.Done()
		svc.Close()
	}()

	wg.Wait()
}

// A wiped root is still 32 bytes, so every length guard downstream still passes
// and HKDF still produces a well-formed 32-byte KEK. Nothing about the secret's
// absence is visible to the arithmetic, which is why the Service has to know it
// is closed rather than infer it.
//
// Before it did, Wrap kept returning envelopes after Close. They were sealed
// under HKDF(zeros) instead of HKDF(root), so anyone who constructs a Service
// over 32 zero bytes could open them, and neither Wrap nor Unwrap reported
// anything. That turned a shutdown race from a nuisance into ciphertext sealed
// under a public constant.
//
// This is the inverted form: the closed Service must refuse, and the all-zero
// root must open nothing.
func TestKMSAttack_WipedRootProducesNothing(t *testing.T) {
	svc := newKMS(t)
	live, err := svc.Wrap("kid-after-close", []byte("secret"))
	if err != nil {
		t.Fatalf("Wrap before Close: %v", err)
	}
	svc.Close()

	if env, err := svc.Wrap("kid-after-close", []byte("secret")); err == nil {
		t.Fatalf("Wrap after Close produced a %d-byte envelope; a closed service "+
			"seals under HKDF(zeros), which is a key anyone can derive", len(env))
	}
	if _, err := svc.Unwrap("kid-after-close", live); !errors.Is(err, kms.ErrUnwrap) {
		t.Fatalf("Unwrap after Close returned %v, want ErrUnwrap", err)
	}

	// The envelope sealed while the root was live must not be openable by a
	// Service over an all-zero root. This is the property that was broken.
	attacker, err := kms.New(make([]byte, 32))
	if err != nil {
		t.Fatalf("kms.New(zero root): %v", err)
	}
	if pt, err := attacker.Unwrap("kid-after-close", live); err == nil {
		t.Fatalf("an all-zero root opened a real envelope and read %q", pt)
	}
}

// Per-kid KEK separation. Two distinct kids must never derive the same KEK, and
// an envelope wrapped under one kid must not open under another. The kid is
// bound twice, as HKDF info and as GCM AAD, so this should hold; it is checked
// because the whole oracle-resistance argument rests on it.
func TestKMSAttack_CrossKidReplayIsRejected(t *testing.T) {
	svc := newKMS(t)
	defer svc.Close()

	env, err := svc.Wrap("tenant-a", []byte("tenant a data key"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Neighboring kids, kids that differ only by the separator the info label
	// ends with, and kids that would collide under a naive concatenation.
	for _, kid := range []string{
		"tenant-b",
		"tenant-A",
		"tenant-a ",
		" tenant-a",
		"tenant-a\x00",
		"/tenant-a",
		"tenant-a/",
		"vault42/kms/kek/v1/tenant-a",
		strings.Repeat("tenant-a", 64),
	} {
		if _, err := svc.Unwrap(kid, env); !errors.Is(err, kms.ErrUnwrap) {
			t.Errorf("envelope for tenant-a opened (or failed non-opaquely) under kid %q: err=%v", kid, err)
		}
	}
}

// The HKDF info is a fixed prefix concatenated with the kid. Concatenation is
// only injective here because the prefix is constant, so no pair of kids can
// produce the same info string. Checked over a set chosen to include the pairs
// a length-extension style confusion would need.
func TestKMSAttack_NoTwoKidsShareAKEK(t *testing.T) {
	svc := newKMS(t)
	defer svc.Close()

	kids := []string{
		"a", "b", "ab", "a/b", "a//b", "/a/b", "ab/", "a\x00b", "ab\x00",
		"vault42/kms/kek/v1/a", "", "A", "а", // Cyrillic a, looks like ASCII a
	}

	// Two kids share a KEK exactly when an envelope wrapped under one opens
	// under the other. Probing through the public API rather than comparing
	// derived keys keeps this honest: it is the property that matters.
	seen := map[string][]byte{}
	for _, kid := range kids {
		if kid == "" {
			continue // Wrap rejects the empty kid outright
		}
		env, err := svc.Wrap(kid, []byte("marker"))
		if err != nil {
			t.Fatalf("Wrap(%q): %v", kid, err)
		}
		seen[kid] = env
	}

	for wrapKid, env := range seen {
		for openKid := range seen {
			if openKid == wrapKid {
				continue
			}
			if _, err := svc.Unwrap(openKid, env); err == nil {
				t.Errorf("kid %q opened an envelope wrapped under kid %q: the KEKs collide", openKid, wrapKid)
			}
		}
	}
}

// Envelope mutation. Every single-byte edit, truncation and extension must be
// rejected, and rejected with the one opaque error. A partial plaintext or a
// distinguishable error would turn the endpoint into the oracle its package doc
// says it is not.
func TestKMSAttack_MutatedEnvelopesAllCollapseToOneError(t *testing.T) {
	svc := newKMS(t)
	defer svc.Close()

	const kid = "kid-mutate"
	plaintext := []byte("0123456789abcdef0123456789abcdef")
	env, err := svc.Wrap(kid, plaintext)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	mutations := map[string][]byte{}

	// Every bit of the nonce, ciphertext and tag flipped one at a time.
	for i := range env {
		for bit := 0; bit < 8; bit++ {
			m := append([]byte(nil), env...)
			m[i] ^= 1 << bit
			mutations[fmt.Sprintf("flip byte %d bit %d", i, bit)] = m
		}
	}
	// Truncation at every offset, including inside the nonce and exactly at the
	// nonce boundary, where Decrypt short-circuits before AES-GCM runs at all.
	for i := 0; i < len(env); i++ {
		mutations[fmt.Sprintf("truncate to %d", i)] = append([]byte(nil), env[:i]...)
	}
	// Extension: trailing bytes, and a whole second envelope appended.
	mutations["append zero byte"] = append(append([]byte(nil), env...), 0)
	mutations["append 4KiB"] = append(append([]byte(nil), env...), bytes.Repeat([]byte{0xFF}, 4096)...)
	mutations["doubled"] = append(append([]byte(nil), env...), env...)
	mutations["nonce reused as ciphertext"] = append(append([]byte(nil), env[:12]...), env[:12]...)

	for name, m := range mutations {
		pt, err := svc.Unwrap(kid, m)
		if err == nil {
			t.Errorf("%s: mutated envelope was accepted, plaintext=%q", name, pt)
			continue
		}
		if !errors.Is(err, kms.ErrUnwrap) {
			t.Errorf("%s: error was %v, not the opaque kms.ErrUnwrap, so the failure mode is distinguishable", name, err)
		}
		if len(pt) != 0 {
			t.Errorf("%s: rejected unwrap still returned %d bytes of plaintext", name, len(pt))
		}
	}
}

// A payload wrapped for one purpose must not be usable for another. The kid is
// the only thing binding an envelope to its purpose, so this reduces to the
// cross-kid property above, but it is worth stating in the terms an operator
// thinks in: the life42 data-root envelope and a hypothetical second consumer's
// envelope are separated by kid alone. Nothing in the envelope records what it
// is for, who wrapped it, or when.
//
// The test passes today. It is here to fail loudly if the kid ever stops being
// bound as AAD, and to document what is NOT bound: there is no purpose field,
// no tenant field, no expiry, and no wrap timestamp. An attacker holding an old
// envelope and the unwrap scope can release its plaintext forever.
func TestKMSAttack_EnvelopeCarriesNoPurposeOrExpiry(t *testing.T) {
	svc := newKMS(t)
	defer svc.Close()

	env, err := svc.Wrap("life42-data-root", []byte("root"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if _, err := svc.Unwrap("life42-backup-root", env); !errors.Is(err, kms.ErrUnwrap) {
		t.Errorf("an envelope crossed purposes: %v", err)
	}

	// The same bytes, unwrapped twice, yield the same plaintext with no replay
	// counter anywhere. Documented in AR-10 as accepted; asserted here so the
	// register and the code cannot drift apart.
	a, err := svc.Unwrap("life42-data-root", env)
	if err != nil {
		t.Fatalf("first unwrap: %v", err)
	}
	b, err := svc.Unwrap("life42-data-root", env)
	if err != nil {
		t.Fatalf("second unwrap failed, so replay IS bounded and AR-10 understates the control: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two unwraps of one envelope disagreed")
	}
}

// Root length handling. Short roots are refused; long roots are accepted, which
// is correct for HKDF but worth pinning so a future "exactly 32" check does not
// silently break a deployment provisioned with a longer secret.
func TestKMSAttack_RootLengthBounds(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31} {
		if _, err := kms.New(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Errorf("a %d-byte root was accepted", n)
		}
	}
	for _, n := range []int{32, 33, 64, 1024} {
		svc, err := kms.New(bytes.Repeat([]byte{1}, n))
		if err != nil {
			t.Errorf("a %d-byte root was rejected: %v", n, err)
			continue
		}
		svc.Close()
	}

	// New copies the root, so a caller zeroing its own buffer afterwards must
	// not affect the Service. The doc comment promises this explicitly.
	root := bytes.Repeat([]byte{7}, 32)
	svc, err := kms.New(root)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	defer svc.Close()
	env, err := svc.Wrap("kid", []byte("x"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	for i := range root {
		root[i] = 0
	}
	if _, err := svc.Unwrap("kid", env); err != nil {
		t.Errorf("zeroing the caller's root buffer broke the Service: %v", err)
	}
}

// The wire encoding the handler uses is base64.StdEncoding. A caller that sends
// base64url, or padding-stripped base64, gets the same opaque failure as a
// tampered envelope, so the encoding is not itself an oracle. Asserted at the
// encoding layer because the handler collapses both into one response and this
// is the only place the distinction is visible.
func TestKMSAttack_Base64VariantsAreNotAnOracle(t *testing.T) {
	svc := newKMS(t)
	defer svc.Close()

	const kid = "kid-b64"
	env, err := svc.Wrap(kid, []byte("payload"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	std := base64.StdEncoding.EncodeToString(env)
	url := base64.URLEncoding.EncodeToString(env)
	raw := base64.RawStdEncoding.EncodeToString(env)

	if _, err := base64.StdEncoding.DecodeString(std); err != nil {
		t.Fatalf("std encoding did not round trip: %v", err)
	}
	// A raw (unpadded) or url-alphabet body decodes to something that is not
	// the envelope, or fails to decode. Either way the handler answers 400
	// unwrap_failed. The property under test is that neither produces a
	// SUCCESS, which would mean the encoding was silently normalized.
	for name, s := range map[string]string{"url": url, "raw": raw} {
		decoded, decErr := base64.StdEncoding.DecodeString(s)
		if decErr != nil {
			continue // rejected at decode, same 400 as everything else
		}
		if bytes.Equal(decoded, env) {
			continue // same bytes, so same outcome, no distinction to exploit
		}
		if _, err := svc.Unwrap(kid, decoded); err == nil {
			t.Errorf("%s-encoded body decoded to a different byte string that still unwrapped", name)
		}
	}
}
