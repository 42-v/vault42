// Rotation-versus-minting regression, and the evidence for what rotation
// actually does to a retired key.
//
// MintService reaches the signing key through keystore.ActiveKey, which
// releases its read lock on return, so the pointer outlives the lock: Mint
// holds it across a UUID generation and a claim construction before signing.
// Meanwhile a rotation calls TokenService.UpdateSigningKey, which zeroes the
// key it replaces. Read side by side those two facts predict a corrupt token
// on POST /mint, the subject-assertion oracle a trusted platform delegates
// signing to.
//
// They do not, and the reason is worth pinning down rather than assuming in
// either direction. Since Go 1.24 crypto/rsa signs from an unexported cached
// representation built at first use, not from the exported D, Primes and
// Precomputed fields that zeroPrivateKey clears. Signing therefore never reads
// the words the wipe overwrites: there is no torn read, no corrupt signature,
// and no data race on that path. TestZeroPrivateKeyLeavesTheKeyUsable in
// token_zeroization_test.go demonstrates the underlying behaviour directly.
//
// This test holds the composite path down anyway, because the reasoning that
// makes it safe lives in the standard library and can change under us. It
// wires the real MintService and the real TokenService to a key holder that
// reproduces keystore.ActiveKey's locking exactly, rotates underneath a fleet
// of minters, and asserts two independent things: the race detector stays
// quiet, and every token that comes back carries a signature that verifies.
// The signature check is what still catches a corrupt token when the suite runs
// without -race.
package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// rotatingKeyHolder mirrors keystore.KeyStore's locking discipline for the two
// operations this race needs: a reader that returns the active key under a read
// lock it then releases, and a rotation that publishes a new key under the write
// lock and notifies a listener afterwards.
//
// It is a stand-in for the real KeyStore only because the real one needs
// Postgres. The locking is copied, not approximated: weakening it here would
// make the test pass for the wrong reason.
type rotatingKeyHolder struct {
	mu     sync.RWMutex
	key    *rsa.PrivateKey
	kid    string
	notify func(key *rsa.PrivateKey, kid string)
}

// ActiveKey reproduces keystore.ActiveKey: read lock, return the pointer,
// release on return. The released lock is the whole point of the regression.
func (h *rotatingKeyHolder) ActiveKey() (*rsa.PrivateKey, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.key, h.kid
}

// rotate publishes a new active key and then notifies, matching the order in
// keystore.applyKeys, which fires onKeyChange after releasing the lock.
func (h *rotatingKeyHolder) rotate(key *rsa.PrivateKey, kid string) {
	h.mu.Lock()
	h.key, h.kid = key, kid
	h.mu.Unlock()
	if h.notify != nil {
		h.notify(key, kid)
	}
}

// verifyRS256 checks the signature over a compact JWS with the public half of
// whichever key signed it. It deliberately does not validate claims: issuer and
// audience belong to the mint policy, and a policy rejection would mask the
// signature failure this test exists to catch.
func verifyRS256(t *testing.T, token string, pubs map[string]*rsa.PublicKey) {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS: %d segments", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	// The kid is read out of the header rather than tracked alongside the token,
	// so a token signed with one key and labelled with another fails here too.
	kid := ""
	if i := strings.Index(string(hdr), `"kid":"`); i >= 0 {
		rest := string(hdr)[i+len(`"kid":"`):]
		if j := strings.IndexByte(rest, '"'); j >= 0 {
			kid = rest[:j]
		}
	}
	pub, ok := pubs[kid]
	if !ok {
		t.Fatalf("token names kid %q, which no key in the set published", kid)
	}

	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("minted token failed signature verification under kid %q: %v", kid, err)
	}
}

// TestMintDoesNotSignWithARotatingKey drives POST /mint's signing path against a
// concurrent key rotation.
//
// Run it under -race. Without the fix the detector reports a write/read pair
// between zeroBigInt and rsa.SignPKCS1v15 on the same big.Int words, and the
// verification below fails on whichever token caught the wipe mid-flight.
func TestMintDoesNotSignWithARotatingKey(t *testing.T) {
	const (
		keyCount  = 4
		minters   = 8
		perMinter = 40
	)

	// Keys are generated up front: RSA-2048 generation is far slower than the
	// window under test, so generating inside the rotation loop would space the
	// rotations too widely to ever land in it.
	keys := make([]*rsa.PrivateKey, keyCount)
	kids := make([]string, keyCount)
	pubs := make(map[string]*rsa.PublicKey, keyCount)
	for i := range keys {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		keys[i] = key
		kids[i] = vaultcrypto.KIDFromPublicKey(&key.PublicKey)
		// The public half is copied before any rotation can zero the private
		// half, and zeroPrivateKey leaves N and E alone in any case.
		pub := key.PublicKey
		pubs[kids[i]] = &pub
	}

	holder := &rotatingKeyHolder{key: keys[0], kid: kids[0]}
	tokenSvc := NewTokenService(keys[0], kids[0], mintTestIssuer, mintTestAudience,
		15*time.Minute, time.Hour, 24*time.Hour)

	// This is cmd/vault/main.go's wiring: the keystore notifies the token
	// service, which swaps the key and wipes the one it replaced.
	holder.notify = func(key *rsa.PrivateKey, kid string) {
		tokenSvc.UpdateSigningKey(key, kid)
	}

	mintSvc, err := NewMintService(holder.ActiveKey, mintTestConfig(), nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}

	tokens := make(chan string, minters*perMinter)
	stop := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(minters)
	for range minters {
		go func() {
			defer wg.Done()
			for range perMinter {
				res, err := mintSvc.Mint(MintRequest{Subject: "beon3-user-1"})
				if err != nil {
					// An unavailable key is a policy outcome, not a race; only a
					// signing failure matters here.
					continue
				}
				tokens <- res.Token
			}
		}()
	}

	var rotator sync.WaitGroup
	rotator.Add(1)
	go func() {
		defer rotator.Done()
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			n := i % keyCount
			holder.rotate(keys[n], kids[n])
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()
	close(stop)
	rotator.Wait()
	close(tokens)

	verified := 0
	for tok := range tokens {
		verifyRS256(t, tok, pubs)
		verified++
	}
	if verified == 0 {
		t.Fatal("no tokens were minted, so the race window was never entered")
	}
	t.Logf("verified %d minted tokens across %d rotations", verified, keyCount)
}
