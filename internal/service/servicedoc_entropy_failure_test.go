package service

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/repository"
)

// errSvcDocEntropyExhausted is what the starved reader returns, so the
// assertion can follow the failure from the reader to Put's caller instead of
// matching a message that the encrypt or the store step could also produce.
var errSvcDocEntropyExhausted = errors.New("servicedoc test: entropy exhausted")

// svcDocUUIDStarvedReader serves real entropy for everything except the 16-byte
// read a UUID is made of. Put needs entropy twice on a first write, once for the
// AES-GCM nonce (12 bytes) and once for the document ID, and only the second
// failure exercises the branch under test, so the discriminator is the request
// size rather than a call count that would drift with crypto internals.
type svcDocUUIDStarvedReader struct{ real io.Reader }

func (r svcDocUUIDStarvedReader) Read(p []byte) (int, error) {
	if len(p) == 16 {
		return 0, errSvcDocEntropyExhausted
	}
	return r.real.Read(p)
}

// The document ID is the row's primary key and the handle every later read,
// replace and erasure addresses it by. A first write that could not mint one has
// nothing to store the ciphertext under, so it has to fail before the upsert:
// a row written with an empty or reused ID would either collide with another
// subject's document or become unreachable to the erasure sweep, which is the
// one operation that must be able to find everything.
func TestServiceDocument_PutFailsWhenTheDocumentIDCannotBeMinted(t *testing.T) {
	repo := newFakeSvcDocRepo()
	svc := newSvcDocService(t, repo, defaultSvcDocConfig())

	serviceRandUse(t, svcDocUUIDStarvedReader{real: serviceRandReal})

	meta, created, err := svc.Put(context.Background(), svcDocClientA, "user-1", "prefs",
		[]byte(`{"a":1}`), repository.VisibilityPrivate)
	if err == nil {
		t.Fatal("Put reported a stored document with no ID to store it under")
	}
	if !errors.Is(err, errSvcDocEntropyExhausted) {
		t.Fatalf("err = %v, want the reader's own failure wrapped; the ID was either "+
			"minted from somewhere else or a different failure was reported as the cause", err)
	}
	if !strings.Contains(err.Error(), "uuid") {
		t.Errorf("err = %v, want it to name the ID step", err)
	}
	if meta != nil {
		t.Errorf("metadata came back alongside the error: %+v", meta)
	}
	if created {
		t.Error("Put reported the document created")
	}
	if n := len(repo.rows); n != 0 {
		t.Errorf("%d row(s) written; a document stored under an ID that was never "+
			"minted is one the erasure sweep cannot address", n)
	}
}

// The exclusion this test retired argued the branch was unreachable because
// crypto/rand.Read fatals rather than returning an error. RandomUUID does not
// call it: it goes through RandomBytes, which is io.ReadFull(rand.Reader, b) and
// reports a short or failed read to its caller like any other reader. Pinning
// that difference here keeps the argument from coming back.
func TestServiceDocument_RandomUUIDReportsReaderFailures(t *testing.T) {
	serviceRandUse(t, svcDocUUIDStarvedReader{real: serviceRandReal})

	id, err := vaultcrypto.RandomUUID()
	if err == nil {
		t.Fatalf("RandomUUID returned %q from a reader that refused to read", id)
	}
	if !errors.Is(err, errSvcDocEntropyExhausted) {
		t.Fatalf("err = %v, want the reader's own failure wrapped", err)
	}
}
