package service

import (
	"bytes"
	"context"
	"errors"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The AAD a blob is bound to is derived from the id in the ROW, not from the id
// the caller asked for. TestBlobAADNamespacesCannotCollide pins that the two AAD
// helpers refuse an id carrying a colon; the tests here pin that the read paths
// honor the refusal instead of discarding it, which is the half that decides
// whether anything is protected.
//
// The write path cannot produce such a row: ids come from RandomUUID, which
// emits hex and dashes. A row like this arrives from somewhere else, a restored
// dump or a second writer against the same table, and that is the case the guard
// was added for.

const (
	blobStoredIDUser   = "user-1"
	blobStoredIDVictim = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	// The id that makes the namespaces ambiguous: the data AAD of this row is
	// the label AAD of the row above it.
	blobStoredIDPoison = "label:" + blobStoredIDVictim
)

// A download must refuse a row whose stored id collides, rather than decrypt
// under an AAD that identifies two different ciphertexts. AES-GCM authenticates
// the AAD it is handed and has no opinion about which of the two things that AAD
// was meant to mean, so the id check is the only layer that can tell them apart.
func TestBlobDownloadRefusesAStoredIDThatCollidesWithALabelAAD(t *testing.T) {
	svc := NewBlobService(&mocks.MockBlobRepo{}, testKey, testHMAC, defaultBlobConfig())
	pseudo := svc.Pseudonym(blobStoredIDUser)

	// The victim's label, sealed exactly as an upload would seal it.
	labelAAD, err := blobLabelAAD(blobStoredIDVictim, pseudo)
	if err != nil {
		t.Fatalf("blobLabelAAD: %v", err)
	}
	const labelText = "weekly-payroll.csv"
	labelEnc, err := vaultcrypto.Encrypt([]byte(labelText), testKey, labelAAD)
	if err != nil {
		t.Fatalf("encrypt label: %v", err)
	}

	// The premise: those same bytes verify as the PAYLOAD of a row whose id is
	// "label:<victim>", because the AAD the download path derives for that row is
	// byte for byte the AAD the label was sealed under. Asserted here so this test
	// cannot quietly degrade into "the decrypt happened to fail".
	plain, err := vaultcrypto.Decrypt(labelEnc, testKey, []byte(blobStoredIDPoison+":"+pseudo))
	if err != nil {
		t.Fatalf("the premise no longer holds: the label ciphertext no longer verifies as the payload of %q (%v), "+
			"so this test would pass with the id check removed", blobStoredIDPoison, err)
	}
	if !bytes.Equal(plain, []byte(labelText)) {
		t.Fatalf("decrypt returned %q, want the victim's label", plain)
	}

	repo := &mocks.MockBlobRepo{
		GetByIDAndPseudonymFn: func(context.Context, string, string) (*model.Blob, error) {
			return &model.Blob{
				ID: blobStoredIDPoison, PseudonymID: pseudo,
				DataEnc: labelEnc, Checksum: "sha256:deadbeef",
			}, nil
		},
	}
	svc = NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	data, label, checksum, err := svc.Download(context.Background(), blobStoredIDUser, blobStoredIDPoison)
	if !errors.Is(err, errBlobIDNamespace) {
		t.Fatalf("err = %v, want errBlobIDNamespace; the row was read under an AAD that identifies two ciphertexts", err)
	}
	if data != nil || label != "" || checksum != "" {
		t.Errorf("a refused download still returned data=%q label=%q checksum=%q", data, label, checksum)
	}
}

// A listing must never show a name decrypted under an ambiguous id: the name it
// would show could have been sealed for a different object. The row is dropped
// from the listing rather than shown unnamed, which is the narrower answer, and
// the rest of the listing has to survive it.
//
// That last part is the regression this pins. Skipping the row is one statement
// away from failing the whole call, and a user whose listing is emptied by one
// unreadable row loses sight of every blob they own, including the ones the
// service can still read perfectly well.
func TestBlobListDropsARowWithAnAmbiguousIDAndKeepsTheRest(t *testing.T) {
	svc := NewBlobService(&mocks.MockBlobRepo{}, testKey, testHMAC, defaultBlobConfig())
	pseudo := svc.Pseudonym(blobStoredIDUser)

	sealLabel := func(id, text string) []byte {
		t.Helper()
		enc, err := vaultcrypto.Encrypt([]byte(text), testKey, []byte("label:"+id+":"+pseudo))
		if err != nil {
			t.Fatalf("encrypt label for %q: %v", id, err)
		}
		return enc
	}

	const (
		secondID    = "9c858901-8a57-4791-81fe-4c455b099bc9"
		firstLabel  = "holiday-photos"
		secondLabel = "tax-return-2025"
		poisonLabel = "totally-normal.pdf"
	)
	firstEnc := sealLabel(blobStoredIDVictim, firstLabel)
	secondEnc := sealLabel(secondID, secondLabel)
	// Sealed under the AAD the listing would derive for the poisoned row, so the
	// name is one the listing would happily show if it stopped checking the id.
	poisonEnc := sealLabel(blobStoredIDPoison, poisonLabel)

	// The poisoned row sits between two sound ones, so a listing that stops or
	// fails at it loses the row after it as well.
	repo := &mocks.MockBlobRepo{
		ListByPseudonymFn: func(context.Context, string) ([]*model.Blob, error) {
			return []*model.Blob{
				{ID: blobStoredIDVictim, PseudonymID: pseudo, LabelEnc: firstEnc, SizeBytes: 10},
				{ID: blobStoredIDPoison, PseudonymID: pseudo, LabelEnc: poisonEnc, SizeBytes: 20},
				{ID: secondID, PseudonymID: pseudo, LabelEnc: secondEnc, SizeBytes: 30},
			}, nil
		},
	}
	svc = NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	metas, quota, err := svc.List(context.Background(), blobStoredIDUser)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if quota == nil {
		t.Fatal("List returned no quota information")
	}

	byID := map[string]*BlobMeta{}
	for _, m := range metas {
		byID[m.ID] = m
		if m.Label == poisonLabel {
			t.Errorf("row %s was named %q, decrypted under an AAD derived from an ambiguous id", m.ID, m.Label)
		}
	}
	if _, ok := byID[blobStoredIDPoison]; ok {
		t.Errorf("the row with the ambiguous id was listed; it cannot be described safely")
	}
	if got := byID[blobStoredIDVictim]; got == nil || got.Label != firstLabel {
		t.Errorf("the sound row before the ambiguous one is %+v, want it listed as %q", got, firstLabel)
	}
	if got := byID[secondID]; got == nil || got.Label != secondLabel {
		t.Errorf("the sound row after the ambiguous one is %+v, want it listed as %q; "+
			"one unreadable row must not empty a user's listing", got, secondLabel)
	}
}
