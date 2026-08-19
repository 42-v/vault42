package service

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// An upload draws on crypto/rand three times: once for the blob ID, once for
// the nonce that encrypts the payload and once for the nonce that encrypts the
// label. Every one of those has an error return, and continuing past any of
// them would store a row the service cannot honor: a blob keyed by an empty
// ID, or a label sitting in the clear in a column the schema treats as
// ciphertext. These tests starve the entropy source at each point and pin that
// the upload fails closed with nothing written and nothing handed back.

// The ID is minted before encryption because it is part of the AAD. Failing
// here must abort before any ciphertext exists, so no row and no quota
// consumption.
func TestBlobUploadBlobIDEntropyFailureStoresNothing(t *testing.T) {
	var created atomic.Bool
	repo := &mockBlobRepo{
		createFn: func(context.Context, *model.Blob) error {
			created.Store(true)
			return nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	serviceAuthStarveEntropy(t, 0)

	blob, err := svc.Upload(context.Background(), "user-1", []byte("payload"), "holiday-photos")

	if !errors.Is(err, errServiceAuthEntropy) {
		t.Fatalf("err = %v, want the entropy failure to surface", err)
	}
	if !strings.Contains(err.Error(), "blob uuid") {
		t.Errorf("err = %v, want it to name the blob ID generation step", err)
	}
	if blob != nil {
		t.Error("an upload result was returned without a blob ID")
	}
	if created.Load() {
		t.Error("a blob row was written after the blob ID generation failed")
	}
}

// The label nonce is the last draw, so the ID and the payload ciphertext both
// exist by the time it fails. Storing the blob anyway would persist a row whose
// LabelEnc is empty while the caller believes the label was encrypted.
func TestBlobUploadLabelEntropyFailureStoresNothing(t *testing.T) {
	var created atomic.Bool
	repo := &mockBlobRepo{
		createFn: func(context.Context, *model.Blob) error {
			created.Store(true)
			return nil
		},
	}
	svc := NewBlobService(repo, testKey, testHMAC, defaultBlobConfig())

	const label = "tax-return-2025"

	serviceAuthStarveEntropy(t, 2)

	blob, err := svc.Upload(context.Background(), "user-1", []byte("payload"), label)

	if !errors.Is(err, errServiceAuthEntropy) {
		t.Fatalf("err = %v, want the entropy failure to surface", err)
	}
	if !strings.Contains(err.Error(), "blob label encrypt") {
		t.Errorf("err = %v, want it to name the label encryption step", err)
	}
	if strings.Contains(err.Error(), label) {
		t.Errorf("err = %v, want the plaintext label kept out of the error", err)
	}
	if blob != nil {
		t.Error("an upload result was returned with an unencrypted label")
	}
	if created.Load() {
		t.Error("a blob row was written after the label encryption failed")
	}
}
