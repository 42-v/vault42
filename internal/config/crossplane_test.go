package config

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// The failure this file holds shut is not a crash. Two planes configured with
// different HMAC secrets derive different subject pseudonyms, an admin erasure
// clears zero rows from the three pseudonym-keyed stores, and it reports
// success. Everything below exists so that configuration cannot reach that
// state unnoticed.

// fakeClaimStore is auth.admin_config reduced to the one operation the check
// uses, with the claim semantics the real statement has: the first value wins
// and every later caller is handed the incumbent.
type fakeClaimStore struct {
	mu     sync.Mutex
	values map[string]string
	err    error
	claims int
}

func newClaimStore() *fakeClaimStore {
	return &fakeClaimStore{values: map[string]string{}}
}

func (s *fakeClaimStore) ClaimIfAbsent(_ context.Context, key, value string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims++
	if s.err != nil {
		return "", s.err
	}
	if existing, ok := s.values[key]; ok {
		return existing, nil
	}
	s.values[key] = value
	return value, nil
}

const (
	secretA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secretB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// The fingerprint is what crosses the plane boundary, so it must reveal nothing
// about the secret and must still separate two secrets that differ.
func TestTheFingerprintSeparatesSecretsWithoutCarryingThem(t *testing.T) {
	a := HMACSecretFingerprint([]byte(secretA))
	b := HMACSecretFingerprint([]byte(secretB))

	if a == b {
		t.Fatal("two different secrets fingerprinted identically; the check would pass on divergence")
	}
	if a != HMACSecretFingerprint([]byte(secretA)) {
		t.Fatal("the fingerprint is not stable for one secret; every boot would report a mismatch")
	}
	if strings.Contains(a, secretA) || strings.Contains(a, secretA[:8]) {
		t.Fatalf("the fingerprint %q carries the secret it was derived from", a)
	}
	if len(a) != hmacFingerprintHexLen {
		t.Errorf("fingerprint length = %d, want %d hex characters", len(a), hmacFingerprintHexLen)
	}
	// A single differing byte has to change it, or a truncated or padded secret
	// file would fingerprint the same as the intended one.
	if HMACSecretFingerprint([]byte(secretA)) == HMACSecretFingerprint([]byte(secretA+"x")) {
		t.Error("appending a byte to the secret left the fingerprint unchanged")
	}
}

func TestAgreeingPlanesPass(t *testing.T) {
	store := newClaimStore()

	if err := VerifyHMACPlaneAgreement(context.Background(), store, []byte(secretA)); err != nil {
		t.Fatalf("first plane to record its fingerprint was rejected: %v", err)
	}
	if err := VerifyHMACPlaneAgreement(context.Background(), store, []byte(secretA)); err != nil {
		t.Fatalf("second plane with the same secret was rejected: %v", err)
	}
	if got := store.values[HMACFingerprintKey]; got != HMACSecretFingerprint([]byte(secretA)) {
		t.Errorf("recorded value = %q, want the fingerprint", got)
	}
}

// The defect itself. Before this check, this configuration produced a
// "successful" erasure that cleared nothing.
func TestDivergingPlanesAreRejected(t *testing.T) {
	store := newClaimStore()

	if err := VerifyHMACPlaneAgreement(context.Background(), store, []byte(secretA)); err != nil {
		t.Fatalf("the first plane was rejected: %v", err)
	}

	err := VerifyHMACPlaneAgreement(context.Background(), store, []byte(secretB))
	if err == nil {
		t.Fatal("a plane holding a different HMAC secret was accepted; erasure would clear zero rows and report success")
	}
	if !errors.Is(err, ErrHMACPlaneMismatch) {
		t.Fatalf("error does not identify a mismatch, so a caller cannot tell it from a broken store: %v", err)
	}
	// The operator has to be able to act on this without being handed a secret.
	msg := err.Error()
	for _, want := range []string{
		HMACSecretFingerprint([]byte(secretA)),
		HMACSecretFingerprint([]byte(secretB)),
		"HMAC_SECRET_FILE",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not mention %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, secretA) || strings.Contains(msg, secretB) {
		t.Fatalf("the mismatch message leaks a secret: %s", msg)
	}
}

// An absent secret is the fail-safe case: cmd/vault refuses to start without
// one, and the gateway leaves erasure returning 503. The check must not turn
// that into a boot failure, and must not record a fingerprint of nothing —
// HMAC with an empty key is a perfectly valid value that every secret-less
// deployment would agree on.
func TestAnAbsentSecretIsNotCheckedAndRecordsNothing(t *testing.T) {
	store := newClaimStore()

	if err := VerifyHMACPlaneAgreement(context.Background(), store, nil); err != nil {
		t.Fatalf("an absent secret was treated as a disagreement: %v", err)
	}
	if store.claims != 0 {
		t.Errorf("the store was written to %d times with no secret to record", store.claims)
	}
}

// A store that cannot answer must be distinguishable from a store that
// answered with a disagreement: the callers make different decisions about
// them, and conflating the two would make a database hiccup fatal or a
// mismatch survivable.
func TestAnUnreadableStoreIsNotReportedAsAMismatch(t *testing.T) {
	store := newClaimStore()
	store.err = errors.New("relation does not exist")

	err := VerifyHMACPlaneAgreement(context.Background(), store, []byte(secretA))
	if err == nil {
		t.Fatal("a store that could not answer was reported as agreement")
	}
	if errors.Is(err, ErrHMACPlaneMismatch) {
		t.Fatal("a store failure was reported as a mismatch; a database hiccup would kill the gateway")
	}
	if !strings.Contains(err.Error(), "relation does not exist") {
		t.Errorf("the underlying store error was swallowed: %v", err)
	}
}
