package service

import (
	"errors"
	"strings"
	"testing"
)

// The blob AAD namespaces are not prefix-free, and this pins the invariant that
// makes that safe.
//
// blobDataAAD is "<id>:<pseudonym>" and blobLabelAAD is
// "label:<id>:<pseudonym>". A blob whose id were literally "label:X" therefore
// produces the same AAD as the LABEL of blob "X", and AES-GCM would accept a
// label ciphertext in place of a data ciphertext.
//
// Nothing can reach that today, because ids come from RandomUUID and a UUID has
// no colon. That was a real guarantee held incidentally: no comment stated it
// and no test checked it, so a later change to id generation, or an id read back
// from a row someone else wrote, would have reopened it silently.
//
// The AAD format is deliberately not being fixed. A length-prefixed or
// domain-tagged encoding is the better construction, and switching to one now
// would make every blob already stored undecryptable, which is worse than a
// weakness that cannot be reached.
func TestBlobAADNamespacesCannotCollide(t *testing.T) {
	const pseudo = "pseudo-1"

	// The collision the construction would otherwise permit.
	dataOfNastyID, err := blobDataAAD("label:X", pseudo)
	if err == nil {
		labelOfX, lerr := blobLabelAAD("X", pseudo)
		if lerr != nil {
			t.Fatalf("blobLabelAAD: %v", lerr)
		}
		if string(dataOfNastyID) == string(labelOfX) {
			t.Fatalf("a blob id of %q produces the same AAD as the label of blob %q: %q",
				"label:X", "X", dataOfNastyID)
		}
	}
	if !errors.Is(err, errBlobIDNamespace) {
		t.Errorf("blobDataAAD(%q) error = %v, want errBlobIDNamespace", "label:X", err)
	}

	if _, err := blobLabelAAD("label:X", pseudo); !errors.Is(err, errBlobIDNamespace) {
		t.Errorf("blobLabelAAD(%q) error = %v, want errBlobIDNamespace", "label:X", err)
	}
}

// A plain colon anywhere in the id is enough to make the two namespaces
// ambiguous, so the guard rejects the character rather than the one prefix that
// happens to be exploitable today.
func TestBlobAADRejectsAnyColonInTheID(t *testing.T) {
	for _, id := range []string{":", "a:b", "label:", "0f8e:1234", strings.Repeat("x", 8) + ":"} {
		if _, err := blobDataAAD(id, "p"); !errors.Is(err, errBlobIDNamespace) {
			t.Errorf("blobDataAAD(%q) was accepted; the separator makes the namespaces ambiguous", id)
		}
	}
}

// The normal shape must still work, byte for byte as before, because changing
// the AAD would orphan every blob already encrypted under the old one.
func TestBlobAADFormatIsUnchangedForRealIDs(t *testing.T) {
	const (
		id     = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
		pseudo = "b8f1c2"
	)
	data, err := blobDataAAD(id, pseudo)
	if err != nil {
		t.Fatalf("blobDataAAD: %v", err)
	}
	if got, want := string(data), id+":"+pseudo; got != want {
		t.Errorf("data AAD = %q, want %q; changing this orphans every stored blob", got, want)
	}

	label, err := blobLabelAAD(id, pseudo)
	if err != nil {
		t.Fatalf("blobLabelAAD: %v", err)
	}
	if got, want := string(label), "label:"+id+":"+pseudo; got != want {
		t.Errorf("label AAD = %q, want %q; changing this orphans every stored label", got, want)
	}
}
