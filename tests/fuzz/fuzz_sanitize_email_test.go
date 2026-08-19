package fuzz

import (
	"net/mail"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/sanitize"
)

// FuzzSanitizeEmail is the tests/fuzz entry the CI "Fuzz Tests" job will run.
// It exercises the real sanitiser, internal/sanitize.Email, which is what
// internal/service/auth.go:413 calls.
//
// It replaced fuzz_email_test.go rather than sitting beside it. That file
// fuzzed a local isValidEmail defined in the same file, under a comment reading
// "same logic as service/auth.go" -- an equivalence nothing enforced and which
// was not even true, because auth.go has never had an isValidEmail and has
// always delegated to sanitize.Email. Its only assertion was that the local copy
// did not panic, so it added a green tick to the fuzz suite while exercising no
// shipped code. TestEveryFuzzTargetReachesShippedCode in tests/spec holds the
// property now, for every target rather than this one.
func FuzzSanitizeEmail(f *testing.F) {
	f.Add("user@example.com")
	f.Add("")
	f.Add("deleted-3f2504e0-4f89-11d3-9a0c-0305e82c3301@deleted.invalid")
	f.Add("user@Deleted.Invalid")
	f.Add("admin <attacker@evil.com>")
	f.Add(`"quoted"@example.com`)
	f.Add("üser@example.com")
	f.Add("user@xn--n3h.com")
	f.Add("deleted-user@example.com")
	f.Add("\x00@example.com")

	f.Fuzz(func(t *testing.T, email string) {
		ok := sanitize.Email(email)
		if at := strings.LastIndexByte(email, '@'); at >= 0 &&
			strings.EqualFold(email[at+1:], "deleted.invalid") && ok {
			t.Fatalf("tombstone-domain address accepted: %q", email)
		}
		if !ok {
			return
		}
		addr, err := mail.ParseAddress(email)
		if err != nil || addr.Address != email {
			t.Fatalf("Email(%q) = true but is not exactly an RFC 5322 address (extracted %v, err %v)", email, addr, err)
		}
	})
}
