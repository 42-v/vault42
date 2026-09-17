package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// A capital letter must not cost a user their reset link.
//
// Every other path folds before it queries -- Register, Login, the OAuth
// callback, admin import -- so auth.users.email only ever holds a folded
// address, and GetByEmail is an exact match. ResetRequest passed its input
// through raw, so "Alice@example.com" from a phone keyboard, or a pasted
// address with a trailing space, missed the row.
//
// Nothing surfaced it. The route answers "if that email exists, a reset link
// has been sent" either way, which is the correct anti-enumeration behavior
// and is exactly what hid this: no mail queued, no audit row, and the user
// shown success. The person it happens to is the one locked out by the
// failed-login counter, for whom this route is the documented way back in.

func TestResetRequestFoldsTheAddressBeforeLookingItUp(t *testing.T) {
	for _, spelling := range []string{
		"rider@example.test",
		"Rider@example.test",
		"RIDER@EXAMPLE.TEST",
		"  rider@example.test  ",
	} {
		t.Run(spelling, func(t *testing.T) {
			var queried string
			users := &mocks.MockUserRepo{
				GetByEmailFn: func(_ context.Context, e string) (*model.User, error) {
					queried = e
					if e != "rider@example.test" {
						// The row only exists under the folded spelling.
						return nil, nil
					}
					return &model.User{ID: "u-1", Email: e}, nil
				},
			}
			h := NewPasswordHandler(
				users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
				&mocks.MockEmailSender{}, newTestAuditLogger(), &mocks.MockCache{},
				"https://vault.test", "TestVault", "", 15, nil, false,
			)

			// Verbatim, spaces and all. Trimming the spelling here to build the
			// body is what let a no-trim version of the fix pass: the
			// whitespace case sent an already-clean address and proved nothing.
			body := strings.NewReader(`{"email":"` + spelling + `"}`)
			req := httptest.NewRequest(http.MethodPost, "/auth/password/reset", body)
			rec := httptest.NewRecorder()
			h.ResetRequest(rec, req)

			if queried != "rider@example.test" {
				t.Errorf("GetByEmail was called with %q; the column only holds folded addresses, "+
					"so anything else silently matches nothing and the user is told a link was "+
					"sent that was never queued", queried)
			}
			// The response is deliberately identical either way. Asserting it
			// here records that the fix did not turn this route into an
			// enumeration oracle by starting to answer differently.
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
		})
	}
}
