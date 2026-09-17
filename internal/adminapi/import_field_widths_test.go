package adminapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Nothing on this endpoint checked a field against the column it is written to.
//
// The 64 KiB admin body cap and the 1000-record batch limit were the only bounds
// applied. Three fields go straight into narrower columns:
//
//	source      -> auth.users.imported_from  VARCHAR(64)   (migration 006)
//	locale      -> auth.users.locale         VARCHAR(10)   (migration 001)
//	ban_reason  -> auth.users.ban_reason     VARCHAR(500)  (migration 004)
//
// PostgreSQL answers an over-long value with 22001 and fails the whole INSERT.
// The loop catches each record's failure on its own and keeps going, so the
// endpoint returns 200 OK with "imported": 0 and a thousand identical
// "create_failed" rows. Nothing in that response names the field, and `source`
// is the worst of the three because it is written to EVERY row: one bad batch
// tag looks exactly like a thousand bad records.
//
// The repository mock cannot reproduce 22001 -- it never touches a column -- so
// these tests assert the thing that is actually in this handler's gift: what it
// hands to CreateImported, and what it answers before it gets there.

func TestImportUsers_SourceLongerThanItsColumnIsRefusedForTheWholeBatch(t *testing.T) {
	var created []*model.User
	h := importHandler(&mocks.MockUserRepo{
		GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(_ context.Context, u *model.User) error { created = append(created, u); return nil },
	})

	body := `{"source":"` + strings.Repeat("l", maxImportSourceLen+1) + `","users":[
		{"email":"one@legacy.test"},
		{"email":"two@legacy.test"}
	]}`
	rec, _ := doImport(t, h, body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400. A batch-wide tag that cannot be stored is a bad request, "+
			"not a thousand bad records: answering 200 with imported=0 and create_failed on every "+
			"row tells the operator their data is wrong when the one field they typed is.", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "source_too_long") {
		t.Errorf("body = %s, want an error naming the field", rec.Body.String())
	}
	if len(created) != 0 {
		t.Errorf("%d accounts were created before the batch was refused; the refusal must come "+
			"before the loop or it is not a refusal", len(created))
	}
}

func TestImportUsers_SourceExactlyItsColumnWidthIsAccepted(t *testing.T) {
	var created []*model.User
	h := importHandler(&mocks.MockUserRepo{
		GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(_ context.Context, u *model.User) error { created = append(created, u); return nil },
	})

	source := strings.Repeat("l", maxImportSourceLen)
	rec, _ := doImport(t, h, `{"source":"`+source+`","users":[{"email":"one@legacy.test"}]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a tag the column holds exactly must not be refused", rec.Code)
	}
	if len(created) != 1 || created[0].ImportedFrom != source {
		t.Fatalf("imported_from was not written through intact: %+v", created)
	}
}

// VARCHAR(n) counts characters, so the bound is on runes. A byte-length check
// would refuse a 64-character tag written in a script PostgreSQL would have
// stored without complaint -- correct for a truncating clamp, wrong for a
// refusal.
func TestImportUsers_SourceIsBoundedInCharactersNotBytes(t *testing.T) {
	var created []*model.User
	h := importHandler(&mocks.MockUserRepo{
		GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(_ context.Context, u *model.User) error { created = append(created, u); return nil },
	})

	// 64 characters, 128 bytes.
	source := strings.Repeat("é", maxImportSourceLen)
	rec, _ := doImport(t, h, `{"source":"`+source+`","users":[{"email":"one@legacy.test"}]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %d characters fit VARCHAR(%d) whatever they weigh in bytes",
			rec.Code, maxImportSourceLen, maxImportSourceLen)
	}
	if len(created) != 1 {
		t.Fatalf("expected the record to be created, got %d", len(created))
	}
}

func TestImportUsers_PerRecordFieldsAreClampedToTheirColumns(t *testing.T) {
	var created []*model.User
	h := importHandler(&mocks.MockUserRepo{
		GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(_ context.Context, u *model.User) error { created = append(created, u); return nil },
	})

	body := `{"source":"legacy","users":[
		{"email":"long@legacy.test","banned":true,"ban_reason":"` + strings.Repeat("r", maxImportBanReasonLen+50) + `"},
		{"email":"loud@legacy.test","locale":"` + strings.Repeat("x", 40) + `"},
		{"email":"weird@legacy.test","locale":"en; DROP"},
		{"email":"fine@legacy.test","locale":"sk-SK","banned":true,"ban_reason":"spam"}
	]}`
	rec, _ := doImport(t, h, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a per-record field is clamped, not a reason to refuse the batch", rec.Code)
	}
	if len(created) != 4 {
		t.Fatalf("expected 4 CreateImported calls, got %d", len(created))
	}

	if n := len([]rune(created[0].BanReason)); n > maxImportBanReasonLen {
		t.Errorf("ban_reason went through at %d characters against a VARCHAR(%d) column, so this "+
			"record fails with 22001 and is reported as a generic create_failed", n, maxImportBanReasonLen)
	}
	if created[0].BanReason == "" {
		t.Error("ban_reason was emptied rather than clamped; the reason an account was banned is " +
			"the thing an operator reads later")
	}

	// sanitize.Locale is the clamp the two other write paths use. Anything it
	// does not recognize as a language tag becomes "en" rather than a row the
	// column refuses.
	for i, want := range map[int]string{1: "en", 2: "en", 3: "sk-sk"} {
		if created[i].Locale != want {
			t.Errorf("record %d locale = %q, want %q", i, created[i].Locale, want)
		}
	}
	if n := len(created[1].Locale); n > 10 {
		t.Errorf("locale is %d characters against VARCHAR(10)", n)
	}
}

// An absent locale still has to come out as something the column accepts. This
// used to be handled by a bare `if locale == ""` in the handler; sanitize.Locale
// subsumes it, and the behavior has to survive the swap.
func TestImportUsers_AbsentLocaleStillDefaults(t *testing.T) {
	var created []*model.User
	h := importHandler(&mocks.MockUserRepo{
		GetByEmailFn:     func(_ context.Context, _ string) (*model.User, error) { return nil, nil },
		CreateImportedFn: func(_ context.Context, u *model.User) error { created = append(created, u); return nil },
	})

	rec, _ := doImport(t, h, `{"source":"legacy","users":[{"email":"bare@legacy.test"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(created) != 1 || created[0].Locale != "en" {
		t.Fatalf("locale = %q, want the default: the column is NOT NULL", created[0].Locale)
	}
}
