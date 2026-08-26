package postgres

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// A long User-Agent used to delete the caller's own audit rows.
//
// Every user_agent column in the schema is VARCHAR(1024) and nothing truncated,
// so the header arrived verbatim and went straight into the statement. Past 1024
// characters PostgreSQL answers 22001 and, on the audit path, that is the whole
// row: the insert is synchronous by default, every call site discards the error
// as best-effort so authentication is never blocked by logging, and no metric
// counts it. An unauthenticated caller could therefore erase their own trail
// from an append-only log by setting a long header -- a credential-stuffing run
// leaving no login_failure rows behind it.
//
// Detection survives, which caps the severity: audit.Logger runs its observers
// on the entry before the insert, so alerting and the anomaly detector still
// fire on an event whose row never lands. What is lost is the record afterwards.

func TestClampUserAgent(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  int // expected rune count
		exact string
	}{
		{"short is untouched", "curl/8.4.0", 10, "curl/8.4.0"},
		{"empty is untouched", "", 0, ""},
		{"exactly at the limit", strings.Repeat("a", 1024), 1024, ""},
		{"one over", strings.Repeat("a", 1025), 1024, ""},
		{"the 2000-byte probe", strings.Repeat("A", 2000), 1024, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clampUserAgent(tc.in)
			if n := utf8.RuneCountInString(got); n != tc.want {
				t.Fatalf("rune count = %d, want %d", n, tc.want)
			}
			if tc.exact != "" && got != tc.exact {
				t.Fatalf("got %q, want %q", got, tc.exact)
			}
		})
	}
}

// Runes, not bytes. PostgreSQL counts VARCHAR(n) in characters, so a byte slice
// would cut in the wrong place -- and would split a multi-byte rune, handing the
// driver invalid UTF-8 and turning a value-too-long into an encoding error. Same
// lost row, more confusing reason.
func TestClampUserAgent_DoesNotSplitARune(t *testing.T) {
	// Three bytes each, so 2000 of them is 6000 bytes and 2000 characters:
	// a byte-based clamp at 1024 would land inside the 342nd rune.
	ua := strings.Repeat("ééé", 700) // 2100 runes, 4200 bytes
	got := clampUserAgent(ua)

	if !utf8.ValidString(got) {
		t.Fatal("clamped to invalid UTF-8; a byte slice split a rune, and the driver will " +
			"refuse the value for a different reason than the one being fixed")
	}
	if n := utf8.RuneCountInString(got); n != 1024 {
		t.Fatalf("rune count = %d, want 1024 -- the column counts characters, not bytes", n)
	}
	if len(got) <= 1024 {
		t.Fatalf("byte length = %d; 1024 two-byte runes should exceed 1024 bytes, so this "+
			"test is not exercising the case it describes", len(got))
	}
}

// The gap between the two limits: more than 1024 BYTES but fewer than 1024
// characters. A byte-length check alone would truncate this, and the column
// would have accepted it whole -- so the fast path has to fall through to the
// rune count rather than deciding on len().
func TestClampUserAgent_LongInBytesButShortInRunes(t *testing.T) {
	// 600 three-byte runes: 1800 bytes, 600 characters. Comfortably over the
	// byte limit and comfortably under the character limit.
	ua := strings.Repeat("日", 600)
	if len(ua) <= userAgentColumn {
		t.Fatalf("byte length %d is not over the limit, so this test is not exercising "+
			"the case it describes", len(ua))
	}
	if n := utf8.RuneCountInString(ua); n >= userAgentColumn {
		t.Fatalf("rune count %d is not under the limit", n)
	}

	got := clampUserAgent(ua)
	if got != ua {
		t.Fatalf("a value the column accepts whole was truncated: %d runes in, %d out",
			utf8.RuneCountInString(ua), utf8.RuneCountInString(got))
	}
}

// The end of it: a row with an over-long agent now lands, against a real
// PostgreSQL with the real column.
func TestAuditRepo_AnOverLongUserAgentStillLands(t *testing.T) {
	svcDocRequireContainerRuntime(t)
	db := svcDocPostgres(t)
	repo := NewAuditRepo(db)
	ctx := context.Background()

	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}

	// Straight at the column first, so the constraint is shown rather than
	// assumed. If this ever succeeds the column widened and the clamp is
	// guarding something that no longer exists.
	_, rawErr := db.Pool.Exec(ctx,
		`INSERT INTO audit.audit_log (id, timestamp, event_type, user_agent) VALUES ($1, $2, $3, $4)`,
		id, time.Now(), "login_failure", strings.Repeat("A", 2000))
	if rawErr == nil {
		t.Fatal("a 2000-character user_agent was accepted by the column; the schema changed")
	}
	t.Logf("the column refuses it: %v", rawErr)

	if err := repo.Insert(ctx, &model.AuditEntry{
		ID:        id,
		Timestamp: time.Now(),
		EventType: "login_failure",
		IP:        "203.0.113.9",
		UserAgent: strings.Repeat("A", 2000),
		Metadata:  map[string]interface{}{"result": "failure"},
	}); err != nil {
		t.Fatalf("the repository did not rescue the row: %v. An unauthenticated caller can "+
			"still erase their own audit trail with a long header.", err)
	}

	var stored string
	if err := db.Pool.QueryRow(ctx,
		`SELECT user_agent FROM audit.audit_log WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n := utf8.RuneCountInString(stored); n != 1024 {
		t.Fatalf("stored user_agent is %d characters, want 1024", n)
	}
}
