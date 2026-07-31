package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// adminapiFailingRows is a pgx.Rows that yields one row and then fails to decode
// it, the shape a driver takes when a column does not match what the repository
// expects (schema drift, a partially applied migration, a corrupted value).
type adminapiFailingRows struct {
	served  bool
	scanErr error
}

func (r *adminapiFailingRows) Close()                                       {}
func (r *adminapiFailingRows) Err() error                                   { return nil }
func (r *adminapiFailingRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *adminapiFailingRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *adminapiFailingRows) Values() ([]any, error)                       { return nil, nil }
func (r *adminapiFailingRows) RawValues() [][]byte                          { return nil }
func (r *adminapiFailingRows) Conn() *pgx.Conn                              { return nil }

func (r *adminapiFailingRows) Next() bool {
	if r.served {
		return false
	}
	r.served = true
	return true
}

func (r *adminapiFailingRows) Scan(...any) error { return r.scanErr }

// The admin list is the answer to "who holds privileged access to this vault".
// A row the driver cannot decode must abort the whole listing: dropping the bad
// row and returning the rest would hide an admin account from the operator
// reviewing access, and nothing anywhere would say a row went missing.
func TestScanAdminUserRow_SurfacesADecodeFailure(t *testing.T) {
	repo := &AdminUserRepo{}
	boom := errors.New("cannot scan NULL into *string")

	got, err := repo.scanAdminUserRow(&adminapiFailingRows{scanErr: boom})

	if err == nil {
		t.Fatal("a row that could not be decoded was reported as a valid admin user")
	}
	if got != nil {
		t.Error("a partially decoded admin user was returned alongside the error")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want the driver failure wrapped", err)
	}
	if !strings.Contains(err.Error(), "scan admin user row") {
		t.Errorf("error = %q, want it to name the failing operation", err)
	}
}

// ListActive is what an operator reads while cutting off a compromised admin
// session. A session that silently fell out of the list because its row failed
// to decode is a session they will never revoke, so the failure has to reach
// them instead of a shorter list that looks complete.
func TestScanSessions_SurfacesADecodeFailure(t *testing.T) {
	repo := &AdminSessionRepo{}
	boom := errors.New("cannot scan NULL into *string")

	got, err := repo.scanSessions(&adminapiFailingRows{scanErr: boom})

	if err == nil {
		t.Fatal("a session row that could not be decoded was silently dropped from the list")
	}
	if got != nil {
		t.Error("a truncated session list was returned alongside the error")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want the driver failure wrapped", err)
	}
	if !strings.Contains(err.Error(), "scan admin session") {
		t.Errorf("error = %q, want it to name the failing operation", err)
	}
}
