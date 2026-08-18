package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// adminapiBrokenEntropy hands out okBytes of deterministic bytes and then reports
// the system CSPRNG as unavailable. Setting okBytes lets a test choose which of a
// handler's successive random draws is the one that fails.
type adminapiBrokenEntropy struct {
	remaining int
}

func (r *adminapiBrokenEntropy) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("entropy source unavailable")
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 0x42
	}
	r.remaining -= n
	return n, nil
}

// adminapiBreakEntropy replaces the process CSPRNG for the duration of one test.
// The swap goes through the atomic switch installed by TestMain, so a goroutine
// that outlives the test never observes a torn write to crypto/rand.Reader.
func adminapiBreakEntropy(t *testing.T, okBytes int) {
	t.Helper()
	adminapiRandUse(t, &adminapiBrokenEntropy{remaining: okBytes})
}

func adminapiBodyHasField(t *testing.T, body, field string) bool {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return false
	}
	_, ok := payload[field]
	return ok
}

// A client credential whose ID or secret came from a degraded CSPRNG is a
// guessable credential. The gateway must abandon the whole creation rather than
// fall back to whatever bytes it managed to get: a half-random client secret that
// was still persisted would authenticate forever.
func TestCreateClient_EntropyFailureCreatesNothing(t *testing.T) {
	tests := []struct {
		name    string
		okBytes int
	}{
		{"id draw fails", 0},
		{"secret draw fails", 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created := false
			h := &Handler{
				clients: &mocks.MockClientRepo{
					CreateFn: func(context.Context, *model.Client) error {
						created = true
						return nil
					},
				},
				auditLog: testAuditLog(),
			}

			rec := httptest.NewRecorder()
			req := withActor(jsonReq(http.MethodPost, "/admin/clients", `{"name":"billing","role":"service"}`))

			adminapiBreakEntropy(t, tt.okBytes)
			h.CreateClient(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
			}
			if created {
				t.Error("a service client was persisted after the CSPRNG failed — its credentials would be built from degraded entropy")
			}
			if adminapiBodyHasField(t, rec.Body.String(), "secret") {
				t.Errorf("the failure response carried a client secret: %s", rec.Body.String())
			}
		})
	}
}

// Rotation replaces a credential that is presumed compromised. If the new secret
// cannot be drawn, the rotation must not be recorded at all: writing a hash of a
// low-entropy secret would leave the client authenticating with a value an
// attacker can search, and the operator believing rotation succeeded.
func TestRotateClientSecret_EntropyFailureLeavesTheOldSecretInPlace(t *testing.T) {
	const originalHash = "$argon2id$v=19$m=47104,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	updated := false
	h := &Handler{
		clients: &mocks.MockClientRepo{
			GetByIDFn: func(context.Context, string) (*model.Client, error) {
				return &model.Client{ID: "cli-1", Name: "billing", SecretHash: originalHash}, nil
			},
			UpdateFn: func(context.Context, *model.Client) error {
				updated = true
				return nil
			},
		},
		auditLog: testAuditLog(),
	}

	rec := httptest.NewRecorder()
	req := withActor(jsonReq(http.MethodPost, "/admin/clients/cli-1/rotate", ""))
	req.SetPathValue("id", "cli-1")

	adminapiBreakEntropy(t, 0)
	h.RotateClientSecret(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
	}
	if updated {
		t.Error("the client record was updated after the CSPRNG failed — the stored hash would cover a secret drawn from degraded entropy")
	}
	if adminapiBodyHasField(t, rec.Body.String(), "secret") {
		t.Errorf("the failure response carried a secret: %s", rec.Body.String())
	}
}

// A new admin account is the most privileged object this service creates. Its ID
// is the subject of every audit record written about it, so a degraded draw must
// abort before the account exists rather than produce an account whose identifier
// might collide with another.
func TestCreateAdmin_EntropyFailureCreatesNoAccount(t *testing.T) {
	repo := newFakeAdminRepo()
	h := newTestHandler(repo, nil, nil, nil)

	rec := httptest.NewRecorder()
	body := `{"username":"newadmin","password":"aVeryLongPassword12345","role":"viewer"}`
	req := withActor(jsonReq(http.MethodPost, "/admin/admins", body))

	adminapiBreakEntropy(t, 0)
	h.CreateAdmin(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
	}
	if len(repo.users) != 0 {
		t.Error("a privileged admin account was created after the CSPRNG failed")
	}
}

// The session token is the whole of the admin gateway's bearer authority. If the
// token or the session ID cannot be drawn, login must deny: issuing a session
// built on predictable bytes would hand an attacker the break-glass surface, and
// a 500 that still minted a session row would be worse than either.
func TestAdminLogin_EntropyFailureIssuesNoSession(t *testing.T) {
	tests := []struct {
		name    string
		okBytes int
	}{
		{"token draw fails", 0},
		{"session id draw fails", 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const password = "the-real-admin-password"
			hash, err := vaultcrypto.HashPassword(password, "")
			if err != nil {
				t.Fatalf("hash: %v", err)
			}

			admins := newFakeAdminRepo()
			admins.users["adm-1"] = &model.AdminUser{ID: "adm-1", Username: "root", PasswordHash: hash, Role: "super_admin"}
			sessions := newFakeSessionRepo()

			h := NewAuthHandler(admins, sessions, testAuditLog(), make([]byte, 32), "", time.Hour, 5, time.Hour)

			rec := httptest.NewRecorder()
			req := jsonReq(http.MethodPost, "/admin/auth/login", `{"username":"root","password":"`+password+`"}`)
			req.RemoteAddr = "203.0.113.7:4321"

			adminapiBreakEntropy(t, tt.okBytes)
			h.Login(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
			}
			if len(sessions.sessions) != 0 {
				t.Error("a session row was created even though the token could not be drawn from a healthy CSPRNG")
			}
			if adminapiBodyHasField(t, rec.Body.String(), "token") {
				t.Errorf("the failure response carried a session token: %s", rec.Body.String())
			}
		})
	}
}

// Enrolment persists the TOTP secret and only then shows it to the operator. A
// secret that could not be drawn properly must never reach the database: the
// admin would go on to bind an authenticator to it and treat a guessable second
// factor as protection.
func TestTOTPSetup_EntropyFailureStoresNoSecret(t *testing.T) {
	admins := newFakeAdminRepo()
	admin := &model.AdminUser{ID: "adm-1", Username: "root", Role: "super_admin"}
	admins.users["adm-1"] = admin

	h := newTestAuth(admins, nil)

	rec := httptest.NewRecorder()
	req := jsonReq(http.MethodPost, "/admin/admins/me/totp/setup", "")
	req = req.WithContext(WithAdmin(req.Context(), admin))

	adminapiBreakEntropy(t, 0)
	h.TOTPSetup(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
	}
	if admins.users["adm-1"].TOTPSecretEnc != "" {
		t.Error("a TOTP secret was persisted after the CSPRNG failed")
	}
	if adminapiBodyHasField(t, rec.Body.String(), "secret") {
		t.Errorf("the failure response carried a TOTP secret: %s", rec.Body.String())
	}
}

// EnsureFirstAdmin runs unattended at boot and prints the one credential that
// opens a fresh vault. If the CSPRNG is not healthy it must refuse to bootstrap:
// an account whose password came from a degraded draw, announced in the logs as
// the break-glass credential, is a vault that ships already compromised.
func TestEnsureFirstAdmin_EntropyFailureBootstrapsNothing(t *testing.T) {
	tests := []struct {
		name    string
		okBytes int
		wantErr string
	}{
		{"id draw fails", 0, "generate UUID"},
		{"password draw fails", 16, "generate password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newFakeAdminRepo()

			adminapiBreakEntropy(t, tt.okBytes)
			err := EnsureFirstAdmin(context.Background(), repo, newStoringAdminConfig(), "")

			if err == nil {
				t.Fatal("EnsureFirstAdmin reported success while the CSPRNG was unavailable")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to name the failed draw (%q)", err, tt.wantErr)
			}
			if len(repo.users) != 0 {
				t.Error("a bootstrap super_admin was created with material drawn from a broken CSPRNG")
			}
		})
	}
}

// Import creates accounts in bulk from a legacy system. A row whose ID could not
// be drawn must be reported as failed and skipped, not created: the batch result
// is what the operator reconciles against the source system, so a row counted as
// imported that never landed leaves an account silently missing forever.
func TestImportUsers_EntropyFailureSkipsTheRowAndSaysSo(t *testing.T) {
	createdAny := false
	h := &Handler{
		users: &mocks.MockUserRepo{
			GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
			CreateImportedFn: func(context.Context, *model.User) error {
				createdAny = true
				return nil
			},
		},
	}

	rec := httptest.NewRecorder()
	req := withActor(jsonReq(http.MethodPost, "/admin/users/import",
		`{"source":"legacy","users":[{"email":"a@example.com"}]}`))

	adminapiBreakEntropy(t, 0)
	h.ImportUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if createdAny {
		t.Error("an account was created with an ID the CSPRNG could not supply")
	}

	var got struct {
		Imported int `json:"imported"`
		Results  []struct {
			Email  string `json:"email"`
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Imported != 0 {
		t.Errorf("imported = %d, want 0 — the operator would reconcile against a count that never landed", got.Imported)
	}
	if len(got.Results) != 1 || got.Results[0].Status != "error" || got.Results[0].Error != "internal_error" {
		t.Errorf("results = %+v, want the row reported as an error", got.Results)
	}
}

// The template row's ID is drawn before the upsert. If that draw fails the write
// must not happen at all: PutEmailTemplate is an upsert, and a partially built
// row would replace the tenant's live verification mail with the caller's body
// under an identifier nothing else can address.
func TestPutEmailTemplate_EntropyFailureWritesNothing(t *testing.T) {
	repo := newFakeTemplateRepo()
	h := &Handler{
		emailTemplates:  repo,
		auditLog:        audit.NewLogger(&mocks.MockAuditRepo{}, 0),
		maxTemplateSize: 1 << 20,
	}

	body := `{"subject":"Verify your email","html_content":"<p>Hello {{.DisplayName}}</p>"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/email-templates/beon3/verification", strings.NewReader(body))
	req.SetPathValue("app", "beon3")
	req.SetPathValue("name", "verification")
	rec := httptest.NewRecorder()

	adminapiBreakEntropy(t, 0)
	h.PutEmailTemplate(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", rec.Code, rec.Body.String())
	}
	if len(repo.items) != 0 {
		t.Error("a template was written even though its ID could not be drawn")
	}
}
