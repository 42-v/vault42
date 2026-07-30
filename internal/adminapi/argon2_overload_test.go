package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Every gateway endpoint that mints a credential hashes it with argon2id, and
// argon2id refuses work when its semaphore is full rather than let four
// concurrent 46 MiB derivations OOM the pod. These tests hold the semaphore at
// capacity for real and pin what the credential-minting endpoints do when the
// hash they need cannot be produced: fail closed with 500 internal_error, write
// nothing, and hand back no secret. A client persisted with an empty or
// unhashed secret would be a credential an attacker can predict, and a
// half-created admin account is the worst outcome this gateway has.

// adminapiArgon2Holder parks the first limit reads until release is closed and
// serves real entropy to every read after that. A parked read is a HashPassword
// call sitting inside the argon2 semaphore holding its slot on a channel
// instead of burning CPU, while the handler under test still draws the random
// material it needs before it reaches its own hash.
type adminapiArgon2Holder struct {
	release chan struct{}
	limit   int32
	seen    atomic.Int32
	parked  atomic.Int32
}

func (h *adminapiArgon2Holder) Read(p []byte) (int, error) {
	if h.seen.Add(1) <= h.limit {
		h.parked.Add(1)
		<-h.release
	}
	return adminapiRandReal.Read(p)
}

// adminapiSaturateArgon2 fills every argon2 semaphore slot and keeps it full
// until the test ends.
func adminapiSaturateArgon2(t *testing.T) {
	t.Helper()

	slots := vaultcrypto.Argon2MaxConcurrent()
	holder := &adminapiArgon2Holder{release: make(chan struct{}), limit: int32(slots)}
	adminapiRandUse(t, holder)

	var wg sync.WaitGroup
	for i := 0; i < slots; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = vaultcrypto.HashPassword("hold-an-argon2-slot")
		}()
	}
	// Registered after adminapiRandUse, so LIFO cleanup releases the parked
	// readers and drains the goroutines before the entropy source is restored.
	t.Cleanup(func() {
		close(holder.release)
		wg.Wait()
	})

	deadline := time.Now().Add(30 * time.Second)
	for holder.parked.Load() < int32(slots) || vaultcrypto.Argon2ActiveCount() < int64(slots) {
		if time.Now().After(deadline) {
			t.Fatal("argon2 semaphore never reached capacity")
		}
		time.Sleep(time.Millisecond)
	}
}

func adminapiErrorCode(t *testing.T, body string) string {
	t.Helper()
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode error body %q: %v", body, err)
	}
	return payload.Error
}

// adminapiOverloadWrites records the writes that must not happen when a
// credential cannot be hashed.
type adminapiOverloadWrites struct {
	clientCreated atomic.Bool
	clientUpdated atomic.Bool
}

func TestCredentialEndpointsWriteNothingWhenArgon2IsOverloaded(t *testing.T) {
	const storedHash = "$argon2id$v=19$m=47104,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	writes := &adminapiOverloadWrites{}
	rotated := &model.Client{ID: "cli-1", Name: "billing", SecretHash: storedHash, Active: true}
	admins := newFakeAdminRepo()

	createClient := &Handler{
		clients: &mocks.MockClientRepo{
			CreateFn: func(context.Context, *model.Client) error {
				writes.clientCreated.Store(true)
				return nil
			},
		},
		auditLog: testAuditLog(),
	}
	rotateClient := &Handler{
		clients: &mocks.MockClientRepo{
			GetByIDFn: func(context.Context, string) (*model.Client, error) { return rotated, nil },
			UpdateFn: func(context.Context, *model.Client) error {
				writes.clientUpdated.Store(true)
				return nil
			},
		},
		auditLog: testAuditLog(),
	}
	createAdmin := newTestHandler(admins, nil, nil, nil)

	rotateReq := withActor(jsonReq(http.MethodPost, "/admin/clients/cli-1/rotate", ""))
	rotateReq.SetPathValue("id", "cli-1")

	cases := []struct {
		name   string
		rec    *httptest.ResponseRecorder
		invoke func(rec *httptest.ResponseRecorder)
		secret string
	}{
		{
			name: "create client",
			rec:  httptest.NewRecorder(),
			invoke: func(rec *httptest.ResponseRecorder) {
				createClient.CreateClient(rec, withActor(jsonReq(http.MethodPost, "/admin/clients",
					`{"name":"billing","role":"service"}`)))
			},
			secret: "secret",
		},
		{
			name: "rotate client secret",
			rec:  httptest.NewRecorder(),
			invoke: func(rec *httptest.ResponseRecorder) {
				rotateClient.RotateClientSecret(rec, rotateReq)
			},
			secret: "secret",
		},
		{
			name: "create admin",
			rec:  httptest.NewRecorder(),
			invoke: func(rec *httptest.ResponseRecorder) {
				createAdmin.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins",
					`{"username":"newadmin","password":"aVeryLongPassword12345","role":"viewer"}`)))
			},
			secret: "password",
		},
	}

	adminapiSaturateArgon2(t)

	var wg sync.WaitGroup
	for _, tc := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc.invoke(tc.rec)
		}()
	}
	wg.Wait()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.rec.Body.String()
			if tc.rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 (body: %s)", tc.rec.Code, body)
			}
			if code := adminapiErrorCode(t, body); code != "internal_error" {
				t.Errorf("error = %q, want internal_error", code)
			}
			if adminapiBodyHasField(t, body, tc.secret) {
				t.Errorf("the failure response carried a %s field: %s", tc.secret, body)
			}
		})
	}

	if writes.clientCreated.Load() {
		t.Error("a client was persisted while argon2 was rejecting work, so its secret hash could not have covered the secret handed out")
	}
	if writes.clientUpdated.Load() {
		t.Error("the client record was updated even though the replacement secret was never hashed")
	}
	if rotated.SecretHash != storedHash {
		t.Errorf("stored secret hash changed to %q during a rotation that failed", rotated.SecretHash)
	}
	if len(admins.users) != 0 {
		t.Error("a privileged admin account was created without a password hash")
	}
}
