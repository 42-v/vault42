package unit_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// blobClientCostlyHash is a PHC string at the parameter ceiling VerifyPassword
// accepts (128 MiB, 10 passes, 4 lanes). Verifying against it is valid but slow,
// which is how the test holds argon2 semaphore slots for a measurable time.
// blobClientCostlyHash builds the most expensive hash the parser will accept, so
// a handful of concurrent verifications saturate the four-slot semaphore.
//
// The memory figure is read from the parser's own ceiling rather than copied.
// It used to be the literal 128 MiB, and when argon2MaxVerifyMemory was lowered
// to 64 MiB this hash stopped being verifiable at all, so the test failed on its
// own fixture instead of on the behaviour it exists to check. Iterations and
// parallelism stay at their caps, so the hash remains far more expensive than
// any hash this product issues.
func blobClientCostlyHash() string {
	salt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 16))
	digest := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		vaultcrypto.Argon2MaxVerifyMemory(), 10, 4, salt, digest)
}

// blobClientTokenRequest builds a client-credentials request with Basic auth.
func blobClientTokenRequest(clientID, secret string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/client/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basicAuth(clientID, secret))
	return req
}

// Argon2id is capped at four concurrent hashes so a flood of logins cannot walk the
// process into an OOM kill. When that cap is hit, VerifyPassword refuses to run and
// returns ErrArgon2Overloaded, and every caller has to decide what that means.
//
// The client-credentials grant has three separate calls into the hasher: the dummy
// burn for an unknown client, the burn for a revoked client, and the real secret
// check. All three must answer 503 and shed the request. The failure that matters is
// the opposite one: treating "the hasher would not run" as "the secret did not match"
// (a valid client locked out during a load spike, indistinguishable from a bad
// secret) or, far worse, as "no error, carry on" (anyone authenticated while the
// server is busy).
//
// The three answers also have to be identical. If a shed unknown client looked
// different from a shed revoked one, load-shedding would become an oracle for which
// client IDs exist.
func TestClientToken_ArgonOverloadShedsEveryCredentialPath(t *testing.T) {
	const (
		clientID    = "client-backpressure"
		validSecret = "correct-client-secret"
		perScenario = 5
	)

	validHash, err := vaultcrypto.HashPassword(validSecret)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}

	costly := blobClientCostlyHash()
	probeStart := time.Now()
	if _, err := vaultcrypto.VerifyPassword("probe", costly); err != nil {
		t.Fatalf("costly hash is not verifiable: %v", err)
	}
	hashCost := time.Since(probeStart)
	if hashCost < time.Millisecond {
		t.Fatalf("costly hash verified in %v, too fast to saturate the semaphore", hashCost)
	}

	// Enough queued verifications that the four slots cannot drain the queue inside
	// the five second acquire timeout, doubled for headroom on a fast machine.
	wallSize := int(2 * 4 * 6 / hashCost.Seconds())
	if wallSize < 32 {
		wallSize = 32
	}
	if wallSize > 512 {
		wallSize = 512
	}

	activeClient := &model.Client{
		ID:         clientID,
		Name:       "backpressure-client",
		SecretHash: validHash,
		Role:       "frontend",
		Scopes:     []string{"user:read"},
		Active:     true,
	}
	revokedClient := *activeClient
	revokedClient.Active = false

	scenarios := []struct {
		name     string
		repo     *mocks.MockClientRepo
		clientID string
		secret   string
	}{
		{
			name: "unknown client",
			repo: &mocks.MockClientRepo{GetByIDFn: func(context.Context, string) (*model.Client, error) {
				return nil, nil
			}},
			clientID: "no-such-client",
			secret:   "any-secret",
		},
		{
			name: "revoked client",
			repo: &mocks.MockClientRepo{GetByIDFn: func(context.Context, string) (*model.Client, error) {
				c := revokedClient
				return &c, nil
			}},
			clientID: clientID,
			secret:   validSecret,
		},
		{
			name: "valid client",
			repo: &mocks.MockClientRepo{GetByIDFn: func(context.Context, string) (*model.Client, error) {
				return activeClient, nil
			}},
			clientID: clientID,
			secret:   validSecret,
		},
	}

	// Everything the requests need is built before the semaphore is saturated: RSA
	// key generation between waves would stagger the acquire deadlines and let the
	// later requests slip through as the earlier wave gives up.
	handlers := make([]*handler.ClientHandler, len(scenarios))
	results := make([][]*httptest.ResponseRecorder, len(scenarios))
	pending := make([][]*http.Request, len(scenarios))
	for i := range scenarios {
		handlers[i] = handler.NewClientHandler(scenarios[i].repo, newTestTokenService(t), newTestAuditLogger())
		results[i] = make([]*httptest.ResponseRecorder, perScenario)
		pending[i] = make([]*http.Request, perScenario)
		for j := 0; j < perScenario; j++ {
			results[i][j] = httptest.NewRecorder()
			pending[i][j] = blobClientTokenRequest(scenarios[i].clientID, scenarios[i].secret)
		}
	}

	var wall sync.WaitGroup
	saturate := func(n int) {
		for i := 0; i < n; i++ {
			wall.Add(1)
			go func() {
				defer wall.Done()
				_, _ = vaultcrypto.VerifyPassword("filler", costly)
			}()
		}
	}
	defer wall.Wait()

	saturate(wallSize)
	time.Sleep(150 * time.Millisecond)
	// The first wave all give up at the same instant, five seconds after it queued.
	// This second wave queues alongside the requests under test, so the slots freed
	// at that instant go to it rather than to the requests.
	saturate(64)
	time.Sleep(2 * time.Millisecond)

	var requests sync.WaitGroup
	for i := range scenarios {
		for j := 0; j < perScenario; j++ {
			requests.Add(1)
			go func(i, j int) {
				defer requests.Done()
				handlers[i].Token(results[i][j], pending[i][j])
			}(i, j)
		}
	}
	requests.Wait()

	shedBodies := make([]string, len(scenarios))
	for i, sc := range scenarios {
		shed := 0
		for _, rec := range results[i] {
			body := rec.Body.String()
			switch rec.Code {
			case http.StatusServiceUnavailable:
				shed++
				shedBodies[i] = body
				if !strings.Contains(body, "server_busy") {
					t.Errorf("%s: shed response body = %s, want server_busy", sc.name, body)
				}
				if strings.Contains(body, "access_token") {
					t.Errorf("%s: a shed request still carried a token: %s", sc.name, body)
				}
				if strings.Contains(body, validSecret) || strings.Contains(body, activeClient.Name) {
					t.Errorf("%s: shed response leaked credential or client detail: %s", sc.name, body)
				}
			case http.StatusOK:
				if sc.name != "valid client" {
					t.Errorf("%s was authenticated while the hasher was refusing to run: %s", sc.name, body)
				}
			case http.StatusUnauthorized:
				if sc.name == "valid client" {
					t.Error("a valid client was rejected as unauthorized instead of shed; overload was reported as a bad secret")
				}
			default:
				t.Errorf("%s: status = %d, body %s", sc.name, rec.Code, body)
			}
		}
		if shed == 0 {
			t.Errorf("%s: no request was shed with 503 while the argon2 semaphore was saturated", sc.name)
		}
	}

	for i := 1; i < len(shedBodies); i++ {
		if shedBodies[i] != "" && shedBodies[0] != "" && shedBodies[i] != shedBodies[0] {
			t.Errorf("shed response for %s (%s) differs from %s (%s); load-shedding tells an attacker which client IDs exist",
				scenarios[i].name, shedBodies[i], scenarios[0].name, shedBodies[0])
		}
	}
}

// Key rotation can leave a replica holding no usable signing key. Every other check
// in the client-credentials grant has already passed at that point: the client
// exists, is active, and presented the right secret. The grant still has to fail
// closed, with no token, no partial 200, and no audit entry claiming the client
// authenticated.
func TestClientToken_SigningFailureIssuesNoToken(t *testing.T) {
	const (
		clientID = "client-nokey"
		secret   = "client-secret-value"
	)

	secretHash, err := vaultcrypto.HashPassword(secret)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}

	repo := &mocks.MockClientRepo{
		GetByIDFn: func(context.Context, string) (*model.Client, error) {
			return &model.Client{
				ID:         clientID,
				Name:       "keyless",
				SecretHash: secretHash,
				Role:       "frontend",
				Scopes:     []string{"user:read"},
				Active:     true,
			}, nil
		},
	}

	var audited []string
	var mu sync.Mutex
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			mu.Lock()
			defer mu.Unlock()
			audited = append(audited, entry.EventType)
			return nil
		},
	}, 0)

	tokenSvc := service.NewTokenService(nil, "kid-gone", testIssuer, testAudience,
		15*time.Minute, 24*time.Hour, 7*24*time.Hour)
	h := handler.NewClientHandler(repo, tokenSvc, auditLog)

	w := httptest.NewRecorder()
	h.Token(w, blobClientTokenRequest(clientID, secret))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "access_token") {
		t.Errorf("a grant that could not be signed still returned a token: %s", body)
	}
	if strings.Contains(body, "kid-gone") || strings.Contains(body, "private key") {
		t.Errorf("error response leaked signing key state: %s", body)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, event := range audited {
		if event == audit.ClientAuth {
			t.Error("a client authentication was audited for a grant that issued no token")
		}
	}
}
