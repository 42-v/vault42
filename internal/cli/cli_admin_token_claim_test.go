package cli

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// atomicAdminConfig models what auth.admin_config actually is: a table with a
// primary key on `key`, where Set is a last-writer-wins upsert and ClaimIfAbsent
// is `INSERT ... ON CONFLICT DO UPDATE SET value = admin_config.value RETURNING
// value`, which returns the incumbent to whoever loses.
//
// The mutex stands in for the row lock. It is what makes this test about the
// caller's read-then-write and not about the store's own atomicity.
type atomicAdminConfig struct {
	mu     sync.Mutex
	values map[string]string
}

func newAtomicAdminConfig() *atomicAdminConfig {
	return &atomicAdminConfig{values: map[string]string{}}
}

func (s *atomicAdminConfig) List(context.Context) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out, nil
}

func (s *atomicAdminConfig) Get(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[key], nil
}

func (s *atomicAdminConfig) Set(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
	return nil
}

func (s *atomicAdminConfig) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

func (s *atomicAdminConfig) ClaimIfAbsent(_ context.Context, key, value string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.values[key]; ok {
		return existing, nil
	}
	s.values[key] = value
	return value, nil
}

// The chart ships replicaCount 3 and cmd/vault runs InitAdminToken on every
// boot, so a first boot is three of these against one database at the same
// moment. Read-then-write gives each of them an empty read, so each mints,
// delivers and stores, and the last write wins: three credentials handed to the
// operator, one of which authenticates, and nothing saying which.
//
// It matters more since the credential stopped going to stdout. All three used
// to land in one aggregated log stream, where an operator could try each in
// turn. They now land in three per-pod memory-backed volumes that do not outlive
// their pods, while admin_token_hash persists -- and every subcommand that could
// rotate it is behind the token itself, so once the copies are gone the way back
// is manual SQL.
func TestInitAdminToken_ConcurrentBootsDeliverOneWorkingToken(t *testing.T) {
	sink := firstBootSink(t)
	store := newAtomicAdminConfig()

	const replicas = 3
	errs := make([]error, replicas)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = New(nil, nil, nil, store, nil, "").InitAdminToken(context.Background())
		}()
	}
	captureStdout(t, func() {
		close(start)
		wg.Wait()
	})

	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}

	body, err := os.ReadFile(sink)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	var delivered []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if token, ok := strings.CutPrefix(line, "VAULT_ADMIN_TOKEN="); ok {
			delivered = append(delivered, token)
		}
	}

	if len(delivered) != 1 {
		t.Fatalf("%d replicas delivered %d admin tokens, want 1. Every extra one is a "+
			"credential an operator was handed that does not authenticate, in a sink that dies "+
			"with its pod while the hash that beat it persists.", replicas, len(delivered))
	}

	stored, err := store.Get(context.Background(), "admin_token_hash")
	if err != nil {
		t.Fatalf("read stored hash: %v", err)
	}
	if stored == "" {
		t.Fatal("no admin_token_hash was stored, so no admin token is in force at all")
	}
	if ok, verr := vaultcrypto.VerifyPassword(delivered[0], stored); !ok || verr != nil {
		t.Errorf("the delivered token does not verify against the stored hash (err=%v). The "+
			"operator holds a credential that authenticates as nothing.", verr)
	}
}
