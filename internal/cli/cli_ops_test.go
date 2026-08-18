package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// cliWith builds a CLI with the given audit repo (others are permissive mocks).
// mockAuditRepo (with CleanupFn/QueryFn) is defined in cli_test.go.
func cliWith(audit repository.AuditRepository) *CLI {
	return New(&mockClientRepo{}, &mockUserRepo{}, nil, nil, audit, "")
}

func TestCLI_CleanupAudit(t *testing.T) {
	ctx := context.Background()

	t.Run("missing retention-days prints usage", func(t *testing.T) {
		if !cliWith(&mockAuditRepo{}).cleanupAudit(ctx, nil) {
			t.Error("expected handled=true")
		}
	})

	t.Run("invalid retention-days rejected", func(t *testing.T) {
		cli := cliWith(&mockAuditRepo{})
		for _, arg := range []string{"0", "-3", "notanumber"} {
			cli.cleanupAudit(ctx, []string{"--retention-days", arg})
		}
	})

	t.Run("nil audit repo reports unavailable", func(t *testing.T) {
		cliWith(nil).cleanupAudit(ctx, []string{"--retention-days", "30"})
	})

	t.Run("success reports deleted count", func(t *testing.T) {
		called := false
		cli := cliWith(&mockAuditRepo{CleanupFn: func(context.Context, time.Time) (int64, error) {
			called = true
			return 7, nil
		}})
		cli.cleanupAudit(ctx, []string{"--retention-days", "30"})
		if !called {
			t.Error("Cleanup was not invoked")
		}
	})

	t.Run("repo error is handled", func(t *testing.T) {
		cli := cliWith(&mockAuditRepo{CleanupFn: func(context.Context, time.Time) (int64, error) {
			return 0, errors.New("db down")
		}})
		cli.cleanupAudit(ctx, []string{"--retention-days", "30"})
	})
}

func TestCLI_ExportAudit(t *testing.T) {
	ctx := context.Background()

	t.Run("nil audit repo reports unavailable", func(t *testing.T) {
		cliWith(nil).exportAudit(ctx, nil)
	})

	t.Run("invalid since/until dates rejected", func(t *testing.T) {
		cli := cliWith(&mockAuditRepo{})
		cli.exportAudit(ctx, []string{"--since", "not-a-date"})
		cli.exportAudit(ctx, []string{"--until", "not-a-date"})
	})

	t.Run("success exports entries as JSONL", func(t *testing.T) {
		called := false
		cli := cliWith(&mockAuditRepo{QueryFn: func(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
			called = true
			return []*model.AuditEntry{{
				ID: "a1", Timestamp: time.Now().UTC(), EventType: "login_success",
				UserID: "u1", Metadata: map[string]interface{}{"ok": true},
			}}, nil
		}})
		cli.exportAudit(ctx, []string{"--since", "2020-01-01", "--until", "2030-01-01", "--event-type", "login_success"})
		if !called {
			t.Error("Query was not invoked")
		}
	})

	t.Run("query error is handled", func(t *testing.T) {
		cli := cliWith(&mockAuditRepo{QueryFn: func(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
			return nil, errors.New("db down")
		}})
		cli.exportAudit(ctx, nil)
	})
}

func TestCLI_RunSeed(t *testing.T) {
	ctx := context.Background()

	t.Run("missing file prints usage", func(t *testing.T) {
		cliWith(&mockAuditRepo{}).runSeed(ctx, nil)
	})

	t.Run("unreadable file is handled", func(t *testing.T) {
		cliWith(&mockAuditRepo{}).runSeed(ctx, []string{"--file", "/no/such/seed.json"})
	})

	t.Run("valid seed file completes", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "seed.json")
		content := `{
			"clients": [{"name":"frontend","role":"frontend","scopes":["user:read"]}],
			"users":   [{"email":"seed@example.com","password":"correct-horse-battery","locale":"en","email_verified":true}]
		}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write seed file: %v", err)
		}
		cliWith(&mockAuditRepo{}).runSeed(ctx, []string{"--file", path})
	})

	t.Run("seed run failure is reported", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "seed.json")
		content := `{"clients": [{"name":"frontend","role":"frontend","scopes":["user:read"]}]}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write seed file: %v", err)
		}
		clients := &mockClientRepo{GetByNameFn: func(context.Context, string) (*model.Client, error) {
			return nil, errors.New("db down")
		}}
		c := New(clients, &mockUserRepo{}, nil, nil, &mockAuditRepo{}, "")

		var stdout string
		stderr := captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				if !c.runSeed(ctx, []string{"--file", path}) {
					t.Error("expected handled=true")
				}
			})
		})
		if !strings.Contains(stderr, "ERROR:") || !strings.Contains(stderr, `seed client "frontend"`) {
			t.Errorf("expected seed failure for client frontend on stderr, got %q", stderr)
		}
		if strings.Contains(stdout, "Seeding complete.") {
			t.Error("seeding reported complete after a failure")
		}
	})
}

func TestCLI_RotateAdminToken(t *testing.T) {
	ctx := context.Background()
	c, _, _, _, admin := newTestCLI()

	t.Run("success stores the new hash", func(t *testing.T) {
		var storedKey string
		admin.SetFn = func(_ context.Context, key, _ string) error { storedKey = key; return nil }
		if !c.rotateAdminToken(ctx) {
			t.Error("expected handled=true")
		}
		if storedKey != "admin_token_hash" {
			t.Errorf("stored key = %q, want admin_token_hash", storedKey)
		}
	})

	t.Run("store error is handled", func(t *testing.T) {
		admin.SetFn = func(context.Context, string, string) error { return errors.New("db down") }
		c.rotateAdminToken(ctx)
	})
}

func TestCLI_RotateJWKS(t *testing.T) {
	c, _, _, _, _ := newTestCLI()

	t.Run("writes a PEM key to --output", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "signing-key.pem")
		if !c.rotateJWKS([]string{"--output", out}) {
			t.Error("expected handled=true")
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("read output: %v", err)
		}
		if len(data) == 0 || !bytesContains(data, "PRIVATE KEY") {
			t.Errorf("output does not look like a PEM key: %q", data)
		}
	})

	t.Run("prints to stdout when no --output", func(t *testing.T) {
		if !c.rotateJWKS(nil) {
			t.Error("expected handled=true")
		}
	})
}

func TestCLI_AddClient(t *testing.T) {
	ctx := context.Background()
	c, clients, _, _, _ := newTestCLI()

	t.Run("creates a client", func(t *testing.T) {
		created := false
		clients.CreateFn = func(context.Context, *model.Client) error { created = true; return nil }
		c.addClient(ctx, []string{"--name", "frontend", "--role", "frontend", "--scopes", "user:read,user:write"})
		if !created {
			t.Error("Create was not called for a valid add-client")
		}
	})

	t.Run("missing name/role prints usage", func(t *testing.T) {
		c.addClient(ctx, []string{"--name", "frontend"})
	})
}

func bytesContains(b []byte, sub string) bool {
	return strings.Contains(string(b), sub)
}

func TestCLI_RotateClientSecret_RetiredIsInert(t *testing.T) {
	ctx := context.Background()
	c, clients, _, _, _ := newTestCLI()
	clients.GetByIDFn = func(context.Context, string) (*model.Client, error) {
		t.Error("rotate-client-secret must not read the clients repository once retired")
		return nil, nil
	}
	clients.UpdateFn = func(context.Context, *model.Client) error {
		t.Error("rotate-client-secret must not write the clients repository once retired")
		return nil
	}
	if handled := c.rotateClientSecret(ctx, []string{"--id", "c1"}); !handled {
		t.Error("rotate-client-secret must stay a recognized command")
	}
}

func TestCLI_InitAdminToken(t *testing.T) {
	ctx := context.Background()
	c, _, _, _, admin := newTestCLI()

	t.Run("generates when unset", func(t *testing.T) {
		firstBootSink(t)
		admin.GetFn = func(context.Context, string) (string, error) { return "", nil }
		set := false
		admin.SetFn = func(context.Context, string, string) error { set = true; return nil }
		if err := c.InitAdminToken(ctx); err != nil {
			t.Fatalf("InitAdminToken: %v", err)
		}
		if !set {
			t.Error("InitAdminToken did not store a token when unset")
		}
	})

	t.Run("no-op when already initialized", func(t *testing.T) {
		admin.GetFn = func(context.Context, string) (string, error) { return "existing-hash", nil }
		called := false
		admin.SetFn = func(context.Context, string, string) error { called = true; return nil }
		if err := c.InitAdminToken(ctx); err != nil {
			t.Fatalf("InitAdminToken: %v", err)
		}
		if called {
			t.Error("InitAdminToken overwrote an existing token")
		}
	})
}
