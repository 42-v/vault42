// Package cli implements administrative CLI commands for The Vault.
// All commands require authentication via --admin-token. Available commands:
// add-client, list-clients, revoke-client, rotate-client-secret, lock-user,
// unlock-user, revoke-all-sessions, rotate-admin-token, rotate-jwks, seed,
// cleanup-audit, and export-audit.
package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/seed"
)

// CLI handles administrative commands executed from the command line.
// Every command requires a valid --admin-token for authentication.
type CLI struct {
	clients     repository.ClientRepository
	users       repository.UserRepository
	tokens      repository.RefreshTokenRepository
	adminConfig repository.AdminConfigRepository
	audit       repository.AuditRepository
	// pepper is forwarded to seed.Run so CLI-driven seeding produces hashes
	// that match the runtime auth-service's pepper. Empty = no pepper.
	pepper string
}

// New creates a new CLI handler with the given repositories.
func New(clients repository.ClientRepository, users repository.UserRepository, tokens repository.RefreshTokenRepository, adminConfig repository.AdminConfigRepository, audit repository.AuditRepository, pepper string) *CLI {
	return &CLI{clients: clients, users: users, tokens: tokens, adminConfig: adminConfig, audit: audit, pepper: pepper}
}

// Run executes a CLI command from the given args. It returns true if a command
// was recognized and handled, false otherwise. The admin token is extracted
// from --admin-token and verified before any command executes.
func (c *CLI) Run(ctx context.Context, args []string) bool {
	if len(args) < 2 {
		return false
	}

	adminToken := ""
	for i, arg := range args {
		if arg == "--admin-token" && i+1 < len(args) {
			adminToken = args[i+1]
		}
	}

	// Verify admin token
	if !c.verifyAdminToken(ctx, adminToken) {
		fmt.Fprintln(os.Stderr, "ERROR: Admin authentication required.")
		os.Exit(1)
	}

	switch args[1] {
	case "add-client":
		return c.addClient(ctx, args)
	case "list-clients":
		return c.listClients(ctx)
	case "revoke-client":
		return c.revokeClient(ctx, args)
	case "rotate-client-secret":
		return c.rotateClientSecret(ctx, args)
	case "lock-user":
		return c.lockUser(ctx, args)
	case "unlock-user":
		return c.unlockUser(ctx, args)
	case "revoke-all-sessions":
		return c.revokeAllSessions(ctx)
	case "rotate-admin-token":
		return c.rotateAdminToken(ctx)
	case "rotate-jwks":
		return c.rotateJWKS(args)
	case "seed":
		return c.runSeed(ctx, args)
	case "cleanup-audit":
		return c.cleanupAudit(ctx, args)
	case "export-audit":
		return c.exportAudit(ctx, args)
	default:
		return false
	}
}

func (c *CLI) verifyAdminToken(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}
	storedHash, err := c.adminConfig.Get(ctx, "admin_token_hash")
	if err != nil || storedHash == "" {
		return false
	}
	valid, _ := vaultcrypto.VerifyPassword(token, storedHash)
	return valid
}

func (c *CLI) addClient(ctx context.Context, args []string) bool {
	name := getFlag(args, "--name")
	role := getFlag(args, "--role")
	scopes := getFlag(args, "--scopes")

	if name == "" || role == "" {
		fmt.Fprintln(os.Stderr, "Usage: vault add-client --admin-token <token> --name <name> --role <role> --scopes <scopes>")
		return true
	}

	// Generate client ID and secret
	clientID, err := vaultcrypto.RandomUUID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	secret, err := vaultcrypto.RandomHex(32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	secretHash, err := vaultcrypto.HashPassword(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}

	scopeList := strings.Split(scopes, ",")
	now := time.Now()

	client := &model.Client{
		ID:         clientID,
		Name:       name,
		SecretHash: secretHash,
		Role:       role,
		Scopes:     scopeList,
		Active:     true,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := c.clients.Create(ctx, client); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}

	fmt.Printf("Client created:\n  ID: %s\n  Secret: %s\n  (secret shown ONCE — save it now)\n", clientID, secret)
	return true
}

func (c *CLI) listClients(ctx context.Context) bool {
	clients, err := c.clients.List(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	for _, cl := range clients {
		status := "active"
		if !cl.Active {
			status = "revoked"
		}
		fmt.Printf("  %s  %s  [%s]  scopes=%v\n", cl.ID, cl.Name, status, cl.Scopes)
	}
	return true
}

func (c *CLI) revokeClient(ctx context.Context, args []string) bool {
	id := getFlag(args, "--id")
	if id == "" {
		fmt.Fprintln(os.Stderr, "Usage: vault revoke-client --admin-token <token> --id <client-id>")
		return true
	}
	if err := c.clients.Deactivate(ctx, id); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	} else {
		fmt.Printf("Client %s revoked.\n", id)
	}
	return true
}

func (c *CLI) rotateClientSecret(ctx context.Context, args []string) bool {
	id := getFlag(args, "--id")
	if id == "" {
		fmt.Fprintln(os.Stderr, "Usage: vault rotate-client-secret --admin-token <token> --id <client-id>")
		return true
	}

	client, err := c.clients.GetByID(ctx, id)
	if err != nil || client == nil {
		fmt.Fprintln(os.Stderr, "ERROR: client not found")
		return true
	}

	newSecret, err := vaultcrypto.RandomHex(32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	newHash, err := vaultcrypto.HashPassword(newSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	client.SecretHash = newHash
	client.UpdatedAt = time.Now()

	if err := c.clients.Update(ctx, client); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	} else {
		fmt.Printf("New secret for %s: %s\n(shown ONCE — save it now)\n", client.Name, newSecret)
	}
	return true
}

func (c *CLI) lockUser(ctx context.Context, args []string) bool {
	id := getFlag(args, "--id")
	if id == "" {
		fmt.Fprintln(os.Stderr, "Usage: vault lock-user --admin-token <token> --id <user-id>")
		return true
	}
	until := time.Now().Add(365 * 24 * time.Hour) // lock for 1 year
	if err := c.users.LockUntil(ctx, id, until); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	} else {
		fmt.Printf("User %s locked until %s\n", id, until)
	}
	return true
}

func (c *CLI) unlockUser(ctx context.Context, args []string) bool {
	id := getFlag(args, "--id")
	if id == "" {
		fmt.Fprintln(os.Stderr, "Usage: vault unlock-user --admin-token <token> --id <user-id>")
		return true
	}
	if err := c.users.Unlock(ctx, id); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	} else {
		fmt.Printf("User %s unlocked.\n", id)
	}
	return true
}

func (c *CLI) revokeAllSessions(ctx context.Context) bool {
	// Nuclear option: revoke ALL refresh tokens system-wide
	fmt.Println("WARNING: Revoking ALL refresh tokens system-wide.")
	deleted, err := c.tokens.DeleteExpired(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR cleaning expired tokens: %v\n", err)
	} else {
		fmt.Printf("Cleaned %d expired tokens.\n", deleted)
	}
	// Revoke all active tokens system-wide
	if err := c.tokens.RevokeAll(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	fmt.Println("All sessions revoked.")
	return true
}

func (c *CLI) rotateAdminToken(ctx context.Context) bool {
	newToken, err := vaultcrypto.RandomHex(32) // 256-bit
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	hash, err := vaultcrypto.HashPassword(newToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	if err := c.adminConfig.Set(ctx, "admin_token_hash", hash); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	fmt.Printf("New admin token: %s\n(shown ONCE — save it now)\n", newToken)
	return true
}

func (c *CLI) rotateJWKS(args []string) bool {
	output := getFlag(args, "--output")

	// Generate new RSA-2048 key pair
	privateKey, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: generate RSA key pair: %v\n", err)
		return true
	}

	// Generate new UUID kid
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: generate key ID: %v\n", err)
		return true
	}

	// Encode private key to PEM
	derBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	if output != "" {
		if err := os.WriteFile(output, pemBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: write key file: %v\n", err)
			return true
		}
		fmt.Printf("kid: %s\nPrivate key written to: %s\n", kid, output)
	} else {
		fmt.Printf("kid: %s\n%s", kid, pemBytes)
	}

	fmt.Fprintln(os.Stderr, "NOTE: Vault generates JWKS keys in memory at startup. To use this key,")
	fmt.Fprintln(os.Stderr, "configure the key file path and restart the service.")
	return true
}

// InitAdminToken generates and stores the initial admin token on first boot.
// If a token hash already exists in the database, this is a no-op. The
// generated token is printed to stdout once and never shown again.
func (c *CLI) InitAdminToken(ctx context.Context) error {
	existing, _ := c.adminConfig.Get(ctx, "admin_token_hash")
	if existing != "" {
		return nil // already initialized
	}

	token, err := vaultcrypto.RandomHex(32)
	if err != nil {
		return fmt.Errorf("generate admin token: %w", err)
	}
	hash, err := vaultcrypto.HashPassword(token)
	if err != nil {
		return fmt.Errorf("hash admin token: %w", err)
	}
	if err := c.adminConfig.Set(ctx, "admin_token_hash", hash); err != nil {
		return err
	}
	fmt.Printf("\n=== FIRST BOOT ===\nAdmin token: %s\nSave this token — it will NOT be shown again.\n================\n\n", token)
	return nil
}

func (c *CLI) runSeed(ctx context.Context, args []string) bool {
	file := getFlag(args, "--file")
	if file == "" {
		fmt.Fprintln(os.Stderr, "Usage: vault seed --admin-token <token> --file <path>")
		return true
	}

	sf, err := seed.Load(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}

	if err := seed.Run(ctx, sf, seed.Deps{Users: c.users, Clients: c.clients, Pepper: c.pepper}); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}

	fmt.Println("Seeding complete.")
	return true
}

func (c *CLI) cleanupAudit(ctx context.Context, args []string) bool {
	daysStr := getFlag(args, "--retention-days")
	if daysStr == "" {
		fmt.Fprintln(os.Stderr, "Usage: vault cleanup-audit --admin-token <token> --retention-days <N>")
		return true
	}
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 {
		fmt.Fprintln(os.Stderr, "ERROR: --retention-days must be a positive integer")
		return true
	}
	if c.audit == nil {
		fmt.Fprintln(os.Stderr, "ERROR: audit repository not available")
		return true
	}
	olderThan := time.Now().AddDate(0, 0, -days)
	deleted, err := c.audit.Cleanup(ctx, olderThan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	fmt.Printf("Deleted %d audit entries older than %d days.\n", deleted, days)
	return true
}

func (c *CLI) exportAudit(ctx context.Context, args []string) bool {
	if c.audit == nil {
		fmt.Fprintln(os.Stderr, "ERROR: audit repository not available")
		return true
	}

	filter := repository.AuditFilter{
		UserID:    getFlag(args, "--user-id"),
		EventType: getFlag(args, "--event-type"),
		Limit:     1000,
	}

	if s := getFlag(args, "--since"); s != "" {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid --since date (use YYYY-MM-DD): %v\n", err)
			return true
		}
		filter.Since = &t
	}
	if s := getFlag(args, "--until"); s != "" {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid --until date (use YYYY-MM-DD): %v\n", err)
			return true
		}
		filter.Until = &t
	}
	if s := getFlag(args, "--limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			fmt.Fprintln(os.Stderr, "ERROR: --limit must be a positive integer")
			return true
		}
		filter.Limit = n
	}

	entries, err := c.audit.Query(ctx, filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}

	enc := json.NewEncoder(os.Stdout)
	for _, e := range entries {
		enc.Encode(e) // #nosec G104 -- stdout write errors are non-actionable
	}
	return true
}

func getFlag(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
