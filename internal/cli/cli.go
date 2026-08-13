// Package cli implements administrative CLI commands for The Vault.
// All commands require authentication via --admin-token. Available commands:
// add-client, list-clients, revoke-client, rotate-client-secret, lock-user,
// unlock-user, revoke-all-sessions, rotate-admin-token, rotate-jwks, seed,
// cleanup-audit, cleanup-recovery, and export-audit.
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

	"github.com/42-v/vault42/internal/config"
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
	// recovery prunes the account-recovery escrow. Attached separately via
	// WithRecoveryPruner, not taken by New: everything else that touches the
	// escrow holds the append-only interface, and only this command and the
	// retention sweeper are handed something that can delete from it.
	recovery repository.AccountRecoveryPruner
	// pepper is forwarded to seed.Run so CLI-driven seeding produces hashes
	// that match the runtime auth-service's pepper. Empty = no pepper.
	pepper string
	// provisionedAdminToken is the admin credential the operator mounted at
	// ADMIN_TOKEN_FILE, either an Argon2id hash or the plaintext token. It seeds
	// admin_token_hash on first boot so the credential never has to be minted
	// and printed to stdout.
	provisionedAdminToken string
	// provisionedAdminErr defers a failed read to InitAdminToken, the only
	// caller that can report it: New has no error return, and dropping the error
	// would restore the silent fall-through to a generated token that the mount
	// was supposed to replace.
	provisionedAdminErr error
}

// New creates a new CLI handler with the given repositories.
func New(clients repository.ClientRepository, users repository.UserRepository, tokens repository.RefreshTokenRepository, adminConfig repository.AdminConfigRepository, audit repository.AuditRepository, pepper string) *CLI {
	token, err := loadProvisionedAdminToken()
	return &CLI{
		clients:               clients,
		users:                 users,
		tokens:                tokens,
		adminConfig:           adminConfig,
		audit:                 audit,
		pepper:                pepper,
		provisionedAdminToken: token,
		provisionedAdminErr:   err,
	}
}

// WithRecoveryPruner attaches the account-recovery escrow pruner that
// `vault cleanup-recovery` needs. Without it the command reports that the
// repository is unavailable rather than silently doing nothing.
func (c *CLI) WithRecoveryPruner(pruner repository.AccountRecoveryPruner) *CLI {
	c.recovery = pruner
	return c
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
		exitProcess(1)
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
	case "cleanup-recovery":
		return c.cleanupRecovery(ctx, args)
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
	secretHash, err := hashPassword(secret)
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
	newHash, err := hashPassword(newSecret)
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

// lockUser is retired. Locking an account from cmd/vault ran as the vault_app
// role and set auth.users.locked_until directly: no audit row, no session
// revocation, and — because vault_app writes the same column the admin plane
// uses for containment — it could silently release or override a lock an admin
// had imposed. Account containment belongs on the admin gateway, which audits
// the action, revokes the target's refresh tokens, and runs as vault_admin.
//
// The command stays recognized (returns true) so cmd/vault does not treat it as
// an unknown argument and fall through to booting the server. It issues no
// database write.
func (c *CLI) lockUser(_ context.Context, _ []string) bool {
	fmt.Fprintln(os.Stderr, "ERROR: lock-user is retired. Lock accounts on the admin gateway: POST /admin/users/{id}/lock (operator role, mTLS loopback). The vault CLI no longer writes account locks.")
	return true
}

// unlockUser is retired for the same reason as lockUser: a vault_app Unlock here
// could release a lock the admin plane set, with no audit trail. Use the admin
// gateway's unlock route instead.
func (c *CLI) unlockUser(_ context.Context, _ []string) bool {
	fmt.Fprintln(os.Stderr, "ERROR: unlock-user is retired. Unlock accounts on the admin gateway: POST /admin/users/{id}/unlock (operator role, mTLS loopback). The vault CLI no longer writes account unlocks.")
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
	hash, err := hashPassword(newToken)
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

// argon2idPrefix marks the PHC-encoded form of an Argon2id hash and is what
// tells ADMIN_TOKEN_FILE's two accepted forms apart. Config.Validate has
// already refused to start on anything carrying this prefix that is not a
// complete hash.
const argon2idPrefix = "$argon2id$"

// loadProvisionedAdminToken reads the admin credential the operator mounted at
// ADMIN_TOKEN_FILE, or returns "" when there is none.
//
// Read here rather than carried on config.Config, following how cmd/vault reads
// SIGNING_KEY: this is the secret's only consumer, and under
// VAULT_SECRET_FILE_CONSUME the read destroys the file, so a second reader
// would get nothing. Config parsed this file for its whole life and stored it
// in a field no code path ever read, which is what let a mounted admin token be
// silently replaced by a generated one.
func loadProvisionedAdminToken() (string, error) {
	if os.Getenv("ADMIN_TOKEN_FILE") == "" {
		return "", nil
	}
	return config.LoadSecret("ADMIN_TOKEN")
}

// InitAdminToken installs the initial admin token on first boot.
//
// ADMIN_TOKEN_FILE wins when set: the operator has already chosen the
// credential and knows its plaintext, so nothing needs to be minted and nothing
// secret reaches stdout. Only when no file is mounted is a token generated and
// printed once.
//
// If a hash already exists in the database it is left alone, because it may be
// the result of rotate-admin-token and re-seeding from the file would silently
// undo that rotation on the next restart.
func (c *CLI) InitAdminToken(ctx context.Context) error {
	if c.provisionedAdminErr != nil {
		return fmt.Errorf("read ADMIN_TOKEN_FILE: %w", c.provisionedAdminErr)
	}

	existing, _ := c.adminConfig.Get(ctx, "admin_token_hash")
	if existing != "" {
		// Not fatal, but not silent either: an operator whose mounted file is no
		// longer the credential in force will otherwise keep authenticating with
		// it and blame the CLI.
		if c.provisionedAdminToken != "" && !c.provisionedTokenMatches(existing) {
			fmt.Fprintln(os.Stderr, "WARNING: the admin token in ADMIN_TOKEN_FILE is not the one in force; the database already holds a different hash. Run rotate-admin-token to change the admin token.")
		}
		return nil
	}

	if c.provisionedAdminToken != "" {
		hash := c.provisionedAdminToken
		if !strings.HasPrefix(hash, argon2idPrefix) {
			// The file may hold the plaintext token instead of its hash, which is
			// what scripts/generate-secrets.sh writes and what
			// charts/vault/templates/NOTES.txt tells operators to cat into
			// --admin-token. Only the hash is ever stored.
			var err error
			hash, err = hashPassword(hash)
			if err != nil {
				return fmt.Errorf("hash admin token from ADMIN_TOKEN_FILE: %w", err)
			}
		}
		if err := c.adminConfig.Set(ctx, "admin_token_hash", hash); err != nil {
			return err
		}
		fmt.Println("Admin token taken from ADMIN_TOKEN_FILE.")
		return nil
	}

	token, err := vaultcrypto.RandomHex(32)
	if err != nil {
		return fmt.Errorf("generate admin token: %w", err)
	}
	hash, err := hashPassword(token)
	if err != nil {
		return fmt.Errorf("hash admin token: %w", err)
	}
	if err := c.adminConfig.Set(ctx, "admin_token_hash", hash); err != nil {
		return err
	}
	fmt.Printf("\n=== FIRST BOOT ===\nAdmin token: %s\nSave this token — it will NOT be shown again.\n================\n\n", token)
	return nil
}

// provisionedTokenMatches reports whether ADMIN_TOKEN_FILE still describes the
// credential stored in the database. The plaintext form costs one Argon2id
// verification per boot, which is the price of telling an operator the truth
// about whether their mount is in force.
func (c *CLI) provisionedTokenMatches(storedHash string) bool {
	if strings.HasPrefix(c.provisionedAdminToken, argon2idPrefix) {
		return c.provisionedAdminToken == storedHash
	}
	ok, _ := vaultcrypto.VerifyPassword(c.provisionedAdminToken, storedHash)
	return ok
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

	if err := seed.Run(ctx, sf, seed.Deps{Users: c.users, Clients: c.clients}, c.pepper); err != nil {
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

// cleanupRecovery purges account-recovery escrow records past a horizon. It is
// the on-demand half of VAULT_RECOVERY_RETENTION_DAYS, and the only supported
// way to remove an escrow record: the table is append-only and both application
// roles have DELETE revoked, so an Operator honouring a later erasure of the
// escrow itself has nothing else to reach for.
func (c *CLI) cleanupRecovery(ctx context.Context, args []string) bool {
	daysStr := getFlag(args, "--retention-days")
	if daysStr == "" {
		fmt.Fprintln(os.Stderr, "Usage: vault cleanup-recovery --admin-token <token> --retention-days <N>")
		return true
	}
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 {
		fmt.Fprintln(os.Stderr, "ERROR: --retention-days must be a positive integer")
		return true
	}
	if c.recovery == nil {
		fmt.Fprintln(os.Stderr, "ERROR: account recovery repository not available")
		return true
	}
	olderThan := time.Now().AddDate(0, 0, -days)
	deleted, err := c.recovery.Prune(ctx, olderThan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	fmt.Printf("Deleted %d recovery escrow records older than %d days.\n", deleted, days)
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

// exitProcess terminates the process when admin authentication fails. It is a
// variable so tests can observe the denial without killing the test binary;
// production never reassigns it, and a replacement must not return.
var exitProcess = os.Exit

// hashPassword is the Argon2id hasher used for generated credentials. It is a
// variable so tests can drive the hashing-failure paths, which are otherwise
// only reachable when the process-wide argon2 semaphore is saturated.
// Production never reassigns it.
var hashPassword = vaultcrypto.HashPassword
