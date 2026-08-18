// Package cli implements administrative CLI commands for The Vault.
// All commands require the admin credential, taken from ADMIN_TOKEN_FILE or,
// with a warning that it is disclosed through argv, from --admin-token.
// Available commands:
// add-client, list-clients, revoke-all-sessions, rotate-admin-token,
// rotate-jwks, seed, cleanup-recovery, and export-audit.
// The revoke-client, rotate-client-secret, lock-user, unlock-user and
// cleanup-audit subcommands are retired stubs that print an error and redirect
// to the plane that owns the capability; they issue no database write.
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
	"github.com/42-v/vault42/internal/firstboot"
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
	if adminToken != "" {
		warnAdminTokenInArgv()
	}

	if !c.authenticate(ctx, adminToken) {
		fmt.Fprintln(os.Stderr, "ERROR: Admin authentication required. Set ADMIN_TOKEN_FILE to a file holding the admin token, or pass --admin-token, which discloses it through /proc/<pid>/cmdline.")
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

// authenticate resolves the admin credential, preferring ADMIN_TOKEN_FILE.
//
// A flag is the one delivery mechanism for a secret that cannot be made safe:
// every argument of a running process is readable through /proc/<pid>/cmdline by
// anything running as the same uid, it appears in `ps` and in container process
// listings, and the shell keeps it in history afterwards. cmd/recover says the
// same about --dsn and warns; the difference here is that the safe path is now
// the default one, following the _FILE convention this repo already uses for
// ADMIN_TOKEN, BRIDGE_ADMIN_TOKEN and VAULT_PEPPER.
//
// The mounted file is tried first and the flag is the fallback rather than the
// other way round, so an operator who has done nothing gets the safe path, and a
// mount that is no longer the credential in force does not lock them out of a
// command they authenticated correctly.
func (c *CLI) authenticate(ctx context.Context, flagToken string) bool {
	if c.provisionedAdminToken != "" {
		if storedHash, err := c.adminConfig.Get(ctx, "admin_token_hash"); err == nil && storedHash != "" {
			if c.provisionedTokenMatches(storedHash) {
				return true
			}
		}
	}
	return c.verifyAdminToken(ctx, flagToken)
}

// warnAdminTokenInArgv says out loud that a credential passed on the command
// line is already disclosed. The process cannot rewrite its own argv, so this is
// the only move left, and it is worth making while the operator is still at the
// keyboard.
func warnAdminTokenInArgv() {
	fmt.Fprintln(os.Stderr, "WARNING: --admin-token puts the admin credential in this process's argv, where it is "+
		"readable by every process on this host via /proc/<pid>/cmdline, shows in `ps` and container process listings, "+
		"and is kept in shell history. Set ADMIN_TOKEN_FILE to a file holding the token instead, and rotate this one.")
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

	// Delivered before the row is created: only the Argon2id hash is stored, so
	// a secret that could not be handed over leaves a client nobody can
	// authenticate as and no command can repair.
	dest, err := firstboot.Deliver("VAULT_CLIENT_SECRET_"+name, secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}

	if err := c.clients.Create(ctx, client); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}

	fmt.Printf("Client created:\n  ID: %s\n  Secret written to: %s (not shown here, and not shown again)\n", clientID, dest)
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

// revokeClient is retired. Deactivating a client from cmd/vault ran as the
// vault_app role, which holds only SELECT and INSERT on auth.clients (migration
// 001): the UPDATE that clears active failed with 42501 insufficient_privilege,
// so the command has been dead since the schema was first cut, and even had it
// run it would leave no audit trail. Client revocation belongs on the admin
// gateway, which audits the action and runs as vault_admin.
//
// The command stays recognized (returns true) so cmd/vault does not treat it as
// an unknown argument and fall through to booting the server. It issues no
// database write.
func (c *CLI) revokeClient(_ context.Context, _ []string) bool {
	fmt.Fprintln(os.Stderr, "ERROR: revoke-client is retired. Revoke a client on the admin gateway: POST /admin/clients/{id}/revoke (operator role, mTLS loopback). The vault CLI no longer writes client state.")
	return true
}

// rotateClientSecret is retired for the same reason as revokeClient: rotating a
// secret from cmd/vault ran as the vault_app role, whose SELECT+INSERT-only grant
// on auth.clients (migration 001) fails the UPDATE with 42501, and it printed a
// fresh secret to stdout with no audit trail. Secret rotation belongs on the
// admin gateway, which audits the action and runs as vault_admin.
//
// The command stays recognized (returns true) so cmd/vault does not fall through
// to booting the server. It issues no database write.
func (c *CLI) rotateClientSecret(_ context.Context, _ []string) bool {
	fmt.Fprintln(os.Stderr, "ERROR: rotate-client-secret is retired. Rotate a client secret on the admin gateway: POST /admin/clients/{id}/rotate (operator role, mTLS loopback). The vault CLI no longer writes client state.")
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
	// Delivered before the hash is installed, for the same reason as
	// InitAdminToken: a rotation the operator cannot receive locks every
	// administrative subcommand out of the deployment.
	dest, err := firstboot.Deliver("VAULT_ADMIN_TOKEN", newToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	if err := c.adminConfig.Set(ctx, "admin_token_hash", hash); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return true
	}
	fmt.Printf("Admin token rotated; the new token was written to %s and is not shown here.\n", dest)
	return true
}

// rotateJWKS mints a signing key. --output is required: without it the command
// wrote a PKCS#1 RSA private key to stdout, and that key signs every access
// token the deployment issues. Run from a Job or an init container — which is
// how key rotation is actually driven — stdout is the pod log, so the private
// half of the signing key ended up in the aggregator alongside the tokens it
// signs. There is no safe way to print it, only a safe file to put it in, which
// is what --output already was.
func (c *CLI) rotateJWKS(args []string) bool {
	output := getFlag(args, "--output")
	if output == "" {
		fmt.Fprintln(os.Stderr, "ERROR: rotate-jwks requires --output <path>: the private key is written to that file at mode 0600 and is never printed.")
		return true
	}

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

	if err := os.WriteFile(output, pemBytes, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: write key file: %v\n", err)
		return true
	}
	fmt.Printf("kid: %s\nPrivate key written to: %s\n", kid, output)

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
	// Delivered before the hash is stored. InitAdminToken returns early once
	// admin_token_hash is set, so storing the hash of a token the operator never
	// received locks every administrative subcommand out with no way back.
	dest, err := firstboot.Deliver("VAULT_ADMIN_TOKEN", token)
	if err != nil {
		return fmt.Errorf("deliver admin token: %w", err)
	}
	if err := c.adminConfig.Set(ctx, "admin_token_hash", hash); err != nil {
		return err
	}
	fmt.Printf("FIRST BOOT: an admin token was generated and written to %s; it is not in this output and will not be shown again.\n", dest)
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

// cleanupAudit is retired (F-17). It reached a capability the RBAC model grants
// no admin, behind a gate the role running it can rewrite.
//
// internal/rbac/rbac.go says audit access "is read-only by design: there is no
// corresponding write or delete permission, because an admin who can edit the
// audit trail can erase their own actions", and no admin tier holds an
// audit-delete permission. Migration 018 grants EXECUTE on
// audit.cleanup_old_entries to vault_app and deliberately not to vault_admin, so
// the admin plane cannot run this at all — while cmd/vault, running as vault_app,
// could, gated only by admin_token_hash in auth.admin_config, a table migration
// 001 grants vault_app SELECT, INSERT and UPDATE on. The caller could overwrite
// its own gate, which makes the token operator convenience and not an
// authorization boundary.
//
// Retiring rather than promoting it to the admin gateway is the honest
// resolution. Promoting would mean granting vault_admin EXECUTE on the purge
// function and minting the audit-delete permission rbac refuses on purpose —
// a migration, and a reversal of a decision the codebase argues for.
//
// Nothing is lost. Audit retention is VAULT_AUDIT_RETENTION_DAYS, swept in
// process by internal/audit.Retention through the same SECURITY DEFINER
// function: declarative, part of the deployment rather than of whoever holds the
// CLI token, and not aimable at an arbitrary cutoff.
//
// The command stays recognized (returns true) so cmd/vault does not treat it as
// an unknown argument and fall through to booting the server. It issues no
// database write.
func (c *CLI) cleanupAudit(_ context.Context, _ []string) bool {
	fmt.Fprintln(os.Stderr, "ERROR: cleanup-audit is retired. Audit retention is set with VAULT_AUDIT_RETENTION_DAYS, which the server sweeps at startup and every 6h. No admin tier holds an audit-delete permission, and the vault CLI no longer deletes audit entries on demand.")
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
