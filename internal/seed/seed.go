// Package seed provides declarative database seeding from JSON files.
// It creates clients and users idempotently — existing entries (matched by
// name for clients, email for users) are skipped. Activated via the
// VAULT_SEED_FILE env var (startup) or the "vault seed" CLI command.
package seed

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/repository"
)

// SeedFile is the top-level structure of a seed JSON file.
// See seed.example.json in the repository root for the expected format.
type SeedFile struct {
	Clients []ClientSeed `json:"clients"`
	Users   []UserSeed   `json:"users"`
	Admins  []AdminSeed  `json:"admins,omitempty"`
}

// AdminSeed defines an admin gateway user to create. Password must be at
// least 15 characters. Role must be one of: super_admin, admin, viewer.
type AdminSeed struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// ClientSeed defines a service client to create.
type ClientSeed struct {
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris"`
}

// UserSeed defines a user to create. EmailVerified defaults to true when
// omitted (dev convenience). Locale defaults to "en". Password must be at
// least 15 characters (NIST SP 800-63B).
//
// Roles is the JWT "roles" claim baked into the access token at login.
// The validator REJECTS the admin-tier role names ("admin", "super_admin")
// here — those are reserved for the AdminUser table (admins seed array)
// and reachable only through the admin gateway. Other strings are passed
// through verbatim and become role claims (e.g. "viewer", "operator").
// Empty roles default to ["user"] at JWT issuance time.
type UserSeed struct {
	Email         string   `json:"email"`
	Password      string   `json:"password"`
	DisplayName   string   `json:"display_name"`
	Locale        string   `json:"locale"`
	EmailVerified *bool    `json:"email_verified"`
	Roles         []string `json:"roles,omitempty"`
}

// ReservedAdminRoles are role names that the User table is FORBIDDEN from
// granting. Only the AdminUser table (admins seed array) can hold these.
// Defense-in-depth: the auth/login JWT issuer also strips these from
// user.Roles in case a row was inserted directly by SQL.
var ReservedAdminRoles = map[string]bool{
	"admin":       true,
	"super_admin": true,
}

// FilterUserRoles removes admin-tier role names from a user's role list.
// Returns a new slice; never mutates the input. Intended for the JWT
// issuance path so a manually-poked DB row can never grant admin access.
func FilterUserRoles(roles []string) []string {
	if len(roles) == 0 {
		return nil
	}
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if !ReservedAdminRoles[r] {
			out = append(out, r)
		}
	}
	return out
}

// Deps holds the repositories needed for seeding.
type Deps struct {
	Users   repository.UserRepository
	Clients repository.ClientRepository
	// Pepper is the optional HMAC-pepper applied to user/admin password hashes.
	// Empty = no pepper (back-compat for deployments without VAULT_PEPPER).
	// Client secrets are NEVER peppered — they are full-entropy random tokens
	// where pepper provides no defensive value.
	Pepper string
}

// Load reads and validates a seed file from the given path.
func Load(path string) (*SeedFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from trusted env var or CLI flag, not user input
	if err != nil {
		return nil, fmt.Errorf("read seed file: %w", err)
	}

	var sf SeedFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parse seed file: %w", err)
	}

	if err := validate(&sf); err != nil {
		return nil, fmt.Errorf("validate seed file: %w", err)
	}

	return &sf, nil
}

// validate checks that all required fields are present and valid.
func validate(sf *SeedFile) error {
	seen := make(map[string]bool)
	for i, c := range sf.Clients {
		if c.Name == "" {
			return fmt.Errorf("clients[%d]: name is required", i)
		}
		if c.Role == "" {
			return fmt.Errorf("clients[%d] (%s): role is required", i, c.Name)
		}
		if seen[c.Name] {
			return fmt.Errorf("clients[%d]: duplicate name %q", i, c.Name)
		}
		seen[c.Name] = true
	}

	emails := make(map[string]bool)
	for i, u := range sf.Users {
		if u.Email == "" {
			return fmt.Errorf("users[%d]: email is required", i)
		}
		if !strings.Contains(u.Email, "@") {
			return fmt.Errorf("users[%d] (%s): invalid email", i, u.Email)
		}
		if u.Password == "" {
			return fmt.Errorf("users[%d] (%s): password is required", i, u.Email)
		}
		if len(u.Password) < 15 {
			return fmt.Errorf("users[%d] (%s): password must be at least 15 characters", i, u.Email)
		}
		if emails[u.Email] {
			return fmt.Errorf("users[%d]: duplicate email %q", i, u.Email)
		}
		emails[u.Email] = true
		// Reserved admin-tier roles cannot be granted via the user table.
		// Reachability through the admins seed array (AdminUser) is the
		// only path to those tiers.
		for _, r := range u.Roles {
			if ReservedAdminRoles[r] {
				return fmt.Errorf("users[%d] (%s): role %q is reserved for the admins seed array",
					i, u.Email, r)
			}
		}
	}

	validAdminRoles := map[string]bool{"super_admin": true, "admin": true, "viewer": true, "operator": true}
	usernames := make(map[string]bool)
	for i, a := range sf.Admins {
		if a.Username == "" {
			return fmt.Errorf("admins[%d]: username is required", i)
		}
		if a.Password == "" {
			return fmt.Errorf("admins[%d] (%s): password is required", i, a.Username)
		}
		if len(a.Password) < 15 {
			return fmt.Errorf("admins[%d] (%s): password must be at least 15 characters", i, a.Username)
		}
		if !validAdminRoles[a.Role] {
			return fmt.Errorf("admins[%d] (%s): role must be super_admin, admin, operator, or viewer", i, a.Username)
		}
		if usernames[a.Username] {
			return fmt.Errorf("admins[%d]: duplicate username %q", i, a.Username)
		}
		usernames[a.Username] = true
	}

	return nil
}

// Run executes the seed file against the database. Existing entries are
// skipped (idempotent). Client secrets are generated and printed to stdout.
func Run(ctx context.Context, sf *SeedFile, deps Deps) error {
	for _, cs := range sf.Clients {
		if err := seedClient(ctx, cs, deps.Clients); err != nil {
			return fmt.Errorf("seed client %q: %w", cs.Name, err)
		}
	}

	for _, us := range sf.Users {
		if err := seedUser(ctx, us, deps.Users, deps.Pepper); err != nil {
			return fmt.Errorf("seed user %q: %w", us.Email, err)
		}
	}

	return nil
}

func seedClient(ctx context.Context, cs ClientSeed, clients repository.ClientRepository) error {
	existing, err := clients.GetByName(ctx, cs.Name)
	if err != nil {
		return err
	}
	if existing != nil {
		fmt.Printf("seed: client %q already exists (id=%s), skipping\n", cs.Name, existing.ID)
		return nil
	}

	clientID, err := vaultcrypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("generate client ID: %w", err)
	}
	secret, err := vaultcrypto.RandomHex(32)
	if err != nil {
		return fmt.Errorf("generate client secret: %w", err)
	}
	secretHash, err := hashPassword(secret)
	if err != nil {
		return fmt.Errorf("hash client secret: %w", err)
	}

	now := time.Now()
	client := &model.Client{
		ID:           clientID,
		Name:         cs.Name,
		SecretHash:   secretHash,
		Role:         cs.Role,
		Scopes:       cs.Scopes,
		RedirectURIs: cs.RedirectURIs,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := clients.Create(ctx, client); err != nil {
		return fmt.Errorf("create: %w", err)
	}

	fmt.Printf("seed: client %q created (id=%s, secret=%s — save this)\n", cs.Name, clientID, secret)
	return nil
}

// RunAdmins seeds admin gateway users from the seed file. Existing admins
// (matched by username) are skipped. This is safe to call without admin
// entries in the seed file — it simply does nothing.
//
// pepper is the optional HMAC-pepper applied to admin password hashes; empty
// means no pepper (back-compat). Must match the value used by the admin
// gateway login flow, otherwise admins cannot authenticate.
func RunAdmins(ctx context.Context, sf *SeedFile, admins repository.AdminUserRepository, pepper string) error {
	for _, as := range sf.Admins {
		if err := seedAdmin(ctx, as, admins, pepper); err != nil {
			return fmt.Errorf("seed admin %q: %w", as.Username, err)
		}
	}
	return nil
}

func seedAdmin(ctx context.Context, as AdminSeed, admins repository.AdminUserRepository, pepper string) error {
	existing, err := admins.GetByUsername(ctx, as.Username)
	if err != nil {
		return err
	}
	if existing != nil {
		fmt.Printf("seed: admin %q already exists (id=%s), skipping\n", as.Username, existing.ID)
		return nil
	}

	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("generate admin ID: %w", err)
	}
	passwordHash, err := hashPassword(as.Password, pepper)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	createdBy, err := seedAdminCreator(ctx, admins)
	if err != nil {
		return err
	}

	now := time.Now()
	admin := &model.AdminUser{
		ID:           id,
		Username:     as.Username,
		PasswordHash: passwordHash,
		Role:         as.Role,
		CreatedAt:    now,
		UpdatedAt:    now,
		CreatedBy:    createdBy,
	}

	if err := admins.Create(ctx, admin); err != nil {
		return fmt.Errorf("create: %w", err)
	}

	fmt.Printf("seed: admin %q created (id=%s, role=%s)\n", as.Username, id, as.Role)
	return nil
}

// seedAdminCreator picks the admin that a seeded row is attributed to.
//
// A seed file names a role and never an actor, so before migration 016 these
// rows went in with created_by NULL. 016 refuses an unattributed admin once any
// admin exists, because "omit created_by" would otherwise be the whole bypass of
// the rank ceiling. The deployment owner applying the seed file is, in practice,
// whoever holds the highest-ranked account, so that is the account recorded; it
// is also the only choice that can satisfy the ceiling for a seeded super_admin.
//
// An empty table means first boot and there is nothing to attribute to, which is
// the one case 016 lets through with no creator.
func seedAdminCreator(ctx context.Context, admins repository.AdminUserRepository) (string, error) {
	existing, err := admins.List(ctx)
	if err != nil {
		return "", fmt.Errorf("list admins: %w", err)
	}

	best, bestRank := "", -1
	for _, a := range existing {
		if a == nil {
			continue
		}
		if rank := adminRoleRank(a.Role); rank > bestRank {
			best, bestRank = a.ID, rank
		}
	}
	return best, nil
}

// adminRoleRank mirrors the rank column of auth.admin_roles. Unknown roles sort
// below every known one so they are never chosen as a creator.
func adminRoleRank(role string) int {
	for i, r := range rbac.ValidRoles {
		if string(r) == role {
			return i
		}
	}
	return -1
}

func seedUser(ctx context.Context, us UserSeed, users repository.UserRepository, pepper string) error {
	existing, err := users.GetByEmail(ctx, us.Email)
	if err != nil {
		return err
	}
	if existing != nil {
		fmt.Printf("seed: user %q already exists (id=%s), skipping\n", us.Email, existing.ID)
		return nil
	}

	userID, err := vaultcrypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("generate user ID: %w", err)
	}
	passwordHash, err := hashPassword(us.Password, pepper)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	locale := us.Locale
	if locale == "" {
		locale = "en"
	}

	emailVerified := true
	if us.EmailVerified != nil {
		emailVerified = *us.EmailVerified
	}

	now := time.Now()
	user := &model.User{
		ID:            userID,
		Email:         us.Email,
		PasswordHash:  passwordHash,
		DisplayName:   us.DisplayName,
		Locale:        locale,
		EmailVerified: emailVerified,
		CreatedAt:     now,
		UpdatedAt:     now,
		Roles:         us.Roles,
	}

	if err := users.Create(ctx, user); err != nil {
		return fmt.Errorf("create: %w", err)
	}

	fmt.Printf("seed: user %q created (id=%s)\n", us.Email, userID)
	return nil
}

// hashPassword is the Argon2id hasher used for every seeded credential. It is
// a variable so tests can drive the hashing-failure paths, which are otherwise
// only reachable when the process-wide argon2 semaphore is saturated.
// Production never reassigns it.
var hashPassword = vaultcrypto.HashPassword
