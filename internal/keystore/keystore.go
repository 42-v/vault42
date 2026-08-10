// Package keystore provides database-backed signing key management with
// encryption at rest, automatic multi-pod refresh, and zero-downtime rotation.
// Keys are stored in PostgreSQL with the private key encrypted using AES-256-GCM
// (master key) and the kid as authenticated data (AAD).
package keystore

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// ErrNoActiveKey is returned when no active signing key exists in the database.
var ErrNoActiveKey = errors.New("keystore: no active signing key")

// ErrRevokedKey is returned when an import would reactivate a revoked key.
// Revocation is terminal: the realistic reason to revoke a signing key is that
// its private material leaked, so it must never come back as active.
var ErrRevokedKey = errors.New("keystore: key is revoked")

// KeyRecord is the decrypted, in-memory shape of an auth.signing_keys row.
// Unlike [KeyInfo] it carries private key material and must never be logged,
// serialized to a response, or written anywhere but memory.
type KeyRecord struct {
	// KID is the key identifier published in JWKS and in the JWT kid header.
	// It is derived from the public key, so the same key always yields the same
	// kid and re-importing a key updates its row rather than creating a second.
	KID string
	// PrivateKey is the signing key, decrypted from the row's AES-256-GCM
	// ciphertext under the master key with KID as AAD. Populated only for the
	// active key; retired keys are loaded for verification only.
	PrivateKey *rsa.PrivateKey
	// PublicKey is the verification key published in JWKS.
	PublicKey *rsa.PublicKey
	// Algorithm is the JWS signing algorithm for this key. Only "RS256" is
	// issued today.
	Algorithm string
	// Status is one of exactly "active", "retired" or "revoked". At most one
	// key is "active" and it is the only one that signs; "retired" keys still
	// verify until ExpiresAt so tokens outlive a rotation; "revoked" is
	// terminal and drops the key from JWKS immediately, on the assumption that
	// the private material leaked. Import refuses to move a row back out of
	// "revoked" (see [ErrRevokedKey]).
	Status string
	// CreatedAt is when the key was first stored.
	CreatedAt time.Time
	// RetiredAt is when the key stopped being active, nil while it still is.
	RetiredAt *time.Time
	// ExpiresAt is when a retired key stops verifying and becomes eligible for
	// deletion by CleanupExpired. Nil for the active key.
	ExpiresAt *time.Time
}

// OnKeyChangeFunc is a callback invoked when the active key changes.
// It receives the new active private key, its kid, and all public keys.
type OnKeyChangeFunc func(activeKey *rsa.PrivateKey, kid string, allPublicKeys map[string]*rsa.PublicKey)

// KeyStore manages signing keys stored in PostgreSQL with encryption at rest.
// It supports automatic refresh from the database, key rotation, and
// notifies subscribers when the active key changes.
type KeyStore struct {
	pool      *pgxpool.Pool
	masterKey []byte

	mu         sync.RWMutex
	activeKey  *rsa.PrivateKey
	activeKID  string
	publicKeys map[string]*rsa.PublicKey

	retentionPeriod time.Duration
	onKeyChange     OnKeyChangeFunc

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New creates a new KeyStore. masterKey must be exactly 32 bytes (AES-256).
func New(pool *pgxpool.Pool, masterKey []byte, retentionPeriod time.Duration) (*KeyStore, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("keystore: master key must be 32 bytes")
	}
	return &KeyStore{
		pool:            pool,
		masterKey:       masterKey,
		publicKeys:      make(map[string]*rsa.PublicKey),
		retentionPeriod: retentionPeriod,
		stopCh:          make(chan struct{}),
	}, nil
}

// SetOnKeyChange registers a callback invoked when the active key changes.
func (ks *KeyStore) SetOnKeyChange(fn OnKeyChangeFunc) {
	ks.onKeyChange = fn
}

// ActiveKey returns the current active signing key and its kid.
func (ks *KeyStore) ActiveKey() (*rsa.PrivateKey, string) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.activeKey, ks.activeKID
}

// AllPublicKeys returns all non-expired public keys (for JWKS).
func (ks *KeyStore) AllPublicKeys() map[string]*rsa.PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	// Return a copy to prevent external mutation
	cp := make(map[string]*rsa.PublicKey, len(ks.publicKeys))
	for k, v := range ks.publicKeys {
		cp[k] = v
	}
	return cp
}

// KeyProvider returns a function suitable for middleware.Auth that provides
// the current public key set. This avoids passing a static map.
func (ks *KeyStore) KeyProvider() func() map[string]*rsa.PublicKey {
	return ks.AllPublicKeys
}

// Import encrypts and stores a key in the database as the active key.
// Any existing active key is retired.
func (ks *KeyStore) Import(ctx context.Context, key *rsa.PrivateKey) (string, error) {
	kid := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

	privPEM, err := vaultcrypto.MarshalSigningKeyPEM(key)
	if err != nil {
		return "", fmt.Errorf("keystore: marshal private key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("keystore: marshal public key: %w", err)
	}

	// Encrypt private key with master key, using kid as AAD
	encPriv, err := vaultcrypto.Encrypt(privPEM, ks.masterKey, []byte(kid))
	config.ZeroBytes(privPEM)
	if err != nil {
		return "", fmt.Errorf("keystore: encrypt private key: %w", err)
	}

	tx, err := ks.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("keystore: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // rollback on committed tx is no-op

	// Retire current active key
	now := time.Now()
	expiresAt := now.Add(ks.retentionPeriod)
	_, err = tx.Exec(ctx, `
		UPDATE auth.signing_keys
		SET status = 'retired', retired_at = $1, expires_at = $2
		WHERE status = 'active'
	`, now, expiresAt)
	if err != nil {
		return "", fmt.Errorf("keystore: retire active key: %w", err)
	}

	// Insert new active key. The kid is derived from the public key, so
	// re-importing the same PEM always conflicts with the existing row; the
	// WHERE guard stops that upsert from reactivating a revoked key.
	result, err := tx.Exec(ctx, `
		INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at)
		VALUES ($1, $2, $3, 'RS256', 'active', $4)
		ON CONFLICT (kid) DO UPDATE SET
			private_key = EXCLUDED.private_key,
			public_key = EXCLUDED.public_key,
			status = 'active',
			retired_at = NULL,
			expires_at = NULL
		WHERE signing_keys.status != 'revoked'
	`, kid, encPriv, pubDER, now)
	if err != nil {
		return "", fmt.Errorf("keystore: insert key: %w", err)
	}
	if result.RowsAffected() == 0 {
		return "", fmt.Errorf("%w: %s cannot be reactivated", ErrRevokedKey, kid)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("keystore: commit: %w", err)
	}

	// Refresh in-memory state
	if err := ks.Refresh(ctx); err != nil {
		return "", fmt.Errorf("keystore: refresh after import: %w", err)
	}

	return kid, nil
}

// Rotate generates a new RSA-2048 key, stores it as active, and retires the old one.
func (ks *KeyStore) Rotate(ctx context.Context) (string, error) {
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		return "", fmt.Errorf("keystore: generate key: %w", err)
	}
	return ks.Import(ctx, key)
}

// Revoke immediately marks a key as revoked. It will be excluded from JWKS
// on the next refresh. Tokens signed with this key will fail validation.
func (ks *KeyStore) Revoke(ctx context.Context, kid string) error {
	result, err := ks.pool.Exec(ctx, `
		UPDATE auth.signing_keys SET status = 'revoked', retired_at = NOW()
		WHERE kid = $1 AND status != 'revoked'
	`, kid)
	if err != nil {
		return fmt.Errorf("keystore: revoke: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("keystore: key %s not found or already revoked", kid)
	}
	return ks.Refresh(ctx)
}

// Refresh loads all non-revoked, non-expired keys from the database and
// updates the in-memory state. Notifies OnKeyChange if the active key changed.
//
// The two partial-failure paths differ, deliberately, and neither is silent to
// an operator reading logs:
//
//   - A row whose public key will not parse, or is not RSA, is logged and
//     skipped. The rest of the key set still loads, so one corrupt row cannot
//     take the whole JWKS down; the cost is that the skipped kid disappears
//     from JWKS and live tokens signed by it start failing verification. This
//     is the intentional trade: a partial verification set beats none.
//
//   - A decrypt or parse failure on the active key aborts before applyKeys, so
//     the previously loaded key set stays in memory untouched. The process
//     keeps signing and verifying with what it already had rather than dropping
//     to no keys at all. Callers see the error; StartRefreshLoop only logs it,
//     so a persistently failing active key surfaces as a stale-key warning in
//     the log and not as an outage.
//
// A successful Refresh always replaces the whole set: keys are never merged
// with what was loaded before.
func (ks *KeyStore) Refresh(ctx context.Context) error {
	rows, err := ks.pool.Query(ctx, `
		SELECT kid, private_key, public_key, algorithm, status, created_at, retired_at, expires_at
		FROM auth.signing_keys
		WHERE status != 'revoked'
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at DESC
	`)
	if err != nil {
		return fmt.Errorf("keystore: query keys: %w", err)
	}
	defer rows.Close()

	var activeKey *rsa.PrivateKey
	var activeKID string
	publicKeys := make(map[string]*rsa.PublicKey)

	for rows.Next() {
		var kid, algorithm, status string
		var encPriv, pubDER []byte
		var createdAt time.Time
		var retiredAt, expiresAt *time.Time

		if err := rows.Scan(&kid, &encPriv, &pubDER, &algorithm, &status, &createdAt, &retiredAt, &expiresAt); err != nil {
			return fmt.Errorf("keystore: scan row: %w", err)
		}

		// Parse public key (always needed for JWKS). An unusable row is dropped
		// from this refresh rather than failing it: the kid vanishes from JWKS
		// and its live tokens stop verifying, which is preferable to a bad row
		// blocking every other key from loading.
		pubKeyRaw, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			log.Printf("keystore: skip key %s: parse public key: %v", kid, err)
			continue
		}
		rsaPub, ok := pubKeyRaw.(*rsa.PublicKey)
		if !ok {
			log.Printf("keystore: skip key %s: not RSA", kid)
			continue
		}
		publicKeys[kid] = rsaPub

		// Decrypt the private key only for the active key. Unlike the skip
		// above, this returns before applyKeys, so the in-memory set from the
		// last good refresh survives: a wrong master key or a corrupt row
		// leaves the process serving stale keys instead of no keys.
		if status == "active" {
			privPEM, err := vaultcrypto.Decrypt(encPriv, ks.masterKey, []byte(kid))
			if err != nil {
				return fmt.Errorf("keystore: decrypt key %s: %w", kid, err)
			}
			// The plaintext PEM of the signing key exists in this buffer and nowhere
			// else in the process. LoadSigningKeyPEM parses it into its own structure,
			// so afterwards the bytes are dead weight that would otherwise sit in a
			// heap block until it happened to be reused. Wiped inline rather than by
			// defer: this is a loop body, so a defer would hold every decrypted key
			// until Refresh returned. Wiped on the error path too, which is when a
			// core dump is most likely.
			privKey, _, err := vaultcrypto.LoadSigningKeyPEM(privPEM)
			config.ZeroBytes(privPEM)
			if err != nil {
				return fmt.Errorf("keystore: parse key %s: %w", kid, err)
			}
			activeKey = privKey
			activeKID = kid
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("keystore: iterate rows: %w", err)
	}

	ks.applyKeys(activeKey, activeKID, publicKeys)

	return nil
}

// applyKeys swaps in a freshly loaded key set and notifies the subscriber when
// the active kid changed.
//
// The loss of the active key propagates too. Revoking the sole active key drops
// it from the verification set immediately, so a signer left holding it would
// mint tokens that fail validation on arrival: a total token outage reported as
// success. Handing the subscriber a nil key instead makes issuance fail closed.
func (ks *KeyStore) applyKeys(activeKey *rsa.PrivateKey, activeKID string, publicKeys map[string]*rsa.PublicKey) {
	ks.mu.Lock()
	prevKID := ks.activeKID
	ks.activeKey = activeKey
	ks.activeKID = activeKID
	ks.publicKeys = publicKeys
	ks.mu.Unlock()

	if activeKID == prevKID {
		return
	}
	if activeKey == nil {
		log.Printf("%v: previous kid=%s was revoked or removed, token issuance fails closed until a key is activated", ErrNoActiveKey, prevKID)
	}
	if ks.onKeyChange != nil {
		ks.onKeyChange(activeKey, activeKID, publicKeys)
	}
}

// ListKeys returns metadata about all signing keys (no private key material).
func (ks *KeyStore) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	rows, err := ks.pool.Query(ctx, `
		SELECT kid, algorithm, status, created_at, retired_at, expires_at
		FROM auth.signing_keys
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("keystore: list keys: %w", err)
	}
	defer rows.Close()

	var keys []KeyInfo
	for rows.Next() {
		var ki KeyInfo
		if err := rows.Scan(&ki.KID, &ki.Algorithm, &ki.Status, &ki.CreatedAt, &ki.RetiredAt, &ki.ExpiresAt); err != nil {
			return nil, fmt.Errorf("keystore: scan key info: %w", err)
		}
		keys = append(keys, ki)
	}
	return keys, rows.Err()
}

// KeyInfo is a metadata-only view of a signing key. It deliberately has no
// field for key material: it is the shape returned to admin API clients, and
// omitting the private key from the type makes leaking it a compile error
// rather than a review catch.
type KeyInfo struct {
	// KID is the key identifier as published in JWKS.
	KID string `json:"kid"`
	// Algorithm is the JWS signing algorithm, "RS256" for keys this store issues.
	Algorithm string `json:"algorithm"`
	// Status is "active", "retired" or "revoked"; see [KeyRecord.Status] for
	// what each state permits.
	Status string `json:"status"`
	// CreatedAt is when the key was first stored.
	CreatedAt time.Time `json:"created_at"`
	// RetiredAt is when the key stopped being active, absent while it still is.
	RetiredAt *time.Time `json:"retired_at,omitempty"`
	// ExpiresAt is when a retired key stops verifying, absent for the active key.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// StartRefreshLoop starts a background goroutine that refreshes keys from the
// database at the given interval, which is how a pod picks up a rotation
// performed by another pod. Call Stop to terminate the loop.
//
// A failing Refresh is logged and the loop continues. Since Refresh leaves the
// previous key set in place on an active-key failure, a pod whose refreshes
// keep failing serves stale keys indefinitely rather than losing the ability to
// sign; the log line is the only signal, so it belongs in an alert.
func (ks *KeyStore) StartRefreshLoop(ctx context.Context, interval time.Duration) {
	ks.wg.Add(1)
	go func() {
		defer ks.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := ks.Refresh(ctx); err != nil {
					log.Printf("keystore: refresh failed: %v", err)
				}
			case <-ks.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop terminates the refresh loop and zeros the master key.
//
// It blocks until the refresh loop has exited. Refresh reads masterKey outside
// ks.mu (AES-GCM decrypt of the active key), so zeroing it while a refresh is
// still in flight is a data race on live key material — and a refresh that read
// the half-zeroed key would fail to decrypt. Stop is idempotent: a second call
// must not re-close stopCh.
func (ks *KeyStore) Stop() {
	ks.stopOnce.Do(func() { close(ks.stopCh) })
	ks.wg.Wait()
	ks.mu.Lock()
	for i := range ks.masterKey {
		ks.masterKey[i] = 0
	}
	ks.mu.Unlock()
}

// EnsureKey loads keys from the database. If no active key exists,
// it either imports the provided key or generates a new one.
func (ks *KeyStore) EnsureKey(ctx context.Context, importKey *rsa.PrivateKey) error {
	// Try loading existing keys first
	if err := ks.Refresh(ctx); err != nil {
		return err
	}

	ks.mu.RLock()
	hasActive := ks.activeKey != nil
	ks.mu.RUnlock()

	if hasActive {
		return nil
	}

	// No active key in DB — import or generate
	if importKey != nil {
		kid, err := ks.Import(ctx, importKey)
		if err != nil {
			return fmt.Errorf("keystore: import initial key: %w", err)
		}
		log.Printf("keystore: imported initial key (kid=%s)", kid)
	} else {
		kid, err := ks.Rotate(ctx)
		if err != nil {
			return fmt.Errorf("keystore: generate initial key: %w", err)
		}
		log.Printf("keystore: generated initial key (kid=%s)", kid)
	}
	return nil
}

// CleanupExpired removes expired retired keys from the database.
// Called periodically during refresh to prevent table bloat.
func (ks *KeyStore) CleanupExpired(ctx context.Context) (int64, error) {
	result, err := ks.pool.Exec(ctx, `
		DELETE FROM auth.signing_keys
		WHERE status = 'retired' AND expires_at IS NOT NULL AND expires_at < NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("keystore: cleanup: %w", err)
	}
	return result.RowsAffected(), nil
}
