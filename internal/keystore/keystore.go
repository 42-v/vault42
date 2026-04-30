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

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// ErrNoActiveKey is returned when no active signing key exists in the database.
var ErrNoActiveKey = errors.New("keystore: no active signing key")

// KeyRecord represents a signing key row from auth.signing_keys.
type KeyRecord struct {
	KID        string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Algorithm  string
	Status     string // "active", "retired", "revoked"
	CreatedAt  time.Time
	RetiredAt  *time.Time
	ExpiresAt  *time.Time
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

	stopCh chan struct{}
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

	// Insert new active key
	_, err = tx.Exec(ctx, `
		INSERT INTO auth.signing_keys (kid, private_key, public_key, algorithm, status, created_at)
		VALUES ($1, $2, $3, 'RS256', 'active', $4)
		ON CONFLICT (kid) DO UPDATE SET
			private_key = EXCLUDED.private_key,
			public_key = EXCLUDED.public_key,
			status = 'active',
			retired_at = NULL,
			expires_at = NULL
	`, kid, encPriv, pubDER, now)
	if err != nil {
		return "", fmt.Errorf("keystore: insert key: %w", err)
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

		// Parse public key (always needed for JWKS)
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

		// Decrypt private key only for active key
		if status == "active" {
			privPEM, err := vaultcrypto.Decrypt(encPriv, ks.masterKey, []byte(kid))
			if err != nil {
				return fmt.Errorf("keystore: decrypt key %s: %w", kid, err)
			}
			privKey, _, err := vaultcrypto.LoadSigningKeyPEM(privPEM)
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

	// Update in-memory state
	ks.mu.Lock()
	prevKID := ks.activeKID
	ks.activeKey = activeKey
	ks.activeKID = activeKID
	ks.publicKeys = publicKeys
	ks.mu.Unlock()

	// Notify if active key changed
	if activeKID != prevKID && activeKey != nil && ks.onKeyChange != nil {
		ks.onKeyChange(activeKey, activeKID, publicKeys)
	}

	return nil
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

// KeyInfo is a metadata-only view of a signing key (no private key material).
type KeyInfo struct {
	KID       string     `json:"kid"`
	Algorithm string     `json:"algorithm"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// StartRefreshLoop starts a background goroutine that refreshes keys from the
// database at the given interval. Call Stop() to terminate the loop.
func (ks *KeyStore) StartRefreshLoop(ctx context.Context, interval time.Duration) {
	go func() {
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
func (ks *KeyStore) Stop() {
	close(ks.stopCh)
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
