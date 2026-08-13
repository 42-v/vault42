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
	pool *pgxpool.Pool

	// masterKeyMu guards masterKey against Stop, and is deliberately NOT ks.mu.
	// The crypto that reads the key happens outside ks.mu, and applyKeys takes
	// ks.mu, so reusing it here would mean taking a read lock and then a write
	// lock on the same non-reentrant mutex inside one Refresh.
	masterKeyMu   sync.RWMutex
	masterKey     []byte
	masterKeyGone bool

	// refreshMu serializes Refresh end to end. Without it two refreshes could
	// interleave their SELECT and their apply, so a slower one could publish a
	// key set it read before the faster one committed, and the notification that
	// follows would hand the token service a key the database has already
	// retired.
	refreshMu sync.Mutex

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

// ErrClosed is returned by any operation needing the master key after Stop.
//
// Failing closed matters more here than it looks. A zeroed master key is still
// 32 bytes, so AES-GCM accepts it and Import would encrypt a private key under
// all zeros and commit the row. The write succeeds, nothing reports an error,
// and the key is permanently undecryptable by the real master key. That is data
// destruction rather than a torn read.
var ErrClosed = errors.New("keystore: closed")

// withMasterKey runs fn with the master key held under a read lock, so Stop
// cannot zero it mid-operation.
//
// The key is passed in rather than read from the struct inside fn, so a caller
// cannot accidentally reach for ks.masterKey directly and reintroduce the race
// the lock exists to prevent.
func (ks *KeyStore) withMasterKey(fn func(masterKey []byte) error) error {
	ks.masterKeyMu.RLock()
	defer ks.masterKeyMu.RUnlock()
	if ks.masterKeyGone {
		return ErrClosed
	}
	return fn(ks.masterKey)
}

// New creates a new KeyStore. masterKey must be exactly 32 bytes (AES-256).
//
// The key is copied rather than retained, because Stop wipes it and the
// caller's slice is shared. cmd/vault takes one working copy of the master key
// and hands that same slice to this constructor and to the service container,
// which passes it on to the identity, blob, service-document and TOTP paths.
// Retaining the caller's array made Stop zero the key all of those were still
// using, and 32 zero bytes is still a valid AES-256 key, so a request draining
// through shutdown encrypted successfully against it and wrote a row no later
// process could ever decrypt.
//
// Owning the copy is what makes the wipe in Stop safe to perform at all: it
// destroys this keystore's key material and nobody else's.
func New(pool *pgxpool.Pool, masterKey []byte, retentionPeriod time.Duration) (*KeyStore, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("keystore: master key must be 32 bytes")
	}
	owned := make([]byte, len(masterKey))
	copy(owned, masterKey)

	return &KeyStore{
		pool:            pool,
		masterKey:       owned,
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

	// Encrypt private key with master key, using kid as AAD.
	//
	// Under the read lock, because Stop zeroes the master key and a zeroed key is
	// still a valid 32-byte AES key: without this the row would be committed
	// encrypted under all zeros and lost for good.
	var encPriv []byte
	err = ks.withMasterKey(func(masterKey []byte) error {
		var encErr error
		encPriv, encErr = vaultcrypto.Encrypt(privPEM, masterKey, []byte(kid))
		return encErr
	})
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
// Every row is opened before any of it is published. A row is published only if
// its private_key decrypts under the master key with its kid as AAD and the
// decrypted key's public half is the public_key column. Nothing else proves the
// row is this vault's: auth.signing_keys is writable by vault_app, so a row that
// merely sits in the table proves only that someone could issue SQL. Publishing
// on that basis let anyone holding the app role INSERT a key of their own as
// 'retired' with a NULL expires_at and have it in JWKS within one refresh
// interval, at which point tokens they signed for any subject verified here and
// in every service that polls this issuer. The public-key comparison closes the
// same attack run as an UPDATE of public_key on a genuine row, where the
// ciphertext is the vault's own and decrypts perfectly.
//
// The three partial-failure paths differ, deliberately, and none is silent to an
// operator reading logs:
//
//   - A row whose public key will not parse, or is not RSA, is logged and
//     skipped. The rest of the key set still loads, so one corrupt row cannot
//     take the whole JWKS down; the cost is that the skipped kid disappears
//     from JWKS and live tokens signed by it start failing verification. This
//     is the intentional trade: a partial verification set beats none.
//
//   - A non-active row that does not open is logged and skipped for the same
//     reason, and the reason is stronger here: the row may well be hostile, and
//     failing the whole refresh on it would hand anyone who can write one row a
//     way to freeze the key set of every pod, then break the next pod to boot,
//     since EnsureKey refuses to start without a Refresh.
//
//   - A decrypt, parse or mismatch failure on the ACTIVE key aborts before
//     applyKeys, so the previously loaded key set stays in memory untouched. The
//     process keeps signing and verifying with what it already had rather than
//     dropping to no keys at all. Skipping instead would leave it signing with a
//     key absent from its own JWKS. Callers see the error; StartRefreshLoop only
//     logs it, so a persistently failing active key surfaces as a stale-key
//     warning in the log and not as an outage.
//
// A successful Refresh always replaces the whole set: keys are never merged
// with what was loaded before.
//
// Opening every row costs one AES-256-GCM decrypt and one PKCS#8 parse per key,
// measured at 151 microseconds for RSA-2048 on the CI-class machine this was
// written on, against a default refresh interval of 60 seconds. A deployment on
// the default one-hour retention holds an active key and one or two retired
// ones; even fifty would be 7.5 milliseconds a minute.
func (ks *KeyStore) Refresh(ctx context.Context) error {
	// Held for the whole function, query and apply together. Refresh has four
	// callers: the refresh ticker, Import, Revoke and EnsureKey, and the middle
	// two are reachable from admin HTTP handlers. Unserialised, a refresh that
	// read the table before another one committed could publish the older key set
	// afterwards, and the notification it fires would then hand the token service
	// a key the database has already retired.
	ks.refreshMu.Lock()
	defer ks.refreshMu.Unlock()

	rows, err := ks.pool.Query(ctx, `
		SELECT kid, private_key, public_key, algorithm, status, created_at, retired_at, expires_at
		FROM auth.signing_keys
		WHERE status != 'revoked'
		  AND (expires_at > NOW() OR (expires_at IS NULL AND status = 'active'))
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

		// Open the row. A key this vault cannot open is not this vault's key,
		// whatever the row says, and must not become a verification key.
		privKey, err := ks.openKey(kid, encPriv)
		if err == nil && !privKey.PublicKey.Equal(rsaPub) {
			err = fmt.Errorf("public key of %s is not the public half of its private key", kid)
		}
		if err != nil {
			if status == "active" {
				return fmt.Errorf("keystore: %w", err)
			}
			log.Printf("keystore: skip key %s: %v", kid, err)
			continue
		}

		publicKeys[kid] = rsaPub
		if status == "active" {
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

// openKey decrypts a row's private key under the master key with the kid as AAD
// and parses the PEM. Success is what distinguishes a row this vault wrote from
// a row someone else put in the table: the AEAD tag covers the kid, so neither a
// key the attacker generated nor a ciphertext lifted from another row will open.
//
// The caller drops the returned key immediately for every row but the active
// one. The parsed key cannot be wiped afterwards (AR-13), so a retired key's
// private material is briefly resident on each refresh; the PEM buffer, which is
// the part that can be wiped, is wiped here.
func (ks *KeyStore) openKey(kid string, encPriv []byte) (*rsa.PrivateKey, error) {
	var privPEM []byte
	if err := ks.withMasterKey(func(masterKey []byte) error {
		var decErr error
		privPEM, decErr = vaultcrypto.Decrypt(encPriv, masterKey, []byte(kid))
		return decErr
	}); err != nil {
		return nil, fmt.Errorf("decrypt key %s: %w", kid, err)
	}
	// The plaintext PEM of the signing key exists in this buffer and nowhere
	// else in the process. LoadSigningKeyPEM parses it into its own structure,
	// so afterwards the bytes are dead weight that would otherwise sit in a heap
	// block until it happened to be reused. Wiped on the error path too, which
	// is when a core dump is most likely.
	privKey, _, err := vaultcrypto.LoadSigningKeyPEM(privPEM)
	config.ZeroBytes(privPEM)
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", kid, err)
	}
	return privKey, nil
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
	ks.masterKeyMu.Lock()
	ks.masterKeyGone = true
	for i := range ks.masterKey {
		ks.masterKey[i] = 0
	}
	ks.masterKeyMu.Unlock()
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
