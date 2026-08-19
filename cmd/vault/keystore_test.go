package main

// The DB-backed keystore branch.
//
// VAULT_KEY_ROTATION_DB swaps the whole signing-key strategy: instead of a key
// from a file or a key generated per process, every replica reads its signing
// keys from PostgreSQL, decrypts them with the master key, and re-reads them on
// a timer so an operator can rotate without a restart. main() is where that
// wiring lives, and it is the part of the startup that a file-based deployment
// never executes.
//
// Two things are worth pinning here and nowhere else. The key the JWKS publishes
// must be the key that is in the database, because a mismatch means every
// relying party rejects every token this replica signs. And a rotation written
// to the database must reach a running process, because that is the entire
// reason the keystore exists.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"syscall"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// keystoreMasterKey is the AES-256 key the scripted rows are encrypted under. It
// is also what MASTER_KEY_FILE holds, which is the point: a row this test writes
// must be decryptable by the process under test with no other coordination.
const keystoreMasterKey = "0123456789abcdef0123456789abcdef"

// signingKeyRow is one row of auth.signing_keys, built exactly as
// KeyStore.Import would have written it.
type signingKeyRow struct {
	kid    string
	values [][]byte
}

// newSigningKeyRow generates a key and encodes it the way the keystore stores
// it: the private key as PKCS#8 PEM sealed under the master key with the kid as
// AAD, the public key as PKIX DER, and the kid derived from the public key.
func newSigningKeyRow(t *testing.T, status string, createdAt time.Time) signingKeyRow {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

	privPEM, err := vaultcrypto.MarshalSigningKeyPEM(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	encPriv, err := vaultcrypto.Encrypt(privPEM, []byte(keystoreMasterKey), []byte(kid))
	if err != nil {
		t.Fatalf("seal private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	return signingKeyRow{
		kid: kid,
		values: [][]byte{
			pgText(kid),
			pgBytea(encPriv),
			pgBytea(pubDER),
			pgText("RS256"),
			pgText(status),
			pgTimestamptz(createdAt),
			nil, // retired_at
			nil, // expires_at
		},
	}
}

// signingKeysRule scripts the SELECT that KeyStore.Refresh runs.
func signingKeysRule(rows ...signingKeyRow) pgRule {
	values := make([][][]byte, 0, len(rows))
	for _, r := range rows {
		values = append(values, r.values)
	}
	return signingKeysRuleFunc(func(int) [][][]byte { return values })
}

// signingKeysRuleFunc is signingKeysRule for a table whose contents change
// between refreshes.
func signingKeysRuleFunc(answers func(prior int) [][][]byte) pgRule {
	return pgRule{
		match:   "FROM auth.signing_keys",
		answers: answers,
		cols: []pgColumn{
			{name: "kid", oid: pgOIDText},
			{name: "private_key", oid: pgOIDBytea},
			{name: "public_key", oid: pgOIDBytea},
			{name: "algorithm", oid: pgOIDText},
			{name: "status", oid: pgOIDText},
			{name: "created_at", oid: pgOIDTimestamptz},
			{name: "retired_at", oid: pgOIDTimestamptz},
			{name: "expires_at", oid: pgOIDTimestamptz},
		},
	}
}

// importSigningKeyRule scripts auth.import_signing_key, the SECURITY DEFINER
// function migration 037 made the only writer of a signing key's material.
// wrote is what KeyStore.Import reads to tell a stored key from a kid the
// function refused to overwrite because it is revoked.
func importSigningKeyRule(wrote bool) pgRule {
	return pgRule{
		match: "auth.import_signing_key",
		cols:  []pgColumn{{name: "import_signing_key", oid: pgOIDBool}},
		rows:  [][][]byte{{pgBool(wrote)}},
	}
}

// keystoreEnv is bootEnv plus the two variables that turn the keystore on.
func keystoreEnv(t *testing.T, stub *pgStub, addr string) map[string]string {
	t.Helper()
	env := bootEnv(t, stub, addr)
	env["VAULT_KEY_ROTATION_DB"] = "true"
	env["MASTER_KEY_FILE"] = secretFile(t, t.TempDir(), "master.key", keystoreMasterKey)
	return env
}

// TestDBBackedKeystorePublishesTheKeyFromTheDatabase asserts the load path end
// to end: the row is decrypted with the master key, adopted as the active key,
// and published under its own kid. The JWKS check is the one that matters. A
// keystore that loaded a key but left the published set behind would sign tokens
// no verifier could check, and the log line alone would look healthy.
func TestDBBackedKeystorePublishesTheKeyFromTheDatabase(t *testing.T) {
	active := newSigningKeyRow(t, "active", time.Now())
	retired := newSigningKeyRow(t, "retired", time.Now().Add(-time.Hour))

	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		signingKeysRule(active, retired),
	)
	addr := freeAddr(t)

	var jwks string
	res := bootAndShutdown(t, vaultRun{env: keystoreEnv(t, stub, addr)}, addr, syscall.SIGTERM, func(t *testing.T) {
		_, jwks = get(t, addr, "/.well-known/jwks.json")
	})

	requireExit(t, res, 0, "DB-backed keystore active (kid="+active.kid+", 2 keys in JWKS)")
	if !strings.Contains(jwks, active.kid) {
		t.Fatalf("JWKS does not publish the active kid %q: %s", active.kid, jwks)
	}
	// A retired key stays verifiable so tokens signed before the rotation keep
	// working until they expire.
	if !strings.Contains(jwks, retired.kid) {
		t.Fatalf("JWKS dropped the retired kid %q, invalidating tokens still in flight: %s", retired.kid, jwks)
	}
	if strings.Contains(res.stderr, "No SIGNING_KEY_FILE") {
		t.Fatalf("the keystore branch fell through to the ephemeral key\nstderr:\n%s", res.stderr)
	}
	requireNoSecretLeak(t, res, keystoreMasterKey)
}

// TestDBBackedKeystoreAdoptsARotationWhileRunning is the reason the refresh loop
// exists. An operator rotates by writing a new active row; every replica must
// notice on its own timer, start signing with the new key, and keep publishing
// the old one so tokens already issued still verify. Nothing restarts.
//
// Minting is enabled here on purpose. With a keystore present the mint service
// is handed the keystore's own accessor rather than the key captured at boot, so
// a regression that passed the boot-time snapshot would leave minted tokens
// signed by a key that is no longer active.
func TestDBBackedKeystoreAdoptsARotationWhileRunning(t *testing.T) {
	first := newSigningKeyRow(t, "active", time.Now().Add(-time.Hour))
	second := newSigningKeyRow(t, "active", time.Now())

	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		signingKeysRule(first),
	)
	addr := freeAddr(t)
	env := keystoreEnv(t, stub, addr)
	env["VAULT_KEY_REFRESH_INTERVAL"] = "100ms"
	env["VAULT_MINT_ENABLED"] = "true"
	env["VAULT_MINT_AUDIENCE"] = "https://beon3.test"
	env["VAULT_MINT_ROLES"] = "service"

	p := startVault(t, vaultRun{env: env})
	awaitServing(t, p, addr, 60*time.Second)

	if _, jwks := get(t, addr, "/.well-known/jwks.json"); !strings.Contains(jwks, first.kid) {
		t.Fatalf("JWKS does not publish the initial kid %q: %s", first.kid, jwks)
	}

	// Rotate in the database: the new key becomes active, the old one retires.
	rotated := first
	rotated.values[4] = pgText("retired")
	stub.setRules(
		adminTokenRule("$argon2id$already-provisioned"),
		signingKeysRule(second, rotated),
	)

	p.awaitStderr(t, "keystore: active key rotated to kid="+second.kid, 30*time.Second)

	_, jwks := get(t, addr, "/.well-known/jwks.json")
	for _, kid := range []string{first.kid, second.kid} {
		if !strings.Contains(jwks, kid) {
			t.Fatalf("JWKS lost kid %q after the rotation: %s", kid, jwks)
		}
	}

	p.signal(t, syscall.SIGTERM)
	res := p.wait(t, 60*time.Second)
	requireExit(t, res, 0, "Shutting down...")
	requireNoSecretLeak(t, res, keystoreMasterKey)
}

// TestDBBackedKeystoreImportsTheFileKeyOnFirstBoot covers the migration path
// from a file-based deployment. With an empty signing_keys table and a
// SIGNING_KEY_FILE present, the file key is imported rather than a fresh one
// generated, so switching a running deployment to the keystore does not
// invalidate the tokens it has already issued.
func TestDBBackedKeystoreImportsTheFileKeyOnFirstBoot(t *testing.T) {
	keyPEM, kid := signingKeyPEM(t)

	// The table starts empty, so EnsureKey imports. Migration 037 moved the
	// upsert into auth.import_signing_key, so the write is a SELECT of that
	// function and it must answer true: false is how the function reports a
	// revoked kid it declined to overwrite, and the keystore reads it as such.
	// The follow-up refresh then returns the imported key.
	imported := importedKeyRow(t, keyPEM, kid)
	stub := startPGStub(t,
		adminTokenRule("$argon2id$already-provisioned"),
		importSigningKeyRule(true),
		signingKeysRuleFunc(func(prior int) [][][]byte {
			if prior == 0 {
				return nil // the table is empty until the import writes to it
			}
			return [][][]byte{imported.values}
		}),
	)
	addr := freeAddr(t)
	env := keystoreEnv(t, stub, addr)
	env["SIGNING_KEY_FILE"] = secretFile(t, t.TempDir(), "signing.pem", keyPEM)

	var jwks string
	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, func(t *testing.T) {
		_, jwks = get(t, addr, "/.well-known/jwks.json")
	})

	requireExit(t, res, 0, "keystore: imported initial key (kid="+kid+")")
	if !strings.Contains(jwks, kid) {
		t.Fatalf("JWKS does not publish the imported kid %q: %s", kid, jwks)
	}
	requireNoSecretLeak(t, res, keyPEM, keystoreMasterKey)
}

// importedKeyRow renders an existing PEM key as the row the keystore would have
// written for it.
func importedKeyRow(t *testing.T, keyPEM, kid string) signingKeyRow {
	t.Helper()
	key, _, err := vaultcrypto.LoadSigningKeyPEM([]byte(keyPEM))
	if err != nil {
		t.Fatalf("load fixture key: %v", err)
	}
	encPriv, err := vaultcrypto.Encrypt([]byte(keyPEM), []byte(keystoreMasterKey), []byte(kid))
	if err != nil {
		t.Fatalf("seal fixture key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal fixture public key: %v", err)
	}
	return signingKeyRow{
		kid: kid,
		values: [][]byte{
			pgText(kid), pgBytea(encPriv), pgBytea(pubDER),
			pgText("RS256"), pgText("active"), pgTimestamptz(time.Now()), nil, nil,
		},
	}
}
