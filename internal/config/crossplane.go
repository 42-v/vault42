package config

import (
	"context"
	"errors"
	"fmt"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// Cross-plane agreement on HMAC_SECRET.
//
// vault42 runs as two processes against one database: cmd/vault serves users,
// cmd/admin-gateway serves operators. Three of the stores an erasure has to
// clear — identity.profiles, objects.blobs and objects.service_documents — are
// keyed by a subject pseudonym HMAC'd under HMAC_SECRET rather than by user id
// (see ErasureService.identityPseudonym and friends). Both planes must
// therefore hold the same secret, and nothing checked that they did.
//
// An ABSENT secret is fail-safe. cmd/vault refuses to start without one in
// every non-dev profile, and cmd/admin-gateway leaves DELETE /admin/users/{id}
// answering 503. A DIVERGENT secret is not. Every pseudonym the admin plane
// derives is then a different string from the one the user plane wrote, so each
// DELETE ... WHERE pseudonym = $1 matches zero rows, returns no error, and the
// cascade runs on to a nil return and an AccountErased audit row. The subject is
// told their data is gone while their identity profile, their blobs and every
// document other services filed about them are still in the database. That is an
// Article 17 erasure that erased almost nothing, and it is silent by
// construction: clearing zero rows is also what erasing an account that held no
// profile looks like, so no amount of care inside the cascade can tell them
// apart.
//
// Neither plane can read the other's configuration, and neither may learn the
// other's secret, so what is compared is a fingerprint: an HMAC of a fixed
// public label under the secret. It cannot be turned back into the secret, and
// it is equal exactly when the secrets are. The first plane to boot records it
// in auth.admin_config, a table both database roles are already granted; every
// later boot claims the same row and is handed whatever is already recorded.

// HMACFingerprintKey is the auth.admin_config key both planes record their
// HMAC secret fingerprint under.
const HMACFingerprintKey = "hmac_secret_fingerprint"

// hmacFingerprintLabel is the message the fingerprint HMACs. It is fixed and
// public on purpose: what makes two fingerprints comparable is that the key is
// the only input that can differ between planes.
const hmacFingerprintLabel = "vault42/cross-plane/hmac-secret/v1"

// hmacFingerprintHexLen keeps 128 bits of the HMAC, as 32 hex characters.
// Publishing the full width would be no less safe — HMAC-SHA256 does not leak
// its key through its output — but the value lands in a table operators read
// through GET /admin/config, and a comparison needs no more of the PRF than
// this.
const hmacFingerprintHexLen = 32

// ErrHMACPlaneMismatch reports that the fingerprint already recorded in the
// database was produced by a different HMAC secret than this process holds.
//
// It is a sentinel so each plane can treat disagreement (a deployment that
// would silently under-erase) differently from an unreadable store (a database
// that is broken in ways its own errors will report).
var ErrHMACPlaneMismatch = errors.New("HMAC_SECRET disagrees with the other vault42 plane")

// HMACSecretFingerprint derives the comparable, non-secret fingerprint of an
// HMAC secret.
//
// Safe to log, store and show an operator: it is HMAC-SHA256 of a constant
// under the secret, so recovering the secret from it means recovering an
// HMAC key from one known-message tag.
func HMACSecretFingerprint(secret []byte) string {
	return vaultcrypto.HMACSign([]byte(hmacFingerprintLabel), secret)[:hmacFingerprintHexLen]
}

// CrossPlaneConfigStore is the narrow view of auth.admin_config this check
// needs. It is declared here rather than reused from repository so that the
// check depends on one method and not on the admin configuration API.
type CrossPlaneConfigStore interface {
	// ClaimIfAbsent records value under key when the key holds nothing yet and
	// returns the value the key holds afterwards: value when this caller
	// claimed it, the incumbent when another plane already had. It must be
	// atomic — two planes booting at the same moment must not both conclude
	// they claimed the row.
	ClaimIfAbsent(ctx context.Context, key, value string) (string, error)
}

// VerifyHMACPlaneAgreement records this plane's HMAC secret fingerprint and
// compares it against whatever the other plane recorded.
//
// nil means the planes agree, or that there is no secret here to compare —
// absent is the fail-safe case and is each plane's own validation to enforce.
// ErrHMACPlaneMismatch (wrapped, with both fingerprints) means they disagree
// and this deployment would under-erase. Any other error means the store could
// not be read and the question is unanswered; the caller decides what an
// unanswered question is worth, which is not the same decision as a mismatch.
func VerifyHMACPlaneAgreement(ctx context.Context, store CrossPlaneConfigStore, secret []byte) error {
	if len(secret) == 0 {
		return nil
	}
	mine := HMACSecretFingerprint(secret)
	recorded, err := store.ClaimIfAbsent(ctx, HMACFingerprintKey, mine)
	if err != nil {
		return fmt.Errorf("cross-plane HMAC_SECRET check: claim %s: %w", HMACFingerprintKey, err)
	}
	if recorded != mine {
		return fmt.Errorf("%w: this plane's HMAC_SECRET fingerprints as %s, the plane that recorded first "+
			"had %s. Subject pseudonyms derived from two different secrets never match, so an account "+
			"erasure would clear zero rows from identity.profiles, objects.blobs and "+
			"objects.service_documents and still report success. Point both planes at the same "+
			"HMAC_SECRET_FILE. If the secret was re-keyed deliberately, every pseudonym already written "+
			"is unreadable and must be re-derived before the %s row in auth.admin_config is cleared",
			ErrHMACPlaneMismatch, mine, recorded, HMACFingerprintKey)
	}
	return nil
}
