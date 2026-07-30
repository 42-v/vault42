package service

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// ErrUserNotFound is returned by DeleteAccount when the target user does not
// exist (or was already erased).
var ErrUserNotFound = errors.New("user not found")

// ErasureService performs GDPR account erasure with key-recoverable escrow.
//
// On deletion it (optionally) writes an encrypted recovery record, cascade-
// deletes the user's PII, revokes all sessions, then scrubs and soft-deletes the
// user row. When a recovery public key is configured the escrow write happens
// FIRST and must succeed — the service fails closed rather than erase a user
// without a recoverable record.
type ErasureService struct {
	users       repository.UserRepository
	identity    repository.IdentityRepository
	blobs       repository.BlobRepository
	devices     repository.DeviceRepository
	social      repository.SocialAccountRepository
	pwHistory   repository.PasswordHistoryRepository
	tokens      repository.RefreshTokenRepository
	totp        repository.TOTPRepository
	webauthn    repository.WebAuthnRepository
	backupCodes repository.BackupCodeRepository
	recovery    repository.AccountRecoveryRepository
	auditLog    *audit.Logger
	recoveryPub *rsa.PublicKey
	hmacSecret  []byte
}

// NewErasureService constructs an ErasureService. recoveryPub may be nil, in
// which case recovery escrow is disabled and erasure still proceeds.
func NewErasureService(
	users repository.UserRepository,
	identity repository.IdentityRepository,
	blobs repository.BlobRepository,
	devices repository.DeviceRepository,
	social repository.SocialAccountRepository,
	pwHistory repository.PasswordHistoryRepository,
	tokens repository.RefreshTokenRepository,
	totp repository.TOTPRepository,
	webauthn repository.WebAuthnRepository,
	backupCodes repository.BackupCodeRepository,
	recovery repository.AccountRecoveryRepository,
	auditLog *audit.Logger,
	recoveryPub *rsa.PublicKey,
	hmacSecret []byte,
) *ErasureService {
	return &ErasureService{
		users: users, identity: identity, blobs: blobs, devices: devices,
		social: social, pwHistory: pwHistory, tokens: tokens,
		totp: totp, webauthn: webauthn, backupCodes: backupCodes, recovery: recovery,
		auditLog: auditLog, recoveryPub: recoveryPub, hmacSecret: hmacSecret,
	}
}

// recoveryPayload is the minimal recoverable profile escrowed on deletion. It is
// JSON-marshalled and encrypted; only the offline recovery private key can read it.
type recoveryPayload struct {
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	Roles       []string  `json:"roles"`
	DisplayName string    `json:"display_name"`
}

// DeleteAccount erases the user identified by userID. deletedBy records who
// initiated it ("self" or "admin:<id>") and reason is a short machine tag
// (e.g. "user_request"). It returns ErrUserNotFound if the user does not exist.
func (s *ErasureService) DeleteAccount(ctx context.Context, userID, deletedBy, reason string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("erasure: load user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	// The cascade below spans nine stores and the repositories are pool-backed, so
	// there is no transaction to roll back with: any step can fail with the ones
	// before it already committed. What matters is which side of the failure the
	// account is left on.
	//
	// Escrow, then tombstone, THEN purge. Scrubbing last would mean a mid-cascade
	// failure left a live, still-loginable account whose second factors had already
	// been destroyed — the user locked out of their own account, and nothing erased.
	// Tombstoning first inverts that: the account stops authenticating before any
	// PII is touched, so a failure leaves it dead-but-not-yet-fully-purged, and the
	// deletes below are all idempotent (DELETE ... WHERE user_id), so the operation
	// can simply be run again to finish the job.
	//
	// A re-run of an already-tombstoned account skips the escrow: the row now holds
	// the tombstone email, and escrowing that would overwrite the recovery record
	// with useless data.
	// tombstoned records whether THIS call did the escrow + scrub, or whether it is
	// finishing an erasure a previous, interrupted call had already started.
	tombstoned := !user.Deleted

	if tombstoned {
		// Escrow first, fail closed: when recovery is enabled we must not delete
		// without a recoverable record. A compromised server cannot read this back —
		// it is encrypted to the offline recovery public key.
		//
		// A failure between here and the scrub below leaves the account un-tombstoned,
		// so a retry escrows again: auth.account_recovery is append-only and has no
		// unique key, so the result is a duplicate record rather than an error. Both
		// copies are written before the scrub, so both hold the real address and
		// either can be used — recovery tooling must simply tolerate more than one
		// record per user, which is the safe direction (the alternative is deleting an
		// account with no recoverable copy at all).
		if s.recoveryPub != nil {
			if err := s.escrow(ctx, user, deletedBy, reason); err != nil {
				return err
			}
		}

		// Scrub + soft-delete the user row. The real email now lives only in the
		// encrypted recovery log; the row is kept for referential integrity and the
		// account-state gate rejects deleted=true users at login/refresh.
		tombstone := "deleted-" + userID + "@deleted.invalid"
		if err := s.users.SoftDeleteScrub(ctx, userID, tombstone); err != nil {
			return fmt.Errorf("erasure: scrub user: %w", err)
		}
	}

	// Cascade-delete PII. The identity profile and blobs are keyed by HMAC
	// pseudonyms derived the same way the identity/blob services derive them.
	if err := s.identity.Delete(ctx, s.identityPseudonym(userID)); err != nil {
		return fmt.Errorf("erasure: delete identity: %w", err)
	}
	if err := s.blobs.DeleteAllForPseudonym(ctx, s.blobPseudonym(userID)); err != nil {
		return fmt.Errorf("erasure: delete blobs: %w", err)
	}
	if err := s.devices.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("erasure: delete devices: %w", err)
	}
	if err := s.social.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("erasure: delete social accounts: %w", err)
	}
	if err := s.pwHistory.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("erasure: delete password history: %w", err)
	}

	// MFA authenticators. These hang off user_id with ON DELETE CASCADE, but the
	// user row is scrubbed with an UPDATE and never deleted — the cascade never
	// fires, so they must be removed explicitly or the encrypted TOTP secret, the
	// WebAuthn public keys and the backup-code hashes outlive the erased account.
	if err := s.totp.DeleteByUserID(ctx, userID); err != nil {
		return fmt.Errorf("erasure: delete totp secret: %w", err)
	}
	if err := s.webauthn.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("erasure: delete webauthn credentials: %w", err)
	}
	// Purge, not DeleteAllForUser: the latter only marks codes used, which leaves
	// the hash and the user_id in the table.
	if err := s.backupCodes.PurgeAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("erasure: purge backup codes: %w", err)
	}

	// Hard-delete rather than revoke: a revoked row keeps the fingerprint hash and
	// the device reference, and an erased account has no replay left to detect.
	if err := s.tokens.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("erasure: delete tokens: %w", err)
	}

	if s.auditLog != nil {
		meta := map[string]interface{}{
			"deleted_by": deletedBy,
			"reason":     reason,
			"recovered":  s.recoveryPub != nil,
		}
		// On a retry of an interrupted erasure the row already holds the tombstone,
		// so user.Email is "deleted-<id>@deleted.invalid". Masking that and filing it
		// as the erased address would put a fabricated value in the one record an
		// investigator would trust. Say what actually happened instead.
		if tombstoned {
			meta["email"] = maskEmail(user.Email)
		} else {
			meta["retry"] = true
			meta["note"] = "cascade completed on re-run; address was recorded by the original attempt"
		}
		_ = s.auditLog.Log(ctx, audit.AccountErased, userID, "", "", "", "", "", meta, 50) // #nosec G104 -- audit is best-effort
	}

	return nil
}

// escrow writes one encrypted recovery record. Any failure aborts deletion.
//
// The record outlives the erasure on purpose, so it is bounded by time instead:
// VAULT_RECOVERY_RETENTION_DAYS + RecoveryRetention, the same shape as the audit
// log (Art. 5(1)(e)). Do not put anything in the payload that the retention
// horizon would not eventually clear, and keep docs/PRIVACY.md §3.2 in step with
// what recoveryPayload actually carries.
func (s *ErasureService) escrow(ctx context.Context, user *model.User, deletedBy, reason string) error {
	payload, err := json.Marshal(recoveryPayload{
		Email:       user.Email,
		CreatedAt:   user.CreatedAt,
		Roles:       user.Roles,
		DisplayName: user.DisplayName,
	})
	if err != nil {
		return fmt.Errorf("erasure: marshal recovery payload: %w", err)
	}

	enc, err := vaultcrypto.EncryptRecovery(s.recoveryPub, payload)
	if err != nil {
		return fmt.Errorf("erasure: encrypt recovery payload: %w", err)
	}

	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("erasure: recovery record id: %w", err)
	}

	rec := &model.AccountRecovery{
		ID:        id,
		Pseudonym: s.recoveryPseudonym(user.ID),
		Payload:   enc,
		DeletedAt: time.Now(),
		DeletedBy: deletedBy,
		Reason:    reason,
	}
	if err := s.recovery.Append(ctx, rec); err != nil {
		// Fail closed: do not proceed to delete without an escrow record.
		return fmt.Errorf("erasure: append recovery record: %w", err)
	}
	return nil
}

func (s *ErasureService) identityPseudonym(userID string) string {
	return vaultcrypto.HMACSign([]byte(userID+":identity"), s.hmacSecret)
}

func (s *ErasureService) blobPseudonym(userID string) string {
	return vaultcrypto.HMACSign([]byte(userID+":objects"), s.hmacSecret)
}

func (s *ErasureService) recoveryPseudonym(userID string) string {
	return vaultcrypto.HMACSign([]byte(userID+":recovery"), s.hmacSecret)
}
