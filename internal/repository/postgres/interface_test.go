package postgres

import (
	"testing"

	"github.com/42-v/vault42/internal/repository"
)

// Compile-time interface satisfaction checks.
// These verify that every postgres repo type implements its corresponding
// repository interface. A build failure here means a method signature drifted.
var (
	_ repository.UserRepository            = (*UserRepo)(nil)
	_ repository.RefreshTokenRepository    = (*RefreshTokenRepo)(nil)
	_ repository.DeviceRepository          = (*DeviceRepo)(nil)
	_ repository.ClientRepository          = (*ClientRepo)(nil)
	_ repository.TOTPRepository            = (*TOTPRepo)(nil)
	_ repository.WebAuthnRepository        = (*WebAuthnRepo)(nil)
	_ repository.BackupCodeRepository      = (*BackupCodeRepo)(nil)
	_ repository.AuditRepository           = (*AuditRepo)(nil)
	_ repository.SocialAccountRepository   = (*SocialAccountRepo)(nil)
	_ repository.PasswordHistoryRepository = (*PasswordHistoryRepo)(nil)
	_ repository.RateLimitRepository       = (*RateLimitRepo)(nil)
	_ repository.AdminConfigRepository     = (*AdminConfigRepo)(nil)
	_ repository.IdentityRepository        = (*IdentityRepo)(nil)
	_ repository.BlobRepository            = (*BlobRepo)(nil)
	_ repository.AccountRecoveryRepository = (*AccountRecoveryRepo)(nil)
)

func TestInterfaceSatisfaction(t *testing.T) {
	// This test exists so `go test` reports this package instead of [no tests to run].
	// The real verification is the compile-time var block above — if any repo type
	// drifts from its interface, this file won't compile.
	t.Log("all 14 postgres repo types satisfy their repository interfaces")
}
