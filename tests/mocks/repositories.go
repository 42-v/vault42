// Package mocks supplies in-memory mock implementations of every
// repository.* and service.* interface used in unit tests.
package mocks

import (
	"context"
	"sync"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// Compile-time interface satisfaction checks.
var (
	_ repository.UserRepository            = (*MockUserRepo)(nil)
	_ repository.RefreshTokenRepository    = (*MockRefreshTokenRepo)(nil)
	_ repository.DeviceRepository          = (*MockDeviceRepo)(nil)
	_ repository.LoginCountryRepository    = (*MockLoginCountryRepo)(nil)
	_ repository.ClientRepository          = (*MockClientRepo)(nil)
	_ repository.TOTPRepository            = (*MockTOTPRepo)(nil)
	_ repository.WebAuthnRepository        = (*MockWebAuthnRepo)(nil)
	_ repository.BackupCodeRepository      = (*MockBackupCodeRepo)(nil)
	_ repository.AuditRepository           = (*MockAuditRepo)(nil)
	_ repository.SocialAccountRepository   = (*MockSocialAccountRepo)(nil)
	_ repository.PasswordHistoryRepository = (*MockPasswordHistoryRepo)(nil)
	_ repository.RateLimitRepository       = (*MockRateLimitRepo)(nil)
	_ repository.AdminConfigRepository     = (*MockAdminConfigRepo)(nil)
	_ repository.IdentityRepository        = (*MockIdentityRepo)(nil)
	_ repository.BlobRepository            = (*MockBlobRepo)(nil)
	_ repository.AccountRecoveryRepository = (*MockAccountRecoveryRepo)(nil)
)

// ---------------------------------------------------------------------------
// MockUserRepo
// ---------------------------------------------------------------------------

type MockUserRepo struct {
	CreateFn               func(ctx context.Context, user *model.User) error
	GetByIDFn              func(ctx context.Context, id string) (*model.User, error)
	GetByEmailFn           func(ctx context.Context, email string) (*model.User, error)
	UpdateFn               func(ctx context.Context, user *model.User) error
	UpdatePasswordFn       func(ctx context.Context, id, passwordHash string) error
	IncrementFailedLoginFn func(ctx context.Context, id string) error
	ResetFailedLoginFn     func(ctx context.Context, id string) error
	LockUntilFn            func(ctx context.Context, id string, until time.Time) error
	UnlockFn               func(ctx context.Context, id string) error
	VerifyEmailFn          func(ctx context.Context, id string) error
	SetLastLoginFn         func(ctx context.Context, id string) error
	CreateImportedFn       func(ctx context.Context, user *model.User) error
	ClearImportPendingFn   func(ctx context.Context, id string) error
	SoftDeleteScrubFn      func(ctx context.Context, id, tombstoneEmail string) error
}

func (m *MockUserRepo) SoftDeleteScrub(ctx context.Context, id, tombstoneEmail string) error {
	if m.SoftDeleteScrubFn != nil {
		return m.SoftDeleteScrubFn(ctx, id, tombstoneEmail)
	}
	return nil
}

func (m *MockUserRepo) SetLastLogin(ctx context.Context, id string) error {
	if m.SetLastLoginFn != nil {
		return m.SetLastLoginFn(ctx, id)
	}
	return nil
}

func (m *MockUserRepo) CreateImported(ctx context.Context, user *model.User) error {
	if m.CreateImportedFn != nil {
		return m.CreateImportedFn(ctx, user)
	}
	return nil
}

func (m *MockUserRepo) ClearImportPending(ctx context.Context, id string) error {
	if m.ClearImportPendingFn != nil {
		return m.ClearImportPendingFn(ctx, id)
	}
	return nil
}

func (m *MockUserRepo) Create(ctx context.Context, user *model.User) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, user)
	}
	return nil
}

func (m *MockUserRepo) GetByID(ctx context.Context, id string) (*model.User, error) {
	if m.GetByIDFn != nil {
		return m.GetByIDFn(ctx, id)
	}
	return nil, nil
}

func (m *MockUserRepo) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	if m.GetByEmailFn != nil {
		return m.GetByEmailFn(ctx, email)
	}
	return nil, nil
}

func (m *MockUserRepo) Update(ctx context.Context, user *model.User) error {
	if m.UpdateFn != nil {
		return m.UpdateFn(ctx, user)
	}
	return nil
}

func (m *MockUserRepo) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	if m.UpdatePasswordFn != nil {
		return m.UpdatePasswordFn(ctx, id, passwordHash)
	}
	return nil
}

func (m *MockUserRepo) IncrementFailedLogin(ctx context.Context, id string) error {
	if m.IncrementFailedLoginFn != nil {
		return m.IncrementFailedLoginFn(ctx, id)
	}
	return nil
}

func (m *MockUserRepo) ResetFailedLogin(ctx context.Context, id string) error {
	if m.ResetFailedLoginFn != nil {
		return m.ResetFailedLoginFn(ctx, id)
	}
	return nil
}

func (m *MockUserRepo) LockUntil(ctx context.Context, id string, until time.Time) error {
	if m.LockUntilFn != nil {
		return m.LockUntilFn(ctx, id, until)
	}
	return nil
}

func (m *MockUserRepo) Unlock(ctx context.Context, id string) error {
	if m.UnlockFn != nil {
		return m.UnlockFn(ctx, id)
	}
	return nil
}

func (m *MockUserRepo) VerifyEmail(ctx context.Context, id string) error {
	if m.VerifyEmailFn != nil {
		return m.VerifyEmailFn(ctx, id)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockRefreshTokenRepo
// ---------------------------------------------------------------------------

type MockRefreshTokenRepo struct {
	CreateFn              func(ctx context.Context, token *model.RefreshToken) error
	GetByTokenHashFn      func(ctx context.Context, hash string) (*model.RefreshToken, error)
	MarkUsedFn            func(ctx context.Context, id string) (bool, error)
	RevokeByIDFn          func(ctx context.Context, id string) error
	RevokeByDeviceIDFn    func(ctx context.Context, deviceID string) error
	RevokeFamilyFn        func(ctx context.Context, familyID string) error
	RevokeAllForUserFn    func(ctx context.Context, userID string) error
	DeleteAllForUserFn    func(ctx context.Context, userID string) error
	RevokeAllFn           func(ctx context.Context) error
	CountActiveFamiliesFn func(ctx context.Context, userID string) (int, error)
	DeleteExpiredFn       func(ctx context.Context) (int64, error)
}

func (m *MockRefreshTokenRepo) Create(ctx context.Context, token *model.RefreshToken) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, token)
	}
	return nil
}

func (m *MockRefreshTokenRepo) GetByTokenHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	if m.GetByTokenHashFn != nil {
		return m.GetByTokenHashFn(ctx, hash)
	}
	return nil, nil
}

func (m *MockRefreshTokenRepo) MarkUsed(ctx context.Context, id string) (bool, error) {
	if m.MarkUsedFn != nil {
		return m.MarkUsedFn(ctx, id)
	}
	return true, nil
}

func (m *MockRefreshTokenRepo) RevokeByID(ctx context.Context, id string) error {
	if m.RevokeByIDFn != nil {
		return m.RevokeByIDFn(ctx, id)
	}
	return nil
}

func (m *MockRefreshTokenRepo) RevokeByDeviceID(ctx context.Context, deviceID string) error {
	if m.RevokeByDeviceIDFn != nil {
		return m.RevokeByDeviceIDFn(ctx, deviceID)
	}
	return nil
}

func (m *MockRefreshTokenRepo) RevokeFamily(ctx context.Context, familyID string) error {
	if m.RevokeFamilyFn != nil {
		return m.RevokeFamilyFn(ctx, familyID)
	}
	return nil
}

func (m *MockRefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	if m.RevokeAllForUserFn != nil {
		return m.RevokeAllForUserFn(ctx, userID)
	}
	return nil
}

func (m *MockRefreshTokenRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	if m.DeleteAllForUserFn != nil {
		return m.DeleteAllForUserFn(ctx, userID)
	}
	return nil
}

func (m *MockRefreshTokenRepo) RevokeAll(ctx context.Context) error {
	if m.RevokeAllFn != nil {
		return m.RevokeAllFn(ctx)
	}
	return nil
}

func (m *MockRefreshTokenRepo) CountActiveFamilies(ctx context.Context, userID string) (int, error) {
	if m.CountActiveFamiliesFn != nil {
		return m.CountActiveFamiliesFn(ctx, userID)
	}
	return 0, nil
}

func (m *MockRefreshTokenRepo) DeleteExpired(ctx context.Context) (int64, error) {
	if m.DeleteExpiredFn != nil {
		return m.DeleteExpiredFn(ctx)
	}
	return 0, nil
}

// ---------------------------------------------------------------------------
// MockDeviceRepo
// ---------------------------------------------------------------------------

type MockDeviceRepo struct {
	CreateFn             func(ctx context.Context, device *model.Device) error
	GetByIDFn            func(ctx context.Context, id string) (*model.Device, error)
	GetByFingerprintFn   func(ctx context.Context, userID, fingerprintHash string) (*model.Device, error)
	ListByUserFn         func(ctx context.Context, userID string) ([]*model.Device, error)
	UpdateLastSeenFn     func(ctx context.Context, id string, ip string) error
	UpdateFriendlyNameFn func(ctx context.Context, id string, name string) error
	TrustFn              func(ctx context.Context, id string, until time.Time) error
	DeleteFn             func(ctx context.Context, id, userID string) error
	DeleteAllForUserFn   func(ctx context.Context, userID string) error
}

func (m *MockDeviceRepo) Create(ctx context.Context, device *model.Device) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, device)
	}
	return nil
}

func (m *MockDeviceRepo) GetByID(ctx context.Context, id string) (*model.Device, error) {
	if m.GetByIDFn != nil {
		return m.GetByIDFn(ctx, id)
	}
	return nil, nil
}

func (m *MockDeviceRepo) GetByFingerprint(ctx context.Context, userID, fingerprintHash string) (*model.Device, error) {
	if m.GetByFingerprintFn != nil {
		return m.GetByFingerprintFn(ctx, userID, fingerprintHash)
	}
	return nil, nil
}

func (m *MockDeviceRepo) ListByUser(ctx context.Context, userID string) ([]*model.Device, error) {
	if m.ListByUserFn != nil {
		return m.ListByUserFn(ctx, userID)
	}
	return nil, nil
}

func (m *MockDeviceRepo) UpdateLastSeen(ctx context.Context, id string, ip string) error {
	if m.UpdateLastSeenFn != nil {
		return m.UpdateLastSeenFn(ctx, id, ip)
	}
	return nil
}

func (m *MockDeviceRepo) UpdateFriendlyName(ctx context.Context, id string, name string) error {
	if m.UpdateFriendlyNameFn != nil {
		return m.UpdateFriendlyNameFn(ctx, id, name)
	}
	return nil
}

func (m *MockDeviceRepo) Trust(ctx context.Context, id string, until time.Time) error {
	if m.TrustFn != nil {
		return m.TrustFn(ctx, id, until)
	}
	return nil
}

func (m *MockDeviceRepo) Delete(ctx context.Context, id, userID string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, id, userID)
	}
	return nil
}

func (m *MockDeviceRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	if m.DeleteAllForUserFn != nil {
		return m.DeleteAllForUserFn(ctx, userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockLoginCountryRepo
// ---------------------------------------------------------------------------

// MockLoginCountryRepo is an in-memory stub of
// repository.LoginCountryRepository. When UpsertAndWasNewFn is nil it behaves
// like a real store: it remembers the countries seen per user, so wasNew and
// hadAny follow the first-seen semantics without a database.
type MockLoginCountryRepo struct {
	UpsertAndWasNewFn func(ctx context.Context, userID, cc string) (bool, bool, error)

	mu   sync.Mutex
	seen map[string]map[string]bool
}

func (m *MockLoginCountryRepo) UpsertAndWasNew(ctx context.Context, userID, cc string) (bool, bool, error) {
	if m.UpsertAndWasNewFn != nil {
		return m.UpsertAndWasNewFn(ctx, userID, cc)
	}
	// The login success path calls this from a goroutine, so the default store
	// is mutex-guarded to stay race-free under -race.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = make(map[string]map[string]bool)
	}
	countries := m.seen[userID]
	hadAny := len(countries) > 0
	if countries == nil {
		countries = make(map[string]bool)
		m.seen[userID] = countries
	}
	wasNew := !countries[cc]
	countries[cc] = true
	return wasNew, hadAny, nil
}

// ---------------------------------------------------------------------------
// MockClientRepo
// ---------------------------------------------------------------------------

type MockClientRepo struct {
	CreateFn     func(ctx context.Context, client *model.Client) error
	GetByIDFn    func(ctx context.Context, id string) (*model.Client, error)
	GetByNameFn  func(ctx context.Context, name string) (*model.Client, error)
	ListFn       func(ctx context.Context) ([]*model.Client, error)
	UpdateFn     func(ctx context.Context, client *model.Client) error
	DeactivateFn func(ctx context.Context, id string) error
}

func (m *MockClientRepo) Create(ctx context.Context, client *model.Client) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, client)
	}
	return nil
}

func (m *MockClientRepo) GetByID(ctx context.Context, id string) (*model.Client, error) {
	if m.GetByIDFn != nil {
		return m.GetByIDFn(ctx, id)
	}
	return nil, nil
}

func (m *MockClientRepo) GetByName(ctx context.Context, name string) (*model.Client, error) {
	if m.GetByNameFn != nil {
		return m.GetByNameFn(ctx, name)
	}
	return nil, nil
}

func (m *MockClientRepo) List(ctx context.Context) ([]*model.Client, error) {
	if m.ListFn != nil {
		return m.ListFn(ctx)
	}
	return nil, nil
}

func (m *MockClientRepo) Update(ctx context.Context, client *model.Client) error {
	if m.UpdateFn != nil {
		return m.UpdateFn(ctx, client)
	}
	return nil
}

func (m *MockClientRepo) Deactivate(ctx context.Context, id string) error {
	if m.DeactivateFn != nil {
		return m.DeactivateFn(ctx, id)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockTOTPRepo
// ---------------------------------------------------------------------------

type MockTOTPRepo struct {
	CreateFn         func(ctx context.Context, secret *model.TOTPSecret) error
	GetByUserIDFn    func(ctx context.Context, userID string) (*model.TOTPSecret, error)
	MarkVerifiedFn   func(ctx context.Context, id string) error
	DeleteByUserIDFn func(ctx context.Context, userID string) error
}

func (m *MockTOTPRepo) Create(ctx context.Context, secret *model.TOTPSecret) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, secret)
	}
	return nil
}

func (m *MockTOTPRepo) GetByUserID(ctx context.Context, userID string) (*model.TOTPSecret, error) {
	if m.GetByUserIDFn != nil {
		return m.GetByUserIDFn(ctx, userID)
	}
	return nil, nil
}

func (m *MockTOTPRepo) MarkVerified(ctx context.Context, id string) error {
	if m.MarkVerifiedFn != nil {
		return m.MarkVerifiedFn(ctx, id)
	}
	return nil
}

func (m *MockTOTPRepo) DeleteByUserID(ctx context.Context, userID string) error {
	if m.DeleteByUserIDFn != nil {
		return m.DeleteByUserIDFn(ctx, userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockWebAuthnRepo
// ---------------------------------------------------------------------------

type MockWebAuthnRepo struct {
	CreateFn            func(ctx context.Context, cred *model.WebAuthnCredential) error
	GetByCredentialIDFn func(ctx context.Context, credID []byte) (*model.WebAuthnCredential, error)
	ListByUserFn        func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error)
	UpdateSignCountFn   func(ctx context.Context, id string, count int) error
	UpdateFlagsFn       func(ctx context.Context, id string, flags int) error
	DeleteFn            func(ctx context.Context, id, userID string) error
	DeleteAllForUserFn  func(ctx context.Context, userID string) error
}

func (m *MockWebAuthnRepo) Create(ctx context.Context, cred *model.WebAuthnCredential) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, cred)
	}
	return nil
}

func (m *MockWebAuthnRepo) GetByCredentialID(ctx context.Context, credID []byte) (*model.WebAuthnCredential, error) {
	if m.GetByCredentialIDFn != nil {
		return m.GetByCredentialIDFn(ctx, credID)
	}
	return nil, nil
}

func (m *MockWebAuthnRepo) ListByUser(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
	if m.ListByUserFn != nil {
		return m.ListByUserFn(ctx, userID)
	}
	return nil, nil
}

func (m *MockWebAuthnRepo) UpdateSignCount(ctx context.Context, id string, count int) error {
	if m.UpdateSignCountFn != nil {
		return m.UpdateSignCountFn(ctx, id, count)
	}
	return nil
}

func (m *MockWebAuthnRepo) UpdateFlags(ctx context.Context, id string, flags int) error {
	if m.UpdateFlagsFn != nil {
		return m.UpdateFlagsFn(ctx, id, flags)
	}
	return nil
}

func (m *MockWebAuthnRepo) Delete(ctx context.Context, id, userID string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, id, userID)
	}
	return nil
}

func (m *MockWebAuthnRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	if m.DeleteAllForUserFn != nil {
		return m.DeleteAllForUserFn(ctx, userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockBackupCodeRepo
// ---------------------------------------------------------------------------

type MockBackupCodeRepo struct {
	CreateBatchFn      func(ctx context.Context, codes []*model.BackupCode) error
	ListUnusedByUserFn func(ctx context.Context, userID string) ([]*model.BackupCode, error)
	MarkUsedFn         func(ctx context.Context, id string) (bool, error)
	DeleteAllForUserFn func(ctx context.Context, userID string) error
	PurgeAllForUserFn  func(ctx context.Context, userID string) error
}

func (m *MockBackupCodeRepo) CreateBatch(ctx context.Context, codes []*model.BackupCode) error {
	if m.CreateBatchFn != nil {
		return m.CreateBatchFn(ctx, codes)
	}
	return nil
}

func (m *MockBackupCodeRepo) ListUnusedByUser(ctx context.Context, userID string) ([]*model.BackupCode, error) {
	if m.ListUnusedByUserFn != nil {
		return m.ListUnusedByUserFn(ctx, userID)
	}
	return nil, nil
}

func (m *MockBackupCodeRepo) MarkUsed(ctx context.Context, id string) (bool, error) {
	if m.MarkUsedFn != nil {
		return m.MarkUsedFn(ctx, id)
	}
	return true, nil
}

func (m *MockBackupCodeRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	if m.DeleteAllForUserFn != nil {
		return m.DeleteAllForUserFn(ctx, userID)
	}
	return nil
}

func (m *MockBackupCodeRepo) PurgeAllForUser(ctx context.Context, userID string) error {
	if m.PurgeAllForUserFn != nil {
		return m.PurgeAllForUserFn(ctx, userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockAuditRepo
// ---------------------------------------------------------------------------

type MockAuditRepo struct {
	InsertFn        func(ctx context.Context, entry *model.AuditEntry) error
	InsertBatchFn   func(ctx context.Context, entries []*model.AuditEntry) error
	QueryFn         func(ctx context.Context, filter repository.AuditFilter) ([]*model.AuditEntry, error)
	CountByUserFn   func(ctx context.Context, userID string) (int, error)
	CleanupFn       func(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupLockedFn func(ctx context.Context, olderThan time.Time) (int64, bool, error)
}

func (m *MockAuditRepo) CleanupLocked(ctx context.Context, olderThan time.Time) (int64, bool, error) {
	if m.CleanupLockedFn != nil {
		return m.CleanupLockedFn(ctx, olderThan)
	}
	// Default: behave like a sweeper that won the lock and delegates to Cleanup,
	// so existing tests that only stub CleanupFn keep working.
	if m.CleanupFn != nil {
		n, err := m.CleanupFn(ctx, olderThan)
		return n, true, err
	}
	return 0, true, nil
}

func (m *MockAuditRepo) Insert(ctx context.Context, entry *model.AuditEntry) error {
	if m.InsertFn != nil {
		return m.InsertFn(ctx, entry)
	}
	return nil
}

func (m *MockAuditRepo) InsertBatch(ctx context.Context, entries []*model.AuditEntry) error {
	if m.InsertBatchFn != nil {
		return m.InsertBatchFn(ctx, entries)
	}
	return nil
}

func (m *MockAuditRepo) Query(ctx context.Context, filter repository.AuditFilter) ([]*model.AuditEntry, error) {
	if m.QueryFn != nil {
		return m.QueryFn(ctx, filter)
	}
	return nil, nil
}

func (m *MockAuditRepo) CountByUser(ctx context.Context, userID string) (int, error) {
	if m.CountByUserFn != nil {
		return m.CountByUserFn(ctx, userID)
	}
	return 0, nil
}

func (m *MockAuditRepo) Cleanup(ctx context.Context, olderThan time.Time) (int64, error) {
	if m.CleanupFn != nil {
		return m.CleanupFn(ctx, olderThan)
	}
	return 0, nil
}

// ---------------------------------------------------------------------------
// MockSocialAccountRepo
// ---------------------------------------------------------------------------

type MockSocialAccountRepo struct {
	CreateFn             func(ctx context.Context, account *model.SocialAccount) error
	GetByProviderAndIDFn func(ctx context.Context, provider, providerUserID string) (*model.SocialAccount, error)
	ListByUserFn         func(ctx context.Context, userID string) ([]*model.SocialAccount, error)
	DeleteFn             func(ctx context.Context, id, userID string) error
	DeleteAllForUserFn   func(ctx context.Context, userID string) error
}

func (m *MockSocialAccountRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	if m.DeleteAllForUserFn != nil {
		return m.DeleteAllForUserFn(ctx, userID)
	}
	return nil
}

func (m *MockSocialAccountRepo) Create(ctx context.Context, account *model.SocialAccount) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, account)
	}
	return nil
}

func (m *MockSocialAccountRepo) GetByProviderAndID(ctx context.Context, provider, providerUserID string) (*model.SocialAccount, error) {
	if m.GetByProviderAndIDFn != nil {
		return m.GetByProviderAndIDFn(ctx, provider, providerUserID)
	}
	return nil, nil
}

func (m *MockSocialAccountRepo) ListByUser(ctx context.Context, userID string) ([]*model.SocialAccount, error) {
	if m.ListByUserFn != nil {
		return m.ListByUserFn(ctx, userID)
	}
	return nil, nil
}

func (m *MockSocialAccountRepo) Delete(ctx context.Context, id, userID string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, id, userID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockPasswordHistoryRepo
// ---------------------------------------------------------------------------

type MockPasswordHistoryRepo struct {
	CreateFn           func(ctx context.Context, entry *model.PasswordHistory) error
	GetRecentByUserFn  func(ctx context.Context, userID string, limit int) ([]*model.PasswordHistory, error)
	DeleteAllForUserFn func(ctx context.Context, userID string) error
}

func (m *MockPasswordHistoryRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	if m.DeleteAllForUserFn != nil {
		return m.DeleteAllForUserFn(ctx, userID)
	}
	return nil
}

func (m *MockPasswordHistoryRepo) Create(ctx context.Context, entry *model.PasswordHistory) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, entry)
	}
	return nil
}

func (m *MockPasswordHistoryRepo) GetRecentByUser(ctx context.Context, userID string, limit int) ([]*model.PasswordHistory, error) {
	if m.GetRecentByUserFn != nil {
		return m.GetRecentByUserFn(ctx, userID, limit)
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// MockRateLimitRepo
// ---------------------------------------------------------------------------

type MockRateLimitRepo struct {
	IncrementFn     func(ctx context.Context, key string, window time.Time) (int, error)
	GetFn           func(ctx context.Context, key string, window time.Time) (int, error)
	DeleteExpiredFn func(ctx context.Context, before time.Time) error
}

func (m *MockRateLimitRepo) Increment(ctx context.Context, key string, window time.Time) (int, error) {
	if m.IncrementFn != nil {
		return m.IncrementFn(ctx, key, window)
	}
	return 0, nil
}

func (m *MockRateLimitRepo) Get(ctx context.Context, key string, window time.Time) (int, error) {
	if m.GetFn != nil {
		return m.GetFn(ctx, key, window)
	}
	return 0, nil
}

func (m *MockRateLimitRepo) DeleteExpired(ctx context.Context, before time.Time) error {
	if m.DeleteExpiredFn != nil {
		return m.DeleteExpiredFn(ctx, before)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockAdminConfigRepo
// ---------------------------------------------------------------------------

type MockAdminConfigRepo struct {
	ListFn   func(ctx context.Context) (map[string]string, error)
	GetFn    func(ctx context.Context, key string) (string, error)
	SetFn    func(ctx context.Context, key, value string) error
	DeleteFn func(ctx context.Context, key string) error
}

func (m *MockAdminConfigRepo) List(ctx context.Context) (map[string]string, error) {
	if m.ListFn != nil {
		return m.ListFn(ctx)
	}
	return map[string]string{}, nil
}

func (m *MockAdminConfigRepo) Get(ctx context.Context, key string) (string, error) {
	if m.GetFn != nil {
		return m.GetFn(ctx, key)
	}
	return "", nil
}

func (m *MockAdminConfigRepo) Set(ctx context.Context, key, value string) error {
	if m.SetFn != nil {
		return m.SetFn(ctx, key, value)
	}
	return nil
}

func (m *MockAdminConfigRepo) Delete(ctx context.Context, key string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, key)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockIdentityRepo
// ---------------------------------------------------------------------------

type MockIdentityRepo struct {
	UpsertFn         func(ctx context.Context, profile *model.IdentityProfile) error
	UpsertCASFn      func(ctx context.Context, profile *model.IdentityProfile, expectedUpdatedAt time.Time) (bool, error)
	GetByPseudonymFn func(ctx context.Context, pseudonymID string) (*model.IdentityProfile, error)
	DeleteFn         func(ctx context.Context, pseudonymID string) error
}

func (m *MockIdentityRepo) UpsertCAS(ctx context.Context, profile *model.IdentityProfile, expectedUpdatedAt time.Time) (bool, error) {
	if m.UpsertCASFn != nil {
		return m.UpsertCASFn(ctx, profile, expectedUpdatedAt)
	}
	// Default: the CAS always wins, delegating to UpsertFn so tests that only stub
	// the plain Upsert still observe the write.
	if m.UpsertFn != nil {
		return true, m.UpsertFn(ctx, profile)
	}
	return true, nil
}

func (m *MockIdentityRepo) Upsert(ctx context.Context, profile *model.IdentityProfile) error {
	if m.UpsertFn != nil {
		return m.UpsertFn(ctx, profile)
	}
	return nil
}

func (m *MockIdentityRepo) GetByPseudonym(ctx context.Context, pseudonymID string) (*model.IdentityProfile, error) {
	if m.GetByPseudonymFn != nil {
		return m.GetByPseudonymFn(ctx, pseudonymID)
	}
	return nil, nil
}

func (m *MockIdentityRepo) Delete(ctx context.Context, pseudonymID string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, pseudonymID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockBlobRepo
// ---------------------------------------------------------------------------

type MockBlobRepo struct {
	CreateFn                  func(ctx context.Context, blob *model.Blob) error
	GetByIDAndPseudonymFn     func(ctx context.Context, id, pseudonymID string) (*model.Blob, error)
	GetByRefAndPseudonymFn    func(ctx context.Context, refHash, pseudonymID string) (*model.Blob, error)
	DeleteByRefAndPseudonymFn func(ctx context.Context, refHash, pseudonymID string) error
	ListByPseudonymFn         func(ctx context.Context, pseudonymID string) ([]*model.Blob, error)
	GetQuotaFn                func(ctx context.Context, pseudonymID string) (*model.BlobQuota, error)
	DeleteFn                  func(ctx context.Context, id, pseudonymID string) error
	DeleteAllForPseudonymFn   func(ctx context.Context, pseudonymID string) error
}

func (m *MockBlobRepo) DeleteAllForPseudonym(ctx context.Context, pseudonymID string) error {
	if m.DeleteAllForPseudonymFn != nil {
		return m.DeleteAllForPseudonymFn(ctx, pseudonymID)
	}
	return nil
}

func (m *MockBlobRepo) Create(ctx context.Context, blob *model.Blob) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, blob)
	}
	return nil
}

func (m *MockBlobRepo) GetByIDAndPseudonym(ctx context.Context, id, pseudonymID string) (*model.Blob, error) {
	if m.GetByIDAndPseudonymFn != nil {
		return m.GetByIDAndPseudonymFn(ctx, id, pseudonymID)
	}
	return nil, nil
}

func (m *MockBlobRepo) GetByRefAndPseudonym(ctx context.Context, refHash, pseudonymID string) (*model.Blob, error) {
	if m.GetByRefAndPseudonymFn != nil {
		return m.GetByRefAndPseudonymFn(ctx, refHash, pseudonymID)
	}
	return nil, nil
}

func (m *MockBlobRepo) DeleteByRefAndPseudonym(ctx context.Context, refHash, pseudonymID string) error {
	if m.DeleteByRefAndPseudonymFn != nil {
		return m.DeleteByRefAndPseudonymFn(ctx, refHash, pseudonymID)
	}
	return nil
}

func (m *MockBlobRepo) ListByPseudonym(ctx context.Context, pseudonymID string) ([]*model.Blob, error) {
	if m.ListByPseudonymFn != nil {
		return m.ListByPseudonymFn(ctx, pseudonymID)
	}
	return nil, nil
}

func (m *MockBlobRepo) GetQuota(ctx context.Context, pseudonymID string) (*model.BlobQuota, error) {
	if m.GetQuotaFn != nil {
		return m.GetQuotaFn(ctx, pseudonymID)
	}
	return &model.BlobQuota{}, nil
}

func (m *MockBlobRepo) Delete(ctx context.Context, id, pseudonymID string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, id, pseudonymID)
	}
	return nil
}

// MockAppRoleRepo is a mock repository.AppRoleRepository.
type MockAppRoleRepo struct {
	ListFn      func(ctx context.Context) ([]*model.AppRole, error)
	ListNamesFn func(ctx context.Context) ([]string, error)
	GetFn       func(ctx context.Context, name string) (*model.AppRole, error)
	CreateFn    func(ctx context.Context, role *model.AppRole) error
	DeleteFn    func(ctx context.Context, name string) error
}

func (m *MockAppRoleRepo) List(ctx context.Context) ([]*model.AppRole, error) {
	if m.ListFn != nil {
		return m.ListFn(ctx)
	}
	return nil, nil
}

func (m *MockAppRoleRepo) ListNames(ctx context.Context) ([]string, error) {
	if m.ListNamesFn != nil {
		return m.ListNamesFn(ctx)
	}
	return nil, nil
}

func (m *MockAppRoleRepo) Get(ctx context.Context, name string) (*model.AppRole, error) {
	if m.GetFn != nil {
		return m.GetFn(ctx, name)
	}
	return nil, nil
}

func (m *MockAppRoleRepo) Create(ctx context.Context, role *model.AppRole) error {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, role)
	}
	return nil
}

func (m *MockAppRoleRepo) Delete(ctx context.Context, name string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, name)
	}
	return nil
}

var _ repository.AppRoleRepository = (*MockAppRoleRepo)(nil)

// ---------------------------------------------------------------------------
// MockAccountRecoveryRepo
// ---------------------------------------------------------------------------

// MockAccountRecoveryRepo is a mock repository.AccountRecoveryRepository.
type MockAccountRecoveryRepo struct {
	AppendFn func(ctx context.Context, rec *model.AccountRecovery) error
	ListFn   func(ctx context.Context, limit, offset int) ([]model.AccountRecovery, error)
}

func (m *MockAccountRecoveryRepo) Append(ctx context.Context, rec *model.AccountRecovery) error {
	if m.AppendFn != nil {
		return m.AppendFn(ctx, rec)
	}
	return nil
}

func (m *MockAccountRecoveryRepo) List(ctx context.Context, limit, offset int) ([]model.AccountRecovery, error) {
	if m.ListFn != nil {
		return m.ListFn(ctx, limit, offset)
	}
	return nil, nil
}

var _ repository.AccountRecoveryRepository = (*MockAccountRecoveryRepo)(nil)
