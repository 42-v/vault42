package mocks

import (
	"context"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/email"
)

// Compile-time interface satisfaction checks.
var (
	_ cache.Cache  = (*MockCache)(nil)
	_ email.Sender = (*MockEmailSender)(nil)
)

// ---------------------------------------------------------------------------
// MockCache
// ---------------------------------------------------------------------------

type MockCache struct {
	GetFn            func(ctx context.Context, key string) (string, error)
	SetFn            func(ctx context.Context, key string, value string, ttl time.Duration) error
	DeleteFn         func(ctx context.Context, key string) error
	GetAndDeleteFn   func(ctx context.Context, key string) (string, error)
	SetIfNotExistsFn func(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)
	IncrementFn      func(ctx context.Context, key string, ttl time.Duration) (int64, error)
	ExistsFn         func(ctx context.Context, key string) (bool, error)
	CloseFn          func() error
}

func (m *MockCache) Get(ctx context.Context, key string) (string, error) {
	if m.GetFn != nil {
		return m.GetFn(ctx, key)
	}
	return "", cache.ErrNotFound
}

func (m *MockCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	if m.SetFn != nil {
		return m.SetFn(ctx, key, value, ttl)
	}
	return nil
}

func (m *MockCache) Delete(ctx context.Context, key string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, key)
	}
	return nil
}

func (m *MockCache) GetAndDelete(ctx context.Context, key string) (string, error) {
	if m.GetAndDeleteFn != nil {
		return m.GetAndDeleteFn(ctx, key)
	}
	return "", cache.ErrNotFound
}

func (m *MockCache) SetIfNotExists(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	if m.SetIfNotExistsFn != nil {
		return m.SetIfNotExistsFn(ctx, key, value, ttl)
	}
	return true, nil // default: always succeed (key didn't exist)
}

func (m *MockCache) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if m.IncrementFn != nil {
		return m.IncrementFn(ctx, key, ttl)
	}
	return 0, nil
}

func (m *MockCache) Exists(ctx context.Context, key string) (bool, error) {
	if m.ExistsFn != nil {
		return m.ExistsFn(ctx, key)
	}
	return false, nil
}

func (m *MockCache) Close() error {
	if m.CloseFn != nil {
		return m.CloseFn()
	}
	return nil
}

// ---------------------------------------------------------------------------
// MockEmailSender
// ---------------------------------------------------------------------------

type MockEmailSender struct {
	SendFn func(ctx context.Context, to, subject, htmlBody, textBody string) error
}

func (m *MockEmailSender) Send(ctx context.Context, _ email.Address, to, subject, htmlBody, textBody string) error {
	if m.SendFn != nil {
		return m.SendFn(ctx, to, subject, htmlBody, textBody)
	}
	return nil
}
