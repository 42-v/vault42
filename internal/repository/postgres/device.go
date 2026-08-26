package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/42-v/vault42/internal/model"
)

// DeviceRepo implements repository.DeviceRepository using PostgreSQL.
type DeviceRepo struct {
	db *DB
}

// NewDeviceRepo creates a new PostgreSQL-backed device repository.
func NewDeviceRepo(db *DB) *DeviceRepo {
	return &DeviceRepo{db: db}
}

// Create inserts a new device record into the auth.devices table.
func (r *DeviceRepo) Create(ctx context.Context, device *model.Device) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO auth.devices (id, user_id, fingerprint_hash, friendly_name, trusted, ip, user_agent, first_seen_at, last_seen_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		device.ID, device.UserID, device.FingerprintHash, nullStr(device.FriendlyName),
		device.Trusted, nullStr(device.IP), nullStr(clampUserAgent(device.UserAgent)),
		device.FirstSeenAt, device.LastSeenAt, device.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create device: %w", err)
	}
	return nil
}

// GetByID retrieves a device by primary key. Returns nil, nil if not found.
func (r *DeviceRepo) GetByID(ctx context.Context, id string) (*model.Device, error) {
	s := newDeviceScan()
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, fingerprint_hash, friendly_name, trusted, trusted_until, ip, user_agent, last_seen_at, first_seen_at, created_at
		FROM auth.devices WHERE id = $1`, id).Scan(s.ptrs()...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}
	return s.device(), nil
}

// GetByFingerprint retrieves a device by user ID and fingerprint hash. Returns nil, nil if not found.
func (r *DeviceRepo) GetByFingerprint(ctx context.Context, userID, fingerprintHash string) (*model.Device, error) {
	s := newDeviceScan()
	err := r.db.Pool.QueryRow(ctx, `
		SELECT id, user_id, fingerprint_hash, friendly_name, trusted, trusted_until, ip, user_agent, last_seen_at, first_seen_at, created_at
		FROM auth.devices WHERE user_id = $1 AND fingerprint_hash = $2`, userID, fingerprintHash).Scan(s.ptrs()...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get device by fp: %w", err)
	}
	return s.device(), nil
}

// ListByUser returns all devices for a user, ordered by most recently seen.
func (r *DeviceRepo) ListByUser(ctx context.Context, userID string) ([]*model.Device, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, user_id, fingerprint_hash, friendly_name, trusted, trusted_until, ip, user_agent, last_seen_at, first_seen_at, created_at
		FROM auth.devices WHERE user_id = $1 ORDER BY last_seen_at DESC NULLS LAST`, userID)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var devices []*model.Device
	for rows.Next() {
		s := newDeviceScan()
		if err := rows.Scan(s.ptrs()...); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		devices = append(devices, s.device())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan devices: %w", err)
	}
	return devices, nil
}

// UpdateLastSeen updates the last-seen timestamp to now and records the current IP.
func (r *DeviceRepo) UpdateLastSeen(ctx context.Context, id string, ip string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.devices SET last_seen_at = $2, ip = $3 WHERE id = $1`, id, time.Now(), ip)
	if err != nil {
		return fmt.Errorf("update last seen: %w", err)
	}
	return nil
}

// UpdateFriendlyName sets a human-readable name for a device.
func (r *DeviceRepo) UpdateFriendlyName(ctx context.Context, id string, name string) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.devices SET friendly_name = $2 WHERE id = $1`, id, name)
	if err != nil {
		return fmt.Errorf("update friendly name: %w", err)
	}
	return nil
}

// Trust marks a device as trusted until the specified time.
func (r *DeviceRepo) Trust(ctx context.Context, id string, until time.Time) error {
	_, err := r.db.Pool.Exec(ctx, `UPDATE auth.devices SET trusted = TRUE, trusted_until = $2 WHERE id = $1`, id, until)
	if err != nil {
		return fmt.Errorf("trust device: %w", err)
	}
	return nil
}

// Delete removes a single device record with ownership verification.
func (r *DeviceRepo) Delete(ctx context.Context, id, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.devices WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("delete device: %w", err)
	}
	return nil
}

// DeleteAllForUser removes all device records for a user.
func (r *DeviceRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM auth.devices WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete all devices: %w", err)
	}
	return nil
}
