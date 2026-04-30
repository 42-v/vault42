package postgres

import "github.com/42-v/vault42/internal/model"

// deref returns the value pointed to by ptr, or the zero value if ptr is nil.
func deref[T any](ptr *T) T {
	if ptr != nil {
		return *ptr
	}
	var zero T
	return zero
}

// scanDevice maps nullable columns from a device row into a model.Device.
// The caller scans into the returned pointers, then calls apply().
type deviceScan struct {
	d            model.Device
	friendlyName *string
	ip           *string
	ua           *string
}

func newDeviceScan() *deviceScan { return &deviceScan{} }

func (s *deviceScan) ptrs() []any {
	return []any{
		&s.d.ID, &s.d.UserID, &s.d.FingerprintHash, &s.friendlyName, &s.d.Trusted, &s.d.TrustedUntil,
		&s.ip, &s.ua, &s.d.LastSeenAt, &s.d.FirstSeenAt, &s.d.CreatedAt,
	}
}

func (s *deviceScan) device() *model.Device {
	s.d.FriendlyName = deref(s.friendlyName)
	s.d.IP = deref(s.ip)
	s.d.UserAgent = deref(s.ua)
	return &s.d
}
