package config

import "time"

// DefaultKeyRotationInterval is how old the active JWT signing key may get before
// the scheduler rotates it: 30 days, which is what docs/spec-draft.md specified
// and what the shipped code never implemented.
const DefaultKeyRotationInterval = 720 * time.Hour

// KeyRotationInterval reports the horizon the DB-backed keystore rotates the
// signing key against (VAULT_KEY_ROTATION_INTERVAL). Zero or less disables the
// scheduler, which is how an operator who rotates on their own schedule — through
// POST /admin/keys/rotate or the rotate-jwks CLI — turns it off.
//
// It is read here rather than carried on Config because it is consumed once, at
// keystore wiring time, and only in the DB-backed mode. The value is still
// validated with every other duration: envcheck's durationEnvVars registry names
// it, so an unparseable or negative setting refuses to start rather than silently
// meaning "never rotate".
//
// This is distinct from the two intervals that already existed and rotate
// nothing: VAULT_KEY_REFRESH_INTERVAL is how often a pod re-reads the store, and
// VAULT_KEY_RETENTION_PERIOD is how long a retired key lingers afterwards.
func KeyRotationInterval() time.Duration {
	return envDuration("VAULT_KEY_ROTATION_INTERVAL", DefaultKeyRotationInterval)
}
