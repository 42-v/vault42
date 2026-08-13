//go:build race

package attack

// atkRaceDetector reports whether this binary was built with -race.
//
// The timing measurements in this directory quote wall-clock medians. Under the
// race detector every memory access is instrumented, which roughly doubles the
// cost of an argon2id hash and adds noise that swamps the microsecond-scale
// gaps being measured. A number produced under -race would be a number about
// the detector, not about vault42, so those tests skip rather than report it.
const atkRaceDetector = true
