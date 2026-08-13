//go:build !race

package attack

// atkRaceDetector reports whether this binary was built with -race.
// See the //go:build race variant of this file for why the timing tests care.
const atkRaceDetector = false
