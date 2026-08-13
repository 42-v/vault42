// Frontend container hardening gate.
//
// The frontend was the one image in this chart that ran as root on a writable
// root filesystem with its tag defaulting to `latest`, while every other image
// is distroless and nonroot with a pinned tag. It was fixed, and then nothing
// held it: no test read the Dockerfile, no test read the securityContext, and a
// revert of either would have passed CI green.
//
// A hardening change with no gate is a comment. This reads the four properties
// off the two files that actually decide them.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestTheFrontendImageDoesNotRunAsRoot reads the Dockerfile, because the
// securityContext below can only refuse to start a container that was built to
// need root. Both halves have to hold.
func TestTheFrontendImageDoesNotRunAsRoot(t *testing.T) {
	src := readFileString(t, filepath.Join(repoRoot(t), "web", "Dockerfile"))

	if !strings.Contains(src, "nginx-unprivileged") {
		t.Error("web/Dockerfile no longer builds on an unprivileged nginx base. " +
			"Stock nginx binds port 80 and writes its pid and caches as root, so it cannot " +
			"run under the nonroot securityContext the chart applies: the pod CrashLoops, " +
			"and the tempting fix is to relax the securityContext.")
	}
	if !strings.Contains(src, "USER 101") {
		t.Error("web/Dockerfile no longer declares USER 101. Without it the image's default " +
			"user is root, and only the chart stands between that and a root nginx.")
	}
}

// frontendSecurityProperties are the securityContext settings that make the
// frontend pod match the rest of the chart, each with what its absence permits.
var frontendSecurityProperties = map[string]string{
	"runAsNonRoot: true":              "the kubelet stops refusing an image that resolves to uid 0",
	"readOnlyRootFilesystem: true":    "a compromised nginx can write anywhere in its own image",
	"allowPrivilegeEscalation: false": "a setuid binary in the image can regain what runAsUser dropped",
}

// TestTheFrontendPodKeepsItsSecurityContext pins the chart half.
func TestTheFrontendPodKeepsItsSecurityContext(t *testing.T) {
	src := readFileString(t, filepath.Join(repoRoot(t), "charts", "vault", "templates", "frontend.yaml"))

	for prop, consequence := range frontendSecurityProperties {
		if !strings.Contains(src, prop) {
			t.Errorf("charts/vault/templates/frontend.yaml no longer sets %q. Without it, %s.",
				prop, consequence)
		}
	}

	// A read-only root filesystem is only survivable because nginx has somewhere
	// to put its caches, pid and temp files. Drop a mount and the pod crashes on
	// startup, which reads as "readOnlyRootFilesystem broke it" and invites
	// removing the wrong line.
	// Matched as a whole mountPath value rather than as a substring. "/tmp" is a
	// prefix of every path under it, so a Contains check stays green when the
	// mount is renamed to "/tmpX", which is precisely the edit this must catch.
	for _, path := range []string{"/var/cache/nginx", "/var/run", "/tmp"} {
		if !hasMountPath(src, path) {
			t.Errorf("charts/vault/templates/frontend.yaml no longer mounts a writable volume at "+
				"%s. nginx needs it under readOnlyRootFilesystem, and without it the pod fails "+
				"to start in a way that points at the wrong setting.", path)
		}
	}
}

// TestTheFrontendImageTagIsPinnedToTheChart stops the tag drifting back to a
// floating one.
//
// Every other image in this chart is pinned. A frontend on `latest` means two
// pods in the same release can serve different builds, a rollback does not roll
// the frontend back, and the version an incident is reconstructed against is
// whatever the registry happened to hold.
func TestTheFrontendImageTagIsPinnedToTheChart(t *testing.T) {
	src := readFileString(t, filepath.Join(repoRoot(t), "charts", "vault", "templates", "frontend.yaml"))

	if !strings.Contains(src, ".Chart.AppVersion") {
		t.Error("charts/vault/templates/frontend.yaml no longer falls back to .Chart.AppVersion " +
			"for the image tag. An unset frontend.image.tag then renders an unpinned reference.")
	}
	if strings.Contains(src, ":latest") {
		t.Error("charts/vault/templates/frontend.yaml pins the frontend to :latest")
	}
}

// hasMountPath reports whether the template mounts a volume at exactly this
// path, comparing the whole YAML value rather than a substring so a renamed
// mount cannot satisfy it by prefix.
func hasMountPath(src, path string) bool {
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "mountPath:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "mountPath:"))
		value = strings.Trim(value, `"'`)
		if value == path {
			return true
		}
	}
	return false
}
