// Secret-in-argv gate for the chart's own workloads.
//
// The in-cluster Redis took its password as "--requirepass $(REDIS_PASSWORD)".
// The env var behind it came from a Secret, which looks careful and is not:
// kubelet substitutes $(VAR) into the argument vector before it execs the
// container, so the cleartext password ended up in /proc/<pid>/cmdline. Anything
// sharing that PID namespace can read it, a debug or ephemeral container added
// later can read it, and a core dump or a process listing captured for support
// carries it out of the cluster. Nothing rotates as a result, because nothing
// records that the password was ever exposed.
//
// A Secret volume does not have that problem: the value is a file the container
// reads, and the argument vector names a path.
//
// This is invisible to helm lint and to a rendering check, both of which see
// valid YAML, and invisible to a reading of values.yaml, which correctly shows
// the password coming from a Secret.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// envItemName matches the start of a container env entry. The uppercase form is
// what the chart uses for every env var, and restricting to it keeps the scan
// off the "- name:" of containers, volumes and ports.
var envItemName = regexp.MustCompile(`^\s*- name: ([A-Z_][A-Z0-9_]*)\s*$`)

// secretRefWindow is how many lines after a "- name: FOO" a secretKeyRef may
// appear and still belong to it. A valueFrom/secretKeyRef/name/key block is four
// lines, so six leaves room for reordering without reaching the next entry.
const secretRefWindow = 6

// chartTemplateFiles returns every template the chart renders.
func chartTemplateFiles(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "charts", "vault", "templates")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no templates; the scan below would pass by finding nothing", dir)
	}
	return out
}

// withoutComments drops whole-line YAML comments. The templates explain in
// comments what they no longer do, and those sentences name the very flags this
// gate looks for, so scanning them would make the fix trip its own check.
func withoutComments(src string) string {
	lines := strings.Split(src, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// secretBackedEnvNames reports the env vars a template sources from a Secret.
func secretBackedEnvNames(src string) []string {
	lines := strings.Split(src, "\n")
	var names []string
	pending, pendingAt := "", -1
	for i, line := range lines {
		if m := envItemName.FindStringSubmatch(line); m != nil {
			pending, pendingAt = m[1], i
			continue
		}
		if pending != "" && strings.Contains(line, "secretKeyRef") && i-pendingAt <= secretRefWindow {
			names = append(names, pending)
			pending, pendingAt = "", -1
		}
	}
	return names
}

// TestNoChartTemplateExpandsASecretBackedEnvVarIntoAnArgument is the general
// form of the defect. Any template that names $(FOO) where FOO comes from a
// Secret has put that secret in the container's argument vector, whatever the
// workload is.
func TestNoChartTemplateExpandsASecretBackedEnvVarIntoAnArgument(t *testing.T) {
	for _, path := range chartTemplateFiles(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			src := withoutComments(readFileString(t, path))
			for _, name := range secretBackedEnvNames(src) {
				if strings.Contains(src, "$("+name+")") {
					t.Errorf("charts/vault/templates/%s expands $(%s) after sourcing it from a Secret. "+
						"kubelet substitutes it before exec, so the cleartext value lands in "+
						"/proc/<pid>/cmdline and is readable by every process in the pod's PID "+
						"namespace, by any ephemeral or debug container attached later, and by "+
						"anything that collects a process listing or a core dump off the node. "+
						"Mount the Secret and pass the path instead.",
						filepath.Base(path), name)
				}
			}
		})
	}
}

// TestTheInClusterRedisTakesItsPasswordFromAFileRatherThanAFlag pins the
// specific mechanism, so the general check above cannot be satisfied by simply
// deleting the password.
//
// redis has no environment variable for its password: the official image reads
// requirepass from its config file or from the command line, and only the config
// file keeps it out of argv. The chart writes the directive into a file the
// config includes, from a Secret mounted with just that one key.
func TestTheInClusterRedisTakesItsPasswordFromAFileRatherThanAFlag(t *testing.T) {
	path := filepath.Join(repoRoot(t), "charts", "vault", "templates", "redis.yaml")
	src := withoutComments(readFileString(t, path))

	if strings.Contains(src, "--requirepass") {
		t.Error("charts/vault/templates/redis.yaml passes --requirepass on the command line. " +
			"Whatever the value is written as, the expanded password is in /proc/<pid>/cmdline " +
			"of the redis process for the life of the pod.")
	}
	if !strings.Contains(src, "include /run/redis/requirepass.conf") {
		t.Error("charts/vault/templates/redis.yaml no longer includes /run/redis/requirepass.conf " +
			"from redis.conf. Without the include the generated file is never read and redis " +
			"serves the whole cache and every rate-limit counter unauthenticated to anything " +
			"that can reach port 6379 in the namespace.")
	}
	if !strings.Contains(src, "umask 077") {
		t.Error("charts/vault/templates/redis.yaml writes the requirepass file without umask 077. " +
			"The default 0644 makes the password readable to every uid in the container, which " +
			"is the exposure the move off the command line was for.")
	}
	if !strings.Contains(src, "medium: Memory") {
		t.Error("charts/vault/templates/redis.yaml no longer backs the requirepass file with a " +
			"memory emptyDir, so the cleartext password is written to the node's disk and " +
			"outlives the pod until the kubelet reclaims the volume.")
	}
	if !strings.Contains(src, "items:") {
		t.Error("charts/vault/templates/redis.yaml mounts the release Secret without an items " +
			"list, which gives redis the master key, the HMAC secret and the pepper as well as " +
			"its own password.")
	}
}
