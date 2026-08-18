// Chart wiring gate for the first-boot credential sink.
//
// Three credentials are minted exactly once, on a boot, and have no second
// chance to be shown: the admin token, each seeded client secret, and the admin
// gateway's super_admin bootstrap password. All three used to go to the process
// log, which in every deployment this chart targets is scraped into an
// aggregator whose readers are a wider set than the database the credential
// protects, and which keeps them long after they are rotated.
//
// internal/firstboot replaced that with a sink that is a 0600 file, or a
// terminal, or nothing -- and nothing means the boot step refuses. A pod is not
// a terminal, so the chart is the only thing that can supply the file, and a
// chart that does not supply it turns a seeded install into a CrashLoopBackOff.
// Refusing is correct; a chart that leaves it refusing is not.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// workloadsThatMintCredentials maps a chart template to the boot path in it that
// reaches firstboot.Deliver. Each has to name the sink, and the two get their
// env from different places -- the vault Deployment through the shared ConfigMap,
// the admin gateway from an inline env block -- so setting it once covers one of
// them and silently leaves the other refusing.
var workloadsThatMintCredentials = map[string]string{
	"configmap.yaml": "the vault Deployment, which mints a secret per seeded client and the admin " +
		"token whenever secrets.keys.adminToken is unset",
	"admin-gateway.yaml": "the admin gateway, whose EnsureFirstAdmin mints the super_admin " +
		"bootstrap password on a first boot against an empty admin table -- the one credential " +
		"here with no other way in",
}

// TestEveryMintingWorkloadNamesACredentialSink reads the env var's name out of
// the Go source rather than repeating it, so renaming the constant fails here
// instead of at somebody's first install.
func TestEveryMintingWorkloadNamesACredentialSink(t *testing.T) {
	root := repoRoot(t)
	src := readFileString(t, filepath.Join(root, "internal", "firstboot", "firstboot.go"))

	match := regexp.MustCompile(`CredentialFileEnv\s*=\s*"([^"]+)"`).FindStringSubmatch(src)
	if match == nil {
		t.Fatal("internal/firstboot no longer declares CredentialFileEnv. The chart names an " +
			"env var the package reads by that constant; if it moved, the chart is setting a " +
			"name nothing consumes and every first-boot credential path refuses again.")
	}
	env := match[1]

	for template, path := range workloadsThatMintCredentials {
		body := readFileString(t, filepath.Join(root, chartDir, "templates", template))
		if !strings.Contains(body, env) {
			t.Errorf("charts/vault/templates/%s does not name %s. Without it %s has nowhere to "+
				"put the credential, and because the delivery is deliberately fail-closed that "+
				"step does not fall back to the log -- it refuses, and the pod does not finish "+
				"booting.", template, env, path)
		}
	}
}

// TestTheCredentialSinkIsWritable checks the half a name alone does not give.
//
// Every workload here runs non-root on a read-only root filesystem, so naming a
// path is not the same as being able to create it. The failure that produces is
// "permission denied" at the moment a credential is minted, which is both the
// least recoverable moment and the one nobody tests.
func TestTheCredentialSinkIsWritable(t *testing.T) {
	root := repoRoot(t)
	values := readFileString(t, filepath.Join(root, chartDir, "values.yaml"))

	match := regexp.MustCompile(`(?m)^\s+path:\s*(\S+)`).FindStringSubmatch(
		sectionOf(values, "firstBootCredential:"))
	if match == nil {
		t.Fatal("values.yaml has no firstBootCredential.path")
	}
	sinkDir := filepath.Dir(match[1])

	for _, template := range []string{"deployment.yaml", "admin-gateway.yaml"} {
		body := readFileString(t, filepath.Join(root, chartDir, "templates", template))

		if !strings.Contains(body, `include "vault.firstBootCredentialMount"`) {
			t.Errorf("charts/vault/templates/%s does not mount the first-boot credential "+
				"volume. The container runs with readOnlyRootFilesystem, so the path it was "+
				"told to write is not writable and the mint refuses with a permission error.",
				template)
		}
		if !strings.Contains(body, `include "vault.firstBootCredentialVolume"`) {
			t.Errorf("charts/vault/templates/%s mounts no volume for the credential sink.", template)
		}
	}

	// The writer refuses a path that exists and is not a regular file. Mounting
	// the volume on the file rather than on its directory makes the path a
	// directory, and every mint then fails on a message about regular files.
	helpers := readFileString(t, filepath.Join(root, chartDir, "templates", "_helpers.tpl"))
	if !strings.Contains(helpers, "dir .Values.firstBootCredential.path") {
		t.Errorf("vault.firstBootCredentialMount no longer mounts at the directory holding "+
			"the credential file (%s). Mounting on the file itself makes the path a directory, "+
			"and internal/firstboot refuses any path that is not a regular file.", sinkDir)
	}
}

// TestTheCredentialSinkNeverLandsOnANodeDisk keeps the default off local storage.
//
// The file holds a credential in cleartext for as long as it exists. A default
// that writes it to whatever backs the node's emptyDir storage trades a leak
// into the log for a leak onto a disk, which is the same finding wearing a
// different hat.
func TestTheCredentialSinkNeverLandsOnANodeDisk(t *testing.T) {
	helpers := readFileString(t, filepath.Join(repoRoot(t), chartDir, "templates", "_helpers.tpl"))
	volume := sectionOf(helpers, `define "vault.firstBootCredentialVolume"`)

	if !strings.Contains(volume, "medium: Memory") {
		t.Error("the default first-boot credential volume is not memory-backed. It holds a " +
			"credential in cleartext, so the default should not put it on a node's disk; an " +
			"operator who needs it to outlive the pod names a claim instead.")
	}
}

// sectionOf returns the text from a marker to the next blank-line-separated
// block, which is enough to scope the assertions above to the right stanza.
func sectionOf(src, marker string) string {
	i := strings.Index(src, marker)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n\n"); j > 0 {
		return rest[:j]
	}
	return rest
}
