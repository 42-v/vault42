// The Secret-key list an operator is handed has to be the list the pod mounts.
//
// NOTES.txt told operators the Secret "needs the keys" master-key,
// db-mig-password, db-app-password, hmac-secret and admin-token. The Deployment
// mounts eight, and following the list of five does not produce a running pod:
// without `pepper` the production profile refuses to start at all
// ("VAULT_PEPPER_FILE required (>=32 bytes) in production profile"), which is a
// CrashLoopBackOff on a fresh install; without `signing-key` the process logs
// one warning and carries on, and each of the three default replicas then signs
// with its own ephemeral key, so a token minted by one replica is rejected by
// the other two. Both were reproduced by running the real binary with exactly
// the five keys the list named and otherwise the chart's own environment.
//
// Nothing could have caught that. The env block is YAML in one template, the
// list was prose in another, and no renderer, linter or test read both. This
// gate does: it renders the Deployment and the list from the same chart, under
// the value profiles that switch each of the conditional keys on and off, and
// compares the two sets. It never states the list itself, so it cannot drift
// with it.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// secretKeyProfiles are the renders that switch each conditional key. Every
// entry has to agree, so a condition present in one template and missing from
// the other shows up as a disagreement in whichever profile flips it.
var secretKeyProfiles = []struct {
	name string
	sets []string
}{
	{"chart defaults", nil},
	{"memory cache drops the redis password", []string{"cache.backend=memory"}},
	{"no admin token key", []string{"secrets.keys.adminToken="}},
	{"no signing key and no pepper", []string{"secrets.keys.signingKey=", "secrets.keys.pepper="}},
	{"renamed keys", []string{
		"secrets.keys.masterKey=mk", "secrets.keys.pepper=pep", "secrets.keys.signingKey=sk",
	}},
}

// TestNotesListsEverySecretKeyTheDeploymentMounts is the gate. Both sides are
// rendered; neither is transcribed.
func TestNotesListsEverySecretKeyTheDeploymentMounts(t *testing.T) {
	helm := helmOrSkip(t)
	root := repoRoot(t)

	for _, profile := range secretKeyProfiles {
		t.Run(profile.name, func(t *testing.T) {
			mounted := secretKeysMountedByDeployment(t, helm, root, profile.sets)
			listed := secretKeysNotesLists(t, helm, root, profile.sets)

			if len(mounted) == 0 {
				t.Fatal("the rendered Deployment mounts no key out of the Secret at all, so this " +
					"gate would pass on a chart that names none of them")
			}
			if strings.Join(mounted, ", ") != strings.Join(listed, ", ") {
				t.Errorf("the Deployment mounts %v; NOTES.txt tells the operator to create %v.\n"+
					"An operator who creates exactly the Secret they were told to create gets a "+
					"pod that does not boot (a missing pepper is fatal in the production profile) "+
					"or one that boots into a fleet whose replicas reject each other's tokens (a "+
					"missing signing key). Whichever side is wrong, the two have to be the same "+
					"set.", mounted, listed)
			}
		})
	}
}

// TestNotesDoesNotHandWriteTheSecretKeyList keeps the list generated. A second
// hand-written copy would pass the gate above on the day it was written and
// drift on the next key.
func TestNotesDoesNotHandWriteTheSecretKeyList(t *testing.T) {
	notes := readFileString(t, filepath.Join(repoRoot(t), chartDir, "templates", "NOTES.txt"))

	head, _, found := strings.Cut(notes, "FIRST-BOOT CREDENTIALS")
	if !found {
		t.Fatal("NOTES.txt no longer has a FIRST-BOOT CREDENTIALS section, so this gate is " +
			"reading a section boundary that has moved and is checking the wrong text")
	}
	if !strings.Contains(head, `include "vault.requiredSecretKeys"`) {
		t.Error("NOTES.txt no longer renders the Secret-key list from vault.requiredSecretKeys. " +
			"The list it hands an operator is then a second copy of the Deployment's env block, " +
			"which is how it came to name five of the eight keys the pod mounts.")
	}
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// secretKeysMountedByDeployment reads the keys off the rendered vault
// Deployment: every env value that lands inside the Secret's own mount, with
// the mount path taken from the volumeMount rather than assumed.
func secretKeysMountedByDeployment(t *testing.T, helm, root string, sets []string) []string {
	t.Helper()
	args := []string{"template", "release", chartDir, "--namespace", "vault"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}

	var found map[string]any
	for _, doc := range renderDocs(t, helm, root, args) {
		if kind, _ := doc["kind"].(string); kind != "Deployment" {
			continue
		}
		labels := mapAt(mapAt(mapAt(mapAt(doc, "spec"), "template"), "metadata"), "labels")
		if component, _ := labels["app.kubernetes.io/component"].(string); component == "vault" {
			found = doc
			break
		}
	}
	if found == nil {
		t.Fatal("no Deployment in the rendered chart carries app.kubernetes.io/component: vault " +
			"on its pod template, so this gate cannot find the workload it is about")
	}

	container := vaultContainer(t, found)

	var mountPath string
	for _, m := range sliceAt(container, "volumeMounts") {
		mount, _ := m.(map[string]any)
		if name, _ := mount["name"].(string); name == "secrets" {
			mountPath, _ = mount["mountPath"].(string)
		}
	}
	if mountPath == "" {
		t.Fatal("the vault container has no volumeMount named \"secrets\", so there is no mount " +
			"path to recognize the Secret's own files by")
	}

	var keys []string
	for _, e := range sliceAt(container, "env") {
		env, _ := e.(map[string]any)
		value, _ := env["value"].(string)
		if rest, ok := strings.CutPrefix(value, mountPath+"/"); ok && rest != "" {
			keys = append(keys, rest)
		}
	}
	sort.Strings(keys)
	return keys
}

// secretKeysNotesLists renders vault.requiredSecretKeys -- the helper NOTES.txt
// prints -- with the real chart's values and the real chart's conditions.
//
// It is executed rather than parsed. A helper whose conditions were read out of
// its source would agree with whatever the reader believed those conditions
// meant, which is the failure this whole file exists to catch one template
// further along.
func secretKeysNotesLists(t *testing.T, helm, root string, sets []string) []string {
	t.Helper()
	probe := t.TempDir()
	if err := os.MkdirAll(filepath.Join(probe, "templates"), 0o750); err != nil {
		t.Fatalf("create probe chart: %v", err)
	}
	copyInto(t, filepath.Join(root, chartDir, "values.yaml"), filepath.Join(probe, "values.yaml"))
	copyInto(t,
		filepath.Join(root, chartDir, "templates", "_helpers.tpl"),
		filepath.Join(probe, "templates", "_helpers.tpl"))
	writeProbeFile(t, filepath.Join(probe, "Chart.yaml"),
		"apiVersion: v2\nname: vault-auth\nversion: 0.0.0\nappVersion: \"0.0.0\"\n")
	writeProbeFile(t, filepath.Join(probe, "templates", "probe.yaml"),
		"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe\ndata:\n"+
			"  keys: {{ include \"vault.requiredSecretKeys\" . | quote }}\n")

	args := []string{"template", "release", probe, "--namespace", "vault"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}

	for _, doc := range renderDocs(t, helm, root, args) {
		raw, ok := mapAt(doc, "data")["keys"].(string)
		if !ok {
			continue
		}
		var keys []string
		for _, k := range strings.Split(raw, ",") {
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		return keys
	}
	t.Fatal("the probe chart rendered no ConfigMap holding vault.requiredSecretKeys, so the " +
		"helper NOTES.txt prints was never executed")
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// vaultContainer returns the one container in the vault pod template. The
// Deployment has exactly one, and a gate that silently picked the first of
// several would stop seeing the env block it is about.
func vaultContainer(t *testing.T, deployment map[string]any) map[string]any {
	t.Helper()
	containers := sliceAt(mapAt(mapAt(mapAt(deployment, "spec"), "template"), "spec"), "containers")
	if len(containers) != 1 {
		t.Fatalf("the vault pod template has %d containers, not 1; this gate reads the env off "+
			"the only one it expects to find", len(containers))
	}
	container, _ := containers[0].(map[string]any)
	return container
}

func sliceAt(m map[string]any, key string) []any {
	out, _ := m[key].([]any)
	return out
}
