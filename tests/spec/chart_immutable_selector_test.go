// A workload selector is immutable, so changing one breaks every upgrade.
//
// `spec.selector` on a Deployment cannot be patched. The 1.0.0 chart added
// app.kubernetes.io/component: vault to the main Deployment's selector, and the
// result on a live cluster was:
//
//	Error: UPGRADE FAILED: cannot patch "v42-vault-auth" with kind Deployment:
//	Deployment.apps "v42-vault-auth" is invalid: spec.selector: Invalid value:
//	{...}: field is immutable
//
// from every previously released chart, with the Service and ConfigMap already
// patched and the release left `failed`. The label was not load-bearing there --
// the ReplicaSet a Deployment creates also selects on pod-template-hash, and the
// Service, NetworkPolicy, PDB and ServiceMonitor that genuinely need the
// component label are all patchable in place -- so it came out again.
//
// Two gates, because they fail on different days. The first runs everywhere and
// says what the vault Deployment's selector has to be. The second needs the
// release tag in the working copy and is the general one: it renders the last
// released chart and this one and refuses any selector that moved, on any
// workload, which is how the next one gets caught in review instead of in
// somebody's production upgrade.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestVaultDeploymentSelectorIsExactlySelectorLabels renders vault.selectorLabels
// and the Deployment from the same chart and requires them to agree, so the gate
// carries no transcript of the labels it is protecting.
func TestVaultDeploymentSelectorIsExactlySelectorLabels(t *testing.T) {
	helm := helmOrSkip(t)
	root := repoRoot(t)

	want := renderSelectorLabels(t, helm, root)
	if len(want) == 0 {
		t.Fatal("vault.selectorLabels rendered nothing, so this gate would accept a Deployment " +
			"with an empty selector")
	}

	got := workloadSelectors(t, helm, root, chartDir)
	selector, ok := got[workloadKey{"Deployment", "release-vault-auth"}]
	if !ok {
		t.Fatalf("the chart no longer renders a Deployment named release-vault-auth; it has %v",
			sortedWorkloadKeys(got))
	}

	if !sameLabels(selector, want) {
		t.Errorf("the vault Deployment selects on %v, and vault.selectorLabels is %v.\n"+
			"spec.selector is immutable: an operator upgrading from any release whose "+
			"Deployment selected on %v gets `field is immutable` and a half-patched release. "+
			"The component label belongs on the pod template and on the Service, "+
			"NetworkPolicy, PDB and ServiceMonitor, all of which can be patched. If this "+
			"change is deliberate, it is a breaking chart change: write the orphan-delete "+
			"procedure into docs/UPGRADING.md and update this gate in the same commit.",
			selector, want, want)
	}
}

// TestNoWorkloadSelectorChangedSinceTheLastRelease is the general form. It
// renders the chart at the most recent release tag and compares every workload
// selector with this one's.
func TestNoWorkloadSelectorChangedSinceTheLastRelease(t *testing.T) {
	helm := helmOrSkip(t)
	root := repoRoot(t)

	tag := lastReleaseTag(t, root)
	old := filepath.Join(t.TempDir(), "released")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatalf("create export dir: %v", err)
	}
	exportChartAtTag(t, root, tag, old)

	before := workloadSelectors(t, helm, old, filepath.Join(old, chartDir))
	after := workloadSelectors(t, helm, root, chartDir)

	for key, was := range before {
		now, ok := after[key]
		if !ok {
			// A workload that no longer renders is a different decision, and
			// helm deletes it rather than patching it. Not this gate's business.
			continue
		}
		if !sameLabels(was, now) {
			t.Errorf("%s %s selected on %v in %s and selects on %v now.\n"+
				"spec.selector is immutable, so `helm upgrade` from %s fails outright with "+
				"`field is immutable` and leaves the release half-patched. Either put the "+
				"selector back and carry the new label on the pod template only, or ship the "+
				"orphan-delete procedure in docs/UPGRADING.md and update this gate with it.",
				key.kind, key.name, was, tag, now, tag)
		}
	}
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

type workloadKey struct{ kind, name string }

// selectorKinds are the kinds whose spec.selector is immutable once created.
// A Service's is not, and neither is a PodDisruptionBudget's -- both were
// verified patchable on a live cluster during the same failed upgrade -- so
// neither belongs here.
var selectorKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"Job":         true,
}

// workloadSelectors renders every value profile and collects spec.selector
// .matchLabels per workload. Profiles are merged because a workload that only
// exists under one of them still has to keep its selector.
func workloadSelectors(t *testing.T, helm, dir, chart string) map[workloadKey]map[string]string {
	t.Helper()
	out := make(map[workloadKey]map[string]string)

	for _, profile := range valuesProfiles {
		args := []string{
			"template", "release", chart, "--namespace", "vault",
			"--set", "adminGateway.tls.secretName=admin-tls",
		}
		if profile != "" {
			args = append(args, "-f", filepath.Join(chart, profile))
		}
		for _, doc := range renderDocs(t, helm, dir, args) {
			kind, _ := doc["kind"].(string)
			if !selectorKinds[kind] {
				continue
			}
			name, _ := mapAt(doc, "metadata")["name"].(string)
			labels := make(map[string]string)
			for k, v := range mapAt(mapAt(mapAt(doc, "spec"), "selector"), "matchLabels") {
				if s, ok := v.(string); ok {
					labels[k] = s
				}
			}
			out[workloadKey{kind, name}] = labels
		}
	}
	return out
}

// renderSelectorLabels executes vault.selectorLabels out of the chart's own
// _helpers.tpl, with the chart's own values, rather than restating what it
// should produce.
func renderSelectorLabels(t *testing.T, helm, root string) map[string]string {
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
		"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe\nlabels:\n"+
			"  {{- include \"vault.selectorLabels\" . | nindent 2 }}\n")

	for _, doc := range renderDocs(t, helm, root, []string{
		"template", "release", probe, "--namespace", "vault",
	}) {
		labels := make(map[string]string)
		for k, v := range mapAt(doc, "labels") {
			if s, ok := v.(string); ok {
				labels[k] = s
			}
		}
		if len(labels) > 0 {
			return labels
		}
	}
	t.Fatal("the probe chart rendered no labels, so vault.selectorLabels was never executed")
	return nil
}

// ---------------------------------------------------------------------------
// The released chart
// ---------------------------------------------------------------------------

// lastReleaseTag is the most recent tag reachable from HEAD -- the version an
// operator is upgrading from.
func lastReleaseTag(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "describe", "--tags", "--abbrev=0", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		t.Skip("no release tag is reachable from HEAD, so the previously released chart " +
			"cannot be rendered. A shallow clone does this; fetch tags (actions/checkout " +
			"with fetch-depth: 0) to run this gate.")
	}
	return strings.TrimSpace(string(out))
}

func exportChartAtTag(t *testing.T, root, tag, dest string) {
	t.Helper()
	archive := exec.Command("git", "-C", root, "archive", tag, chartDir) // #nosec G204 -- tag comes from git describe in this repo
	untar := exec.Command("tar", "-x", "-C", dest)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		t.Fatalf("pipe git archive: %v", err)
	}
	untar.Stdin = pipe
	if err := untar.Start(); err != nil {
		t.Fatalf("start tar: %v", err)
	}
	if err := archive.Run(); err != nil {
		t.Fatalf("git archive %s: %v", tag, err)
	}
	if err := untar.Wait(); err != nil {
		t.Fatalf("extract %s: %v", tag, err)
	}
	if _, err := os.Stat(filepath.Join(dest, chartDir, "Chart.yaml")); err != nil {
		t.Fatalf("%s holds no chart at %s: %v", tag, chartDir, err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// helmOrSkip resolves helm once, with the same reasoning as the other chart
// gates: without it the manifests cannot be produced at all.
func helmOrSkip(t *testing.T) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH, so the rendered manifests cannot be produced. " +
			"Install helm, or add azure/setup-helm to the job, to run this gate.")
	}
	return helm
}

func renderDocs(t *testing.T, helm, root string, args []string) []map[string]any {
	t.Helper()
	cmd := exec.Command(helm, args...) // #nosec G204 -- fixed args over paths inside this repo
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}

	var docs []map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(stdout.Bytes()))
	for {
		var doc map[string]any
		if err := decoder.Decode(&doc); err != nil {
			break
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs
}

func sameLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func sortedWorkloadKeys(m map[workloadKey]map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, fmt.Sprintf("%s/%s", k.kind, k.name))
	}
	sort.Strings(out)
	return out
}

func copyInto(t *testing.T, from, to string) {
	t.Helper()
	body, err := os.ReadFile(from) // #nosec G304 -- fixed path inside this repo
	if err != nil {
		t.Fatalf("read %s: %v", from, err)
	}
	writeProbeFile(t, to, string(body))
}

func writeProbeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
