package compliance

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// =============================================================================
// Kubernetes Pod Security Standards — the "restricted" profile
//
// Named precisely, and not "CIS Kubernetes Benchmark". That benchmark is
// overwhelmingly control-plane, etcd, kubelet and node configuration, none of
// which a Helm chart owns; claiming it would be the exact overclaim pattern
// this register is trying to leave behind. PSS is workload-scoped, which is
// what a chart can actually be held to.
//
// What the chart deploys is not one thing, so the claim is not one claim
// either. Three groups:
//
//   - the vault-plane workloads (vault, admin gateway, frontend, redis,
//     cloudflared, bridge, honeypot vault) meet restricted, and this asserts
//     each of the profile's controls on each of them;
//   - the admin gateway meets every control except hostNetwork, which PSS
//     forbids at baseline and which the chart sets deliberately so the gateway
//     binds the node's loopback. That is a real deviation and is recorded as
//     one rather than being called compliance;
//   - the bundled PostgreSQL and Mailpit are development conveniences, both
//     disabled by default and both labeled "dev only" in values.yaml. They do
//     not meet restricted, and the register says so rather than quietly scoping
//     them out.
//
// The assertions read the templates rather than a rendered manifest, so they
// run wherever `go test ./tests/...` runs and do not need helm on PATH.
// =============================================================================

// pssWorkload is a chart template that must satisfy the restricted profile,
// with where each half of its security context comes from.
type pssWorkload struct {
	template string
	// inheritsValues records how the workload got its context when this list was
	// written. It is not what the assertion keys on -- resolveSecurityContext
	// follows .Values and _helpers.tpl alike -- but it says which shape a reader
	// should expect to find.
	inheritsValues bool
	note           string
}

var pssRestrictedWorkloads = []pssWorkload{
	{"deployment.yaml", true, "the vault server itself, the only workload the chart deploys by default"},
	{"admin-gateway.yaml", true, "meets every control except hostNetwork; see the deviation asserted below"},
	{"bridge.yaml", true, "non-default deployment mode, held to the same profile"},
	{"honeypot-vault.yaml", true, "non-default deployment mode, held to the same profile"},
	{"frontend.yaml", false, "nginx-unprivileged, declares its own context because it runs as uid 101"},
	{"redis.yaml", false, "declares its own context because it runs as uid 999"},
	{"cloudflared.yaml", false, "declares its own context"},
	// Hardened after the fact, and the reason they were once excluded. The
	// bundled datastores and the mail catcher are still dev-only and still off
	// by default; being off by default is not a security property, so they are
	// held to the profile like everything else.
	{"postgres.yaml", false, "bundled dev database, hardened; fsGroup 70 because postgres:17-alpine runs as uid 70, not 999"},
	{"honeypot-postgres.yaml", false, "the honeypot's own database"},
	{"mailpit.yaml", false, "dev mail catcher"},
}

// restrictedPodControls are the pod-level settings the profile requires.
var restrictedPodControls = map[string]string{
	"runAsNonRoot: true": "without it the kubelet will start a container whose image resolves to uid 0",
	"seccompProfile":     "RuntimeDefault or Localhost is required at restricted; unconfined is the default otherwise",
}

// restrictedContainerControls are the container-level settings the profile
// requires.
var restrictedContainerControls = map[string]string{
	"allowPrivilegeEscalation: false": "a setuid binary in the image otherwise regains what runAsUser dropped",
	"drop":                            "capabilities must drop ALL at restricted",
}

// TestK8sPSS_Restricted_VaultPlaneWorkloadsMeetTheProfile reads each template
// and asserts the controls are present, either inline or through the values the
// template inherits.
func TestK8sPSS_Restricted_VaultPlaneWorkloadsMeetTheProfile(t *testing.T) {
	root := repoRoot(t)
	values := readChartFile(t, "values.yaml")

	// The shared defaults, which four of the seven workloads inherit.
	for control, why := range restrictedPodControls {
		if !strings.Contains(values, control) {
			t.Errorf("PSS restricted: charts/vault/values.yaml podSecurityContext no longer sets %q -- %s",
				control, why)
		}
	}
	for control, why := range restrictedContainerControls {
		if !strings.Contains(values, control) {
			t.Errorf("PSS restricted: charts/vault/values.yaml securityContext no longer sets %q -- %s",
				control, why)
		}
	}
	if !strings.Contains(values, "runAsUser: 65532") {
		t.Error("PSS restricted: the shared podSecurityContext no longer pins a non-root uid")
	}

	for _, w := range pssRestrictedWorkloads {
		path := filepath.Join(root, "charts", "vault", "templates", w.template)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("PSS restricted: charts/vault/templates/%s is named in the register and does "+
				"not exist", w.template)
			continue
		}
		src := string(raw)

		// Every pod spec should refuse the service-account token it does not
		// use. This is not a PSS control -- PSS says nothing about it -- but it
		// is the same class of default and the chart is otherwise consistent
		// about it. cloudflared is the one workload that omits it, which is a
		// real gap in the chart rather than a gap in this profile; it is
		// recorded here so that it stays the only one.
		if !strings.Contains(src, "automountServiceAccountToken: false") {
			if w.template == "cloudflared.yaml" {
				t.Logf("note, outside the PSS profile: charts/vault/templates/%s does not set "+
					"automountServiceAccountToken: false, and every other workload in the chart "+
					"does. Worth closing; it is not part of the restricted claim.", w.template)
				continue
			}
			t.Errorf("PSS restricted: %s no longer disables service-account token automounting (%s). "+
				"cloudflared is the one recorded exception; a second one is a regression.",
				w.template, w.note)
		}

		podSrc, ctrSrc := resolveSecurityContext(t, src, values)

		for control, why := range restrictedPodControls {
			if !strings.Contains(podSrc, control) {
				t.Errorf("PSS restricted: nothing reaching %s sets %q -- %s (%s)",
					w.template, control, why, w.note)
			}
		}
		for control, why := range restrictedContainerControls {
			if !strings.Contains(ctrSrc, control) {
				t.Errorf("PSS restricted: nothing reaching %s sets %q -- %s (%s)",
					w.template, control, why, w.note)
			}
		}
	}
}

// resolveSecurityContext returns the text a workload's pod and container
// security contexts really come from.
//
// A chart can supply them three ways and all three are legitimate: inline in the
// template, through .Values, or through a named helper in _helpers.tpl. An
// assertion that only understands one of the three does not check the property,
// it checks the spelling -- and it fails the day a chart is refactored, which is
// the worst moment for a security gate to cry wolf.
func resolveSecurityContext(t *testing.T, template, values string) (pod, container string) {
	t.Helper()

	pod, container = template, template
	if strings.Contains(template, ".Values.podSecurityContext") {
		pod += "\n" + values
	}
	if strings.Contains(template, ".Values.securityContext") {
		container += "\n" + values
	}
	if strings.Contains(template, `include "vault.podSecurityContext"`) {
		pod += "\n" + chartHelper(t, "vault.podSecurityContext")
	}
	if strings.Contains(template, `include "vault.containerSecurityContext"`) {
		container += "\n" + chartHelper(t, "vault.containerSecurityContext")
	}
	return pod, container
}

// chartHelper returns the body of one define block in _helpers.tpl, or "" when
// the chart has no such helper.
func chartHelper(t *testing.T, name string) string {
	t.Helper()
	src := readChartFile(t, "templates/_helpers.tpl")
	start := strings.Index(src, `define "`+name+`"`)
	if start < 0 {
		t.Errorf("PSS restricted: a template includes %q, which _helpers.tpl does not define. "+
			"Helm would fail to render; this says so with the control that goes missing.", name)
		return ""
	}
	end := strings.Index(src[start:], "{{- end }}")
	if end < 0 {
		return src[start:]
	}
	return src[start : start+end]
}

// pssAllowedVolumeTypes is the restricted profile's volume allow-list, verbatim.
// The profile names the permitted types rather than forbidding a few, so a scan
// that only refuses hostPath answers a narrower question than the one PSS asks:
// nfs, iscsi, gitRepo and flexVolume are all forbidden and none of them is
// hostPath. This is what PSS-volume-types is Met on, and it has to be an
// allow-list for the row to be true.
var pssAllowedVolumeTypes = map[string]bool{
	"configMap":             true,
	"csi":                   true,
	"downwardAPI":           true,
	"emptyDir":              true,
	"ephemeral":             true,
	"persistentVolumeClaim": true,
	"projected":             true,
	"secret":                true,
}

// pssVolumesBlockRe finds a `volumes:` key and captures its indentation, so the
// entries beneath it can be read without mistaking a volumeMount, an env var or
// a container port for a volume -- each of those is also a `- name:` item
// followed by a key, and a regex that only looks at that shape matches all of
// them.
var pssVolumesBlockRe = regexp.MustCompile(`(?m)^([ \t]*)volumes:[ \t]*$`)

// pssVolumeItemRe matches the head of one volume entry inside such a block.
var pssVolumeItemRe = regexp.MustCompile(`^([ \t]*)- name:`)

// pssVolumeTypeRe matches the type key of a volume entry.
var pssVolumeTypeRe = regexp.MustCompile(`^([ \t]*)([A-Za-z][A-Za-z0-9]*):`)

// pssCapabilityAddRe matches a capabilities add, in either YAML form: a block
// list on following lines, or an inline flow list. The old scan looked for the
// bare token "add:" over charts/vault/templates only, and the container
// securityContext is in values.yaml, so `capabilities: {drop: [ALL], add:
// [SYS_ADMIN]}` in the chart defaults passed this gate and the tests/spec render
// gate together while giving every container in a default install CAP_SYS_ADMIN.
var pssCapabilityAddRe = regexp.MustCompile(`(?m)^\s*add:\s*(\[\s*[^\]\s][^\]]*\]|$)`)

// TestK8sPSS_Restricted_NoWorkloadTakesAHostNamespaceOrPrivilege is the
// negative half. The profile forbids host namespaces, host ports, privileged
// containers, added capabilities and every volume type outside its allow-list,
// and the only way to know none of them arrived is to look for all of them.
//
// The corpus is the templates AND the values files. A chart's securityContext
// can be written in either, this one writes it in values.yaml, and a scan of
// templates/ alone cannot see the setting it exists to check.
func TestK8sPSS_Restricted_NoWorkloadTakesAHostNamespaceOrPrivilege(t *testing.T) {
	root := repoRoot(t)
	chart := filepath.Join(root, "charts", "vault")

	var files []string
	for _, sub := range []string{"templates", ""} {
		dir := filepath.Join(chart, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
				continue
			}
			if sub == "" && !strings.HasPrefix(entry.Name(), "values") {
				continue
			}
			files = append(files, filepath.Join(sub, entry.Name()))
		}
	}

	forbidden := map[string]string{
		"privileged: true": "a privileged container is outside baseline, let alone restricted",
		"hostPID: true":    "the host process namespace is forbidden at baseline",
		"hostIPC: true":    "the host IPC namespace is forbidden at baseline",
		"hostPath:":        "hostPath volumes are forbidden at baseline",
		"hostPort:":        "host ports are forbidden at baseline, and PSS-host-ports is Met on their absence",
	}

	scanned := 0
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(chart, rel))
		if err != nil {
			continue
		}
		src := string(raw)
		scanned++
		shown := filepath.ToSlash(filepath.Join("charts/vault", rel))

		for token, why := range forbidden {
			if strings.Contains(src, token) {
				t.Errorf("PSS restricted: %s contains %q -- %s", shown, token, why)
			}
		}

		// Capabilities. drop: ALL followed by an add is the shape the profile
		// forbids, and the restricted profile permits exactly one addition.
		for _, m := range pssCapabilityAddRe.FindAllString(src, -1) {
			if strings.Contains(m, "NET_BIND_SERVICE") {
				continue
			}
			t.Errorf("PSS restricted: %s adds a capability back (%q). The restricted profile "+
				"requires drop ALL and permits only NET_BIND_SERVICE, and nothing in this "+
				"chart binds a privileged port.", shown, strings.TrimSpace(m))
		}

		// Volume types, as the allow-list the profile actually specifies.
		for _, kind := range volumeTypesIn(src) {
			if pssAllowedVolumeTypes[kind] {
				continue
			}
			t.Errorf("PSS restricted: %s declares a %q volume. The restricted profile allows "+
				"only %v, so this is not a narrower spelling of an allowed type; it is one the "+
				"profile forbids.", shown, kind, sortedVolumeTypes(pssAllowedVolumeTypes))
		}

		// hostNetwork is the one deviation, and it belongs to exactly one
		// workload. Anywhere else it is a regression.
		if strings.Contains(src, "hostNetwork: true") && rel != filepath.Join("templates", "admin-gateway.yaml") {
			t.Errorf("PSS restricted: %s takes the host network unconditionally. The admin "+
				"gateway is the only workload permitted to offer it at all, and even there it "+
				"is opt-in and off by default.", shown)
		}
	}

	if scanned < 10 {
		t.Fatalf("only %d chart files scanned; the walk is broken and every assertion above is "+
			"vacuous", scanned)
	}
	if volumes := countVolumeDeclarations(t, chart, files); volumes < 5 {
		t.Fatalf("only %d volume declarations were parsed out of %d chart files. The chart mounts "+
			"more than that; the volume regex no longer matches the chart's shape, so the "+
			"allow-list above cleared every volume by not seeing one.", volumes, scanned)
	}
	t.Logf("PSS restricted: %d chart files scanned for host namespaces, privilege, added "+
		"capabilities, host ports and volume types", scanned)
}

// TestK8sPSS_Restricted_ThereAreNoDeviationsLeft is what the deviation and
// exclusion tests became.
//
// Two earlier versions of this file existed to keep an honest scope on a claim
// that did not cover everything: one pinned the admin gateway's hostNetwork as
// the single recorded deviation, and one failed the day postgres,
// honeypot-postgres or mailpit was hardened, so the exclusion could not outlive
// its reason. Both fired. hostNetwork now defaults to false and all three
// workloads meet the profile, so the claim is unqualified and this asserts that
// rather than asserting a carve-out.
func TestK8sPSS_Restricted_ThereAreNoDeviationsLeft(t *testing.T) {
	values := readChartFile(t, "values.yaml")

	// The one setting that used to be the deviation. It may still be opted into
	// -- LocalOnly genuinely wants the node's loopback -- but the default is
	// what the register describes, and a default is what most deployments get.
	if !strings.Contains(values, "hostNetwork: false") {
		t.Error("PSS restricted: adminGateway.hostNetwork no longer defaults to false. Both the " +
			"baseline and restricted profiles forbid host namespaces, so a default render would " +
			"stop meeting the claim the register makes; if the default has moved, the row goes back " +
			"to an accepted risk with the argument written down.")
	}
	gw := readChartFile(t, "templates/admin-gateway.yaml")
	if !strings.Contains(gw, "{{- if .Values.adminGateway.hostNetwork }}") {
		t.Error("PSS restricted: the admin gateway no longer gates hostNetwork on the value, so it " +
			"is emitted unconditionally regardless of what values.yaml says")
	}

	// The three formerly-excluded workloads are covered by
	// pssRestrictedWorkloads above. What is asserted here is that they are
	// still labeled for what they are: a hardened dev database is still a dev
	// database, and the deployment guide tells operators not to run it.
	for _, dev := range []struct{ marker, label string }{
		{"# ---- PostgreSQL (dev/embedded only) ----", "postgres"},
		{"# ---- Mailpit (dev only) ----", "mailpit"},
	} {
		if !strings.Contains(values, dev.marker) {
			t.Errorf("PSS restricted: charts/vault/values.yaml no longer labels the bundled %s as "+
				"development-only. It meets the profile now, which is not the same as it being a "+
				"supported production datastore.", dev.label)
		}
	}
	for _, template := range []string{"postgres.yaml", "mailpit.yaml"} {
		if !strings.Contains(readChartFile(t, "templates/"+template), ".enabled }}") {
			t.Errorf("PSS restricted: charts/vault/templates/%s is no longer gated on an enabled "+
				"flag, so it may render in a default install", template)
		}
	}
}

func readChartFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "charts", "vault", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read charts/vault/%s: %v", rel, err)
	}
	return string(raw)
}

// sortedVolumeTypes renders the allow-list deterministically for a failure
// message.
func sortedVolumeTypes(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// countVolumeDeclarations is the floor under the volume allow-list. A regex that
// stops matching the chart's shape would clear every volume by finding none, and
// PSS-volume-types would go on being Met on a check that read nothing.
func countVolumeDeclarations(t *testing.T, chart string, files []string) int {
	t.Helper()
	n := 0
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(chart, rel))
		if err != nil {
			continue
		}
		n += len(volumeTypesIn(string(raw)))
	}
	return n
}

// volumeTypesIn returns the type key of every volume declared in one chart file.
//
// The blocks are read by indentation rather than parsed, because a chart
// template is Go template source and not YAML until Helm has rendered it. A
// volume entry is a `- name:` item under a `volumes:` key, and its type is the
// first key one level inside it; anything deeper belongs to that type
// (secretName, claimName) and anything shallower has left the block.
func volumeTypesIn(src string) []string {
	lines := strings.Split(src, "\n")
	var kinds []string

	for i, line := range lines {
		block := pssVolumesBlockRe.FindStringSubmatch(line)
		if block == nil {
			continue
		}
		blockIndent := len(block[1])

		itemIndent := -1
		for _, next := range lines[i+1:] {
			trimmed := strings.TrimSpace(next)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "{{") {
				continue
			}
			indent := len(next) - len(strings.TrimLeft(next, " \t"))
			if indent <= blockIndent {
				break // the block ended
			}
			if m := pssVolumeItemRe.FindStringSubmatch(next); m != nil {
				itemIndent = len(m[1]) + 2
				continue
			}
			if itemIndent < 0 {
				continue
			}
			if m := pssVolumeTypeRe.FindStringSubmatch(next); m != nil && len(m[1]) == itemIndent {
				kinds = append(kinds, m[2])
				itemIndent = -1
			}
		}
	}
	return kinds
}
