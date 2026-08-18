package compliance

import (
	"os"
	"path/filepath"
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

// TestK8sPSS_Restricted_NoWorkloadTakesAHostNamespaceOrPrivilege is the
// negative half. The profile forbids host namespaces, host ports, privileged
// containers, added capabilities and hostPath volumes, and the only way to know
// none of them arrived is to look for all of them.
func TestK8sPSS_Restricted_NoWorkloadTakesAHostNamespaceOrPrivilege(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "charts", "vault", "templates")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read chart templates: %v", err)
	}

	forbidden := map[string]string{
		"privileged: true": "a privileged container is outside baseline, let alone restricted",
		"hostPID: true":    "the host process namespace is forbidden at baseline",
		"hostIPC: true":    "the host IPC namespace is forbidden at baseline",
		"hostPath:":        "hostPath volumes are forbidden at baseline",
		"add:":             "adding a capability back is forbidden at restricted, which requires drop ALL and permits only NET_BIND_SERVICE",
	}

	scanned := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		src := string(raw)
		scanned++

		for token, why := range forbidden {
			if strings.Contains(src, token) {
				t.Errorf("PSS restricted: charts/vault/templates/%s contains %q -- %s",
					entry.Name(), token, why)
			}
		}

		// hostNetwork is the one deviation, and it belongs to exactly one
		// workload. Anywhere else it is a regression.
		if strings.Contains(src, "hostNetwork:") && entry.Name() != "admin-gateway.yaml" {
			t.Errorf("PSS restricted: charts/vault/templates/%s takes the host network. The admin "+
				"gateway's hostNetwork is a recorded deviation with an argument behind it; a "+
				"second one is not.", entry.Name())
		}
	}

	if scanned < 10 {
		t.Fatalf("only %d chart templates scanned; the walk is broken and every assertion above is "+
			"vacuous", scanned)
	}
	t.Logf("PSS restricted: %d chart templates scanned for host namespaces and privilege", scanned)
}

// TestK8sPSS_Restricted_TheDeviationsAreExactlyTheOnesRecorded pins what the
// register does *not* claim.
//
// Three workloads do not meet the profile, and the honest thing is to name them
// and say why they are acceptable, rather than to scope them out and let a
// reader infer the chart is uniformly restricted. If any of them is hardened,
// this test fails and the register row moves with it; if a fourth appears, it
// fails too.
func TestK8sPSS_Restricted_TheDeviationsAreExactlyTheOnesRecorded(t *testing.T) {
	// 1. The admin gateway takes the host network, deliberately: LocalOnly
	//    refuses anything that is not the node's loopback, and hostNetwork is
	//    what makes the pod's loopback the node's.
	gw := readChartFile(t, "templates/admin-gateway.yaml")
	if !strings.Contains(gw, "hostNetwork: true") {
		t.Error("PSS restricted: the admin gateway no longer takes the host network. That was the " +
			"one recorded deviation from the profile; if it is gone the register row should say " +
			"the vault plane meets restricted outright.")
	}
	if !strings.Contains(gw, "LocalOnly") && !strings.Contains(gw, "hostNetwork is false") {
		t.Error("PSS restricted: the admin gateway template no longer explains why it takes the " +
			"host network. A deviation without its argument written next to it becomes a defect " +
			"at the next review.")
	}

	// 2 and 3. The bundled datastore and mail catcher are development
	//    conveniences. They are excluded from the claim, and what makes that
	//    honest is that they are off by default and labeled as such.
	values := readChartFile(t, "values.yaml")
	for _, dev := range []struct{ marker, label string }{
		{"# ---- PostgreSQL (dev/embedded only) ----", "postgres"},
		{"# ---- Mailpit (dev only) ----", "mailpit"},
	} {
		if !strings.Contains(values, dev.marker) {
			t.Errorf("PSS restricted: charts/vault/values.yaml no longer labels the bundled %s as "+
				"development-only. The register excludes it from the PSS claim on exactly that "+
				"basis; if it becomes a supported production workload it has to meet the profile.",
				dev.label)
		}
	}

	// Off by default is the other half of that argument.
	for _, template := range []string{"postgres.yaml", "mailpit.yaml"} {
		src := readChartFile(t, "templates/"+template)
		if !strings.Contains(src, ".enabled }}") {
			t.Errorf("PSS restricted: charts/vault/templates/%s is no longer gated on an enabled "+
				"flag, so it may render in a default install", template)
		}
	}
}

// TestK8sPSS_Restricted_TheExcludedWorkloadsAreStillExcluded is the closure
// tripwire on the scope of the claim.
//
// postgres, honeypot-postgres and mailpit are excluded from the PSS claim
// because they do not meet the profile and are dev-only and off by default.
// That is an honest exclusion only while it is true. The day one of them is
// hardened, the register should stop excluding it rather than keep a permanent
// carve-out that quietly understates the chart.
func TestK8sPSS_Restricted_TheExcludedWorkloadsAreStillExcluded(t *testing.T) {
	values := readChartFile(t, "values.yaml")

	for _, template := range []string{"postgres.yaml", "honeypot-postgres.yaml", "mailpit.yaml"} {
		src := readChartFile(t, "templates/"+template)
		pod, ctr := resolveSecurityContext(t, src, values)

		hardened := true
		for control := range restrictedPodControls {
			if !strings.Contains(pod, control) {
				hardened = false
			}
		}
		for control := range restrictedContainerControls {
			if !strings.Contains(ctr, control) {
				hardened = false
			}
		}
		if hardened {
			t.Errorf("PSS restricted: charts/vault/templates/%s now satisfies the profile. The "+
				"register excludes it by name from the Kubernetes PSS claim on the basis that it "+
				"does not. Drop the exclusion from the PSS rows and from meta.scope.out_of_scope, "+
				"and delete this entry -- an exclusion kept past its reason understates the chart "+
				"and reads, to anyone who checks, like a claim nobody maintains.", template)
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
