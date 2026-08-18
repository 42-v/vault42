// Restricted-PSS gate over every workload the chart renders.
//
// This file used to check one pod. The frontend was the image that ran as root
// on a writable root filesystem while every other image was distroless and
// nonroot, it was fixed, and a test was written to hold the fix. It held that
// fix and nothing else: at the same time honeypot-postgres had no
// securityContext at all, postgres ran as root, mailpit ran unconfined off a
// floating tag, and redis named a group its process is not in. Four findings an
// audit had to find by hand, in workloads a one-workload test could not see.
//
// So the shape changed. Every workload in the rendered output of every shipped
// values profile is enumerated and checked against the Kubernetes Pod Security
// Standards "restricted" profile, so the next component added to this chart
// fails CI unless it arrives confined. Failures name the values file, the
// workload and the property, because "the chart is not hardened" is not
// something anyone can act on.
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

// ---------------------------------------------------------------------------
// The chart half: rendered manifests
// ---------------------------------------------------------------------------

// valuesProfiles are the value files a `helm template` has to be run with to see
// everything this chart can render. The empty string is the chart's own
// defaults, which is the profile an operator gets by typing nothing.
var valuesProfiles = []string{
	"",
	"values-dev.yaml",
	"values-local.yaml",
	"values-embedded.yaml",
	"values-honeypot.yaml",
	"values-bridge.yaml",
}

// workloadKinds are the kinds that carry a pod template. A kind missing from
// here is a kind this gate does not see, which is why it is checked against the
// rendered output rather than assumed: workloadsIn fails on a document that
// holds a pod template under a kind not named here.
var workloadKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"ReplicaSet":  true,
	"Job":         true,
	"CronJob":     true,
}

// workload is one pod template pulled out of a rendered manifest, with enough
// identity attached to name it in a failure.
type workload struct {
	profile string
	kind    string
	name    string
	spec    map[string]any // .spec.template.spec
}

func (w workload) String() string {
	return fmt.Sprintf("%s: %s/%s", profileName(w.profile), w.kind, w.name)
}

// TestEveryRenderedWorkloadRunsAsNonRoot is the pod-level half of the profile.
//
// runAsNonRoot alone is not enough. The kubelet honors it by refusing to start
// an image whose user resolves to 0, so an image with a nonroot USER passes it
// while still running as whatever uid that image chose. The uid and gid have to
// be named for the pod to be reproducible, and fsGroup has to match the gid or
// the process cannot write the volume mounted for it -- which is exactly how
// this chart came to carry fsGroup 999 against an image that is uid/gid 70.
func TestEveryRenderedWorkloadRunsAsNonRoot(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		sc := mapAt(w.spec, "securityContext")
		if sc == nil {
			t.Errorf("%s has no pod securityContext. It runs as whatever user its "+
				"image declares, with no seccomp profile, and cannot be admitted to a "+
				"namespace enforcing the restricted Pod Security Standards profile.", w)
			continue
		}

		if sc["runAsNonRoot"] != true {
			t.Errorf("%s does not set runAsNonRoot: true. The kubelet will start the "+
				"pod even where the image resolves to uid 0.", w)
		}
		for _, key := range []string{"runAsUser", "runAsGroup"} {
			id, ok := intAt(sc, key)
			switch {
			case !ok:
				t.Errorf("%s does not set %s. Without it the pod runs as whatever the "+
					"image happens to declare, and a rebuilt image changes that silently.", w, key)
			case id == 0:
				t.Errorf("%s sets %s: 0, which is root.", w, key)
			}
		}
		if gid, ok := intAt(sc, "runAsGroup"); ok {
			fsGroup, set := intAt(sc, "fsGroup")
			switch {
			case !set:
				t.Errorf("%s sets runAsGroup: %d but no fsGroup. Any volume it mounts "+
					"stays owned by the group the volume was created with.", w, gid)
			case fsGroup != gid:
				t.Errorf("%s sets runAsGroup: %d and fsGroup: %d. The process is not in "+
					"the group that owns its volumes, so writes to them fail at runtime "+
					"with an error that reads like a broken volume.", w, gid, fsGroup)
			}
		}
		if got := seccompType(sc); got != "RuntimeDefault" {
			t.Errorf("%s has pod seccompProfile.type = %q, want %q. Unconfined means "+
				"every syscall in the kernel is reachable from the container.",
				w, got, "RuntimeDefault")
		}
	}
}

// TestEveryRenderedContainerIsConfined is the container-level half.
//
// Each property is checked at its effective value: a container securityContext
// overrides the pod one, so a pod that looks right with a container quietly
// relaxing it is the case this has to catch.
func TestEveryRenderedContainerIsConfined(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		pod := mapAt(w.spec, "securityContext")
		for _, c := range containersOf(t, w) {
			sc := mapAt(c.spec, "securityContext")
			if sc == nil {
				t.Errorf("%s container %q has no securityContext.", w, c.name)
				continue
			}

			if effective(sc, pod, "allowPrivilegeEscalation") != false {
				t.Errorf("%s container %q does not resolve allowPrivilegeEscalation to "+
					"false. A setuid binary anywhere in the image regains what runAsUser "+
					"dropped.", w, c.name)
			}
			if effective(sc, pod, "privileged") == true {
				t.Errorf("%s container %q is privileged.", w, c.name)
			}
			if effective(sc, pod, "readOnlyRootFilesystem") != true {
				t.Errorf("%s container %q does not resolve readOnlyRootFilesystem to "+
					"true. A compromised process can write anywhere in its own image, "+
					"including over the binary it is running. Where a process genuinely "+
					"writes to a path, mount an emptyDir on that path rather than "+
					"relaxing this.", w, c.name)
			}
			if effective(sc, pod, "runAsNonRoot") != true {
				t.Errorf("%s container %q does not resolve runAsNonRoot to true.", w, c.name)
			}
			if got := seccompTypeEffective(sc, pod); got != "RuntimeDefault" {
				t.Errorf("%s container %q resolves seccompProfile.type to %q, want %q.",
					w, c.name, got, "RuntimeDefault")
			}
			if !dropsAllCapabilities(sc) {
				t.Errorf("%s container %q does not drop ALL capabilities. Capabilities "+
					"are not inherited from the pod securityContext, so this has to be set "+
					"on the container and nowhere else.", w, c.name)
			}
			if added := capabilitiesAddedBack(sc); len(added) > 0 {
				t.Errorf("%s container %q adds %v back after dropping ALL. The restricted "+
					"profile permits exactly one, NET_BIND_SERVICE, and nothing in this chart "+
					"binds a privileged port. drop: [ALL] followed by an add is not a "+
					"confined container; it is the capability set someone chose.",
					w, c.name, added)
			}
		}
	}
}

// TestNoRenderedWorkloadUsesTheHostNamespaces keeps the chart's default posture
// admissible.
//
// hostNetwork was the shipped default for the admin gateway. Both the baseline
// and the restricted profiles forbid it, so a namespace enforcing either
// rejected the pod, and the operator who found that out found it out as a
// rejection with no hint of the cause. It is still reachable -- it is the
// strongest posture for a local-only admin plane -- but only by asking for it.
func TestNoRenderedWorkloadUsesTheHostNamespaces(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		for _, key := range []string{"hostNetwork", "hostPID", "hostIPC"} {
			if w.spec[key] == true {
				t.Errorf("%s sets %s: true in a shipped values profile. Both the baseline "+
					"and the restricted Pod Security Standards profiles forbid it, so the "+
					"profile cannot be installed into an enforcing namespace. It has to be "+
					"something a deployment opts in to, never a default.", w, key)
			}
		}
	}
}

// TestEveryRenderedWorkloadDeclinesItsServiceAccountToken checks the credential
// nothing in this chart needs.
//
// No workload here calls the Kubernetes API. A mounted token is a credential
// sitting in a container for no reason, and cloudflared -- the pod holding the
// tunnel credential -- was mounting one.
func TestEveryRenderedWorkloadDeclinesItsServiceAccountToken(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		if w.spec["automountServiceAccountToken"] != false {
			t.Errorf("%s does not set automountServiceAccountToken: false. Nothing in "+
				"this chart calls the Kubernetes API, so the token is a credential left "+
				"in the container for whatever gets into it.", w)
		}
		if _, ok := w.spec["serviceAccountName"].(string); !ok {
			t.Errorf("%s names no serviceAccountName, so it runs under the namespace's "+
				"`default` ServiceAccount along with everything else that did the same.", w)
		}
	}
}

// TestEveryRenderedContainerIsBounded checks resources.
//
// A container with no requests is scheduled best-effort and is the first thing
// evicted when a node runs short; a container with no memory limit can take the
// node down with it. Both are how a workload with no bounds becomes everyone
// else's problem.
func TestEveryRenderedContainerIsBounded(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		for _, c := range containersOf(t, w) {
			resources := mapAt(c.spec, "resources")
			requests := mapAt(resources, "requests")
			limits := mapAt(resources, "limits")

			for _, r := range []string{"cpu", "memory"} {
				if _, ok := requests[r]; !ok {
					t.Errorf("%s container %q has no resources.requests.%s. The pod is "+
						"scheduled best-effort and evicted first under node pressure.",
						w, c.name, r)
				}
			}
			if _, ok := limits["memory"]; !ok {
				t.Errorf("%s container %q has no resources.limits.memory. A leak in it "+
					"takes down the node rather than the pod.", w, c.name)
			}
		}
	}
}

// TestEveryRenderedContainerIsProbed checks that Kubernetes can tell whether the
// process is alive and whether it is ready to be sent traffic.
//
// A container with no readiness probe receives traffic the moment its process
// starts, which for anything that migrates a schema on boot is before it can
// serve. A container with no liveness probe is restarted only when it exits.
func TestEveryRenderedContainerIsProbed(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		// A Job's pod runs to completion: readiness has nothing to gate and
		// liveness would restart work that is finishing normally.
		if w.kind == "Job" || w.kind == "CronJob" {
			continue
		}
		for _, c := range containersOf(t, w) {
			for _, probe := range []string{"readinessProbe", "livenessProbe"} {
				if mapAt(c.spec, probe) == nil {
					t.Errorf("%s container %q has no %s.", w, c.name, probe)
				}
			}
		}
	}
}

// TestNoRenderedImageFloats catches a mutable tag anywhere in the chart.
//
// mailpit shipped on :latest, so a rebuilt image replaced a running pod on any
// restart with nothing recording which build had been running before.
func TestNoRenderedImageFloats(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		for _, c := range containersOf(t, w) {
			image, _ := c.spec["image"].(string)
			if strings.Contains(image, "@sha256:") {
				continue // pinned to bytes; nothing can move underneath it
			}
			ref := image
			if i := strings.LastIndex(ref, "/"); i >= 0 {
				ref = ref[i+1:]
			}
			if strings.HasSuffix(ref, ":latest") || !strings.Contains(ref, ":") {
				t.Errorf("%s container %q uses image %q, whose tag the registry can move "+
					"underneath a running pod. Pin a version, and a digest as well where "+
					"the image is not built from this repository.", w, c.name, image)
			}
		}
	}
}

// TestTheHoneypotHoldsNoProductionCredential is the boundary the honeypot exists
// to create.
//
// The honeypot mounted the release Secret -- the production master key, HMAC
// secret, pepper, signing key, admin token and database passwords -- into the one
// component of this deployment that is advertised to attackers and meant to be
// broken into. Reaching the decoy was reaching the vault, while the docs called
// the honeypot isolated.
//
// The check is on the rendered manifest rather than the template, because the
// name is assembled from a helper and an override and it is the resolved value
// that decides what the kubelet mounts.
func TestTheHoneypotHoldsNoProductionCredential(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		if !strings.Contains(w.name, "honeypot") {
			continue
		}
		for _, name := range secretsReferencedBy(w) {
			if !strings.Contains(name, "honeypot") {
				t.Errorf("%s mounts Secret %q, which is not a honeypot Secret. The "+
					"honeypot is the component this deployment invites attackers into: "+
					"whatever it holds is what breaking the decoy yields. Give it its own "+
					"credentials via honeypotInstance.secrets.existingSecret.", w, name)
			}
		}
	}
}

// TestTheProductionWorkloadsHoldNoHoneypotCredential is the same boundary from
// the other side: a honeypot credential reaching production would mean the
// honeypot's keys unlock something real.
func TestTheProductionWorkloadsHoldNoHoneypotCredential(t *testing.T) {
	for _, w := range renderedWorkloads(t) {
		if strings.Contains(w.name, "honeypot") {
			continue
		}
		for _, name := range secretsReferencedBy(w) {
			if strings.Contains(name, "honeypot") {
				t.Errorf("%s mounts the honeypot Secret %q.", w, name)
			}
		}
	}
}

// secretsReferencedBy collects every Secret a workload reads, through a volume or
// through a secretKeyRef.
func secretsReferencedBy(w workload) []string {
	seen := map[string]bool{}
	volumes, _ := w.spec["volumes"].([]any)
	for _, entry := range volumes {
		volume, _ := entry.(map[string]any)
		if name, ok := mapAt(volume, "secret")["secretName"].(string); ok {
			seen[name] = true
		}
	}
	for _, key := range []string{"initContainers", "containers"} {
		list, _ := w.spec[key].([]any)
		for _, entry := range list {
			c, _ := entry.(map[string]any)
			env, _ := c["env"].([]any)
			for _, e := range env {
				item, _ := e.(map[string]any)
				ref := mapAt(mapAt(item, "valueFrom"), "secretKeyRef")
				if name, ok := ref["name"].(string); ok {
					seen[name] = true
				}
			}
			froms, _ := c["envFrom"].([]any)
			for _, f := range froms {
				item, _ := f.(map[string]any)
				if name, ok := mapAt(item, "secretRef")["name"].(string); ok {
					seen[name] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// The template half: no helm binary required
// ---------------------------------------------------------------------------

// sanctionedPodSecurityContextSources are the two ways a pod template in this
// chart may get a securityContext: the helper, or the values the product
// workloads expose for operators to tune.
var sanctionedPodSecurityContextSources = []string{
	`include "vault.podSecurityContext"`,
	".Values.podSecurityContext",
}

// sanctionedContainerSecurityContextSources are the same two for containers.
var sanctionedContainerSecurityContextSources = []string{
	`include "vault.containerSecurityContext"`,
	".Values.securityContext",
}

// chartWorkloadTemplates is the number of template files that currently render a
// pod. It exists so a refactor that stops the detection below from matching
// fails here instead of passing having checked nothing.
const chartWorkloadTemplates = 8

// TestEveryPodTemplateTakesItsSecurityContextFromOneOfTwoPlaces is the gate that
// survives a runner with no helm on it.
//
// The rendered checks above are the stronger ones, and they skip where helm is
// absent. This reads the templates as text instead, so a new workload that
// hand-rolls a securityContext -- or ships without one, which is how
// honeypot-postgres arrived -- fails either way.
func TestEveryPodTemplateTakesItsSecurityContextFromOneOfTwoPlaces(t *testing.T) {
	dir := filepath.Join(repoRoot(t), chartDir, "templates")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	var checked int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		src := readFileString(t, filepath.Join(dir, e.Name()))
		// "containers:" at pod-template indentation is what marks a file as
		// carrying a workload. Nothing else in this chart has it.
		if !strings.Contains(src, "\n      containers:") {
			continue
		}
		checked++

		if !containsAny(src, sanctionedPodSecurityContextSources) {
			t.Errorf("charts/vault/templates/%s renders a pod template whose "+
				"securityContext comes from neither %q nor %q. Those are the two "+
				"definitions of the restricted profile in this chart; a third one "+
				"written inline is a third thing to keep correct, and it is the one "+
				"that gets forgotten.", e.Name(),
				sanctionedPodSecurityContextSources[0], sanctionedPodSecurityContextSources[1])
		}
		if !containsAny(src, sanctionedContainerSecurityContextSources) {
			t.Errorf("charts/vault/templates/%s renders a container whose "+
				"securityContext comes from neither %q nor %q. capabilities and "+
				"readOnlyRootFilesystem are container-level settings: no pod "+
				"securityContext supplies them.", e.Name(),
				sanctionedContainerSecurityContextSources[0],
				sanctionedContainerSecurityContextSources[1])
		}
	}

	if checked < chartWorkloadTemplates {
		t.Errorf("found pod templates in only %d chart files, expected at least %d, so "+
			"the detection above has stopped matching the workloads it is meant to check",
			checked, chartWorkloadTemplates)
	}
}

// ---------------------------------------------------------------------------
// The frontend image, which the chart cannot fix from its own side
// ---------------------------------------------------------------------------

// TestTheFrontendImageDoesNotRunAsRoot reads the Dockerfile, because the
// securityContext can only refuse to start a container that was built to need
// root. Both halves have to hold.
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

// TestTheFrontendKeepsItsWritablePaths pins the mounts a read-only root needs.
//
// Drop one and the pod crashes on startup, which reads as
// "readOnlyRootFilesystem broke it" and invites removing the wrong line.
// Matched as a whole mountPath value rather than as a substring: "/tmp" is a
// prefix of every path under it, so a Contains check stays green when the mount
// is renamed to "/tmpX", which is precisely the edit this must catch.
func TestTheFrontendKeepsItsWritablePaths(t *testing.T) {
	src := readFileString(t, filepath.Join(repoRoot(t), chartDir, "templates", "frontend.yaml"))

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
// A frontend on `latest` means two pods in the same release can serve different
// builds, a rollback does not roll the frontend back, and the version an
// incident is reconstructed against is whatever the registry happened to hold.
func TestTheFrontendImageTagIsPinnedToTheChart(t *testing.T) {
	src := readFileString(t, filepath.Join(repoRoot(t), chartDir, "templates", "frontend.yaml"))

	if !strings.Contains(src, ".Chart.AppVersion") {
		t.Error("charts/vault/templates/frontend.yaml no longer falls back to .Chart.AppVersion " +
			"for the image tag. An unset frontend.image.tag then renders an unpinned reference.")
	}
	if strings.Contains(src, ":latest") {
		t.Error("charts/vault/templates/frontend.yaml pins the frontend to :latest")
	}
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// renderedCache holds the rendered workloads for the lifetime of the test
// binary, so six `helm template` runs serve every test in this file.
var renderedCache []workload

func renderedWorkloads(t *testing.T) []workload {
	t.Helper()
	if renderedCache != nil {
		return renderedCache
	}
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH, so the rendered manifests cannot be produced. " +
			"TestEveryPodTemplateTakesItsSecurityContextFromOneOfTwoPlaces covers the " +
			"same ground from the templates; install helm, or add azure/setup-helm to " +
			"the job, to run the full gate.")
	}

	root := repoRoot(t)
	var all []workload
	for _, profile := range valuesProfiles {
		args := []string{
			"template", "release", chartDir,
			"--namespace", "vault",
			// Required whenever the admin gateway is enabled, and rendering has
			// to reach the gateway for this gate to see it.
			"--set", "adminGateway.tls.secretName=admin-tls",
		}
		if profile != "" {
			args = append(args, "-f", filepath.Join(chartDir, profile))
		}

		cmd := exec.Command(helm, args...) // #nosec G204 -- fixed args over paths inside this repo
		cmd.Dir = root
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("helm template with %s failed: %v\n%s", profileName(profile), err, stderr.String())
		}
		all = append(all, workloadsIn(t, profile, stdout.Bytes())...)
	}

	if len(all) == 0 {
		t.Fatal("no workloads found in any rendered profile, so this gate would pass " +
			"on an empty chart")
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].profile != all[j].profile {
			return all[i].profile < all[j].profile
		}
		return all[i].name < all[j].name
	})
	renderedCache = all
	return all
}

func profileName(profile string) string {
	if profile == "" {
		return "values.yaml (chart defaults)"
	}
	return profile
}

// workloadsIn pulls the pod templates out of one rendered manifest stream.
func workloadsIn(t *testing.T, profile string, manifest []byte) []workload {
	t.Helper()
	var out []workload

	decoder := yaml.NewDecoder(bytes.NewReader(manifest))
	for {
		var doc map[string]any
		if err := decoder.Decode(&doc); err != nil {
			break
		}
		if doc == nil {
			continue
		}
		kind, _ := doc["kind"].(string)
		name := "<unnamed>"
		if n, ok := mapAt(doc, "metadata")["name"].(string); ok {
			name = n
		}

		podSpec := mapAt(mapAt(mapAt(doc, "spec"), "template"), "spec")
		if podSpec == nil {
			// A CronJob nests one level deeper. Anything else without a pod
			// template is a Service, a ConfigMap or a policy object.
			podSpec = mapAt(mapAt(mapAt(mapAt(mapAt(doc, "spec"), "jobTemplate"), "spec"), "template"), "spec")
		}
		if podSpec == nil {
			continue
		}
		if !workloadKinds[kind] {
			t.Errorf("%s: %s/%s carries a pod template under a kind this gate does not "+
				"enumerate. Add %q to workloadKinds, or it ships unchecked.",
				profileName(profile), kind, name, kind)
			continue
		}
		out = append(out, workload{profile: profile, kind: kind, name: name, spec: podSpec})
	}
	return out
}

// container is one entry of .containers or .initContainers.
type container struct {
	name string
	spec map[string]any
}

func containersOf(t *testing.T, w workload) []container {
	t.Helper()
	var out []container
	for _, key := range []string{"initContainers", "containers"} {
		list, _ := w.spec[key].([]any)
		for i, entry := range list {
			spec, ok := entry.(map[string]any)
			if !ok {
				t.Errorf("%s has a malformed %s[%d]", w, key, i)
				continue
			}
			name, _ := spec["name"].(string)
			if name == "" {
				name = fmt.Sprintf("%s[%d]", key, i)
			}
			out = append(out, container{name: name, spec: spec})
		}
	}
	if len(out) == 0 {
		t.Errorf("%s renders no containers", w)
	}
	return out
}

// ---------------------------------------------------------------------------
// Reading rendered YAML
// ---------------------------------------------------------------------------

// mapAt returns the nested map at key, or nil. It never panics on a missing or
// wrongly typed level, so callers can chain it.
func mapAt(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	nested, _ := m[key].(map[string]any)
	return nested
}

// intAt reads an integer field, tolerating the several numeric types a YAML
// decoder can hand back.
func intAt(m map[string]any, key string) (int, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[key].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// effective resolves a value the way the kubelet does: the container's own where
// it sets one, the pod's otherwise.
func effective(containerSC, podSC map[string]any, key string) any {
	if containerSC != nil {
		if v, ok := containerSC[key]; ok {
			return v
		}
	}
	if podSC != nil {
		if v, ok := podSC[key]; ok {
			return v
		}
	}
	return nil
}

func seccompType(sc map[string]any) string {
	name, _ := mapAt(sc, "seccompProfile")["type"].(string)
	if name == "" {
		return "<unset>"
	}
	return name
}

func seccompTypeEffective(containerSC, podSC map[string]any) string {
	if got := seccompType(containerSC); got != "<unset>" {
		return got
	}
	return seccompType(podSC)
}

// dropsAllCapabilities checks the container drops every capability. Capabilities
// are not inherited from the pod securityContext, so only the container's own
// value counts.
func dropsAllCapabilities(containerSC map[string]any) bool {
	drop, _ := mapAt(containerSC, "capabilities")["drop"].([]any)
	for _, entry := range drop {
		if name, _ := entry.(string); strings.EqualFold(name, "ALL") {
			return true
		}
	}
	return false
}

// capabilitiesAddedBack returns every capability the container asks for beyond
// the one the restricted profile permits.
//
// Dropping ALL and adding one back is a single securityContext away, and until
// 1.0.0 nothing saw it: putting `capabilities: {drop: [ALL], add: [SYS_ADMIN]}`
// into the chart's default container securityContext left this suite green and
// the compliance suite green, because the compliance scan reads
// charts/vault/templates/ and the container securityContext lives in
// values.yaml. Every rendered container in a default install would have carried
// CAP_SYS_ADMIN.
func capabilitiesAddedBack(containerSC map[string]any) []string {
	add, _ := mapAt(containerSC, "capabilities")["add"].([]any)
	beyond := make([]string, 0, len(add))
	for _, entry := range add {
		name, _ := entry.(string)
		if strings.EqualFold(name, "NET_BIND_SERVICE") {
			continue
		}
		beyond = append(beyond, name)
	}
	return beyond
}

func containsAny(src string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(src, n) {
			return true
		}
	}
	return false
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
