// Chart wiring gate for the metrics listener.
//
// /metrics used to be a route on the public listener: unauthenticated, behind
// nothing, a readable count of every operation the vault had performed. The
// in-code comment said to fence it with a NetworkPolicy, which could never work
// as written -- a NetworkPolicy matches ports, not paths, so the only rule
// expressible was one that also allowed every request the vault exists to serve.
//
// It now binds a listener of its own, and that listener defaults to
// 127.0.0.1:9090: reachable from inside the pod and nowhere else. So the chart
// has to bind it to the pod IP for a scrape to arrive at all, and the chart is
// now the only thing deciding whether Prometheus can reach it.
//
// That makes a five-link chain, and every link is a name that has to match a
// name somewhere else: the Go constant, the env in the ConfigMap, the container
// port, the Service port, and the ServiceMonitor endpoint. Nothing in the build
// sees more than one of them at a time. The chart scraped port `http` for as
// long as it did precisely because no test read both ends.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// metricsPath is the route the metrics mux registers in internal/server.
const metricsPath = "/metrics"

// TestTheChartSetsTheEnvTheServerActuallyReads reads the env var's name out of
// the Go source rather than repeating it, so renaming the constant without
// touching the chart fails here instead of in a cluster.
func TestTheChartSetsTheEnvTheServerActuallyReads(t *testing.T) {
	src := readFileString(t, filepath.Join(repoRoot(t), "internal", "server", "server.go"))

	match := regexp.MustCompile(`metricsAddrEnv\s*=\s*"([^"]+)"`).FindStringSubmatch(src)
	if match == nil {
		t.Fatal("internal/server/server.go no longer declares metricsAddrEnv. The chart sets " +
			"an env var the server reads by that constant; if it moved, the chart is setting " +
			"a name nothing consumes and the metrics listener silently keeps its default.")
	}
	env := match[1]

	configmap := readFileString(t, filepath.Join(repoRoot(t), chartDir, "templates", "configmap.yaml"))
	if !strings.Contains(configmap, env+":") {
		t.Errorf("charts/vault/templates/configmap.yaml does not set %s. Without it the "+
			"listener keeps its own default, which is loopback, and every scrape from "+
			"Prometheus is refused at connect while the pod reports perfectly healthy.", env)
	}

	// The default is loopback on purpose. A chart that leaves it there ships a
	// scrape target nothing outside the pod can reach.
	defaultMatch := regexp.MustCompile(`defaultMetricsAddr\s*=\s*"([^"]+)"`).FindStringSubmatch(src)
	if defaultMatch != nil && strings.Contains(configmap, env+": \""+defaultMatch[1]+"\"") {
		t.Errorf("charts/vault/templates/configmap.yaml sets %s to the server's own default "+
			"%q, which binds loopback. Nothing outside the pod can reach that, so the "+
			"ServiceMonitor below resolves to a port that refuses every connection.",
			env, defaultMatch[1])
	}
}

// TestTheScrapeChainResolvesEndToEnd walks the rendered manifests the way
// Prometheus does: the ServiceMonitor names a Service port, the Service port
// targets a container port, and the container port is the one the env told the
// binary to bind.
func TestTheScrapeChainResolvesEndToEnd(t *testing.T) {
	docs := renderWithMetrics(t)

	monitor := docOfKind(t, docs, "ServiceMonitor")
	service := docOfKind(t, docs, "Service")
	deployment := docOfKind(t, docs, "Deployment")

	// 1. ServiceMonitor -> Service port name
	endpoints, _ := mapAt(monitor, "spec")["endpoints"].([]any)
	if len(endpoints) == 0 {
		t.Fatal("the ServiceMonitor renders no endpoints")
	}
	endpoint, _ := endpoints[0].(map[string]any)
	monitorPort, _ := endpoint["port"].(string)
	if path, _ := endpoint["path"].(string); path != metricsPath {
		t.Errorf("the ServiceMonitor scrapes path %q, want %q", path, metricsPath)
	}

	servicePorts, _ := mapAt(service, "spec")["ports"].([]any)
	var target any
	var publicPortName string
	for _, entry := range servicePorts {
		port, _ := entry.(map[string]any)
		name, _ := port["name"].(string)
		if name == monitorPort {
			target = port["targetPort"]
		}
		if name == "http" {
			publicPortName = name
		}
	}
	if target == nil {
		t.Fatalf("the ServiceMonitor scrapes Service port %q, which the Service does not "+
			"declare. Prometheus resolves an endpoint by port name, so this scrapes nothing.",
			monitorPort)
	}
	if monitorPort == publicPortName {
		t.Errorf("the ServiceMonitor scrapes the public port %q. %s is no longer a route on "+
			"the public listener: it moved to a listener of its own precisely because an "+
			"unauthenticated read of every counter in the process does not belong behind the "+
			"same door as the API.", publicPortName, metricsPath)
	}

	// 2. Service targetPort -> container port name
	pod := mapAt(mapAt(mapAt(deployment, "spec"), "template"), "spec")
	containers, _ := pod["containers"].([]any)
	container, _ := containers[0].(map[string]any)
	ports, _ := container["ports"].([]any)

	var containerPort int
	var found bool
	for _, entry := range ports {
		port, _ := entry.(map[string]any)
		if name, _ := port["name"].(string); name == target {
			containerPort, found = intAt(port, "containerPort")
		}
	}
	if !found {
		t.Fatalf("the Service targets container port %v, which the Deployment does not "+
			"declare. The scrape resolves to a port nothing is listening on.", target)
	}

	// 3. container port -> the address the env actually binds
	var addr string
	for _, doc := range docs {
		if kind, _ := doc["kind"].(string); kind != "ConfigMap" {
			continue
		}
		if value, ok := mapAt(doc, "data")["VAULT_METRICS_ADDR"].(string); ok {
			addr = value
		}
	}
	if addr == "" {
		t.Fatal("no rendered ConfigMap sets VAULT_METRICS_ADDR, so the listener binds its " +
			"own loopback default and the whole chain above reaches a closed port.")
	}
	if _, portText, ok := strings.Cut(addr, ":"); !ok || portText != itoa(containerPort) {
		t.Errorf("VAULT_METRICS_ADDR is %q but the container declares port %d. The binary "+
			"binds what the env says; the Service targets what the port says. When they "+
			"disagree the scrape fails and nothing else does.", addr, containerPort)
	}
	if strings.HasPrefix(addr, "127.0.0.1:") || strings.HasPrefix(addr, "localhost:") {
		t.Errorf("VAULT_METRICS_ADDR is %q, which binds loopback inside the pod. The "+
			"kubelet and Prometheus both connect to the pod IP.", addr)
	}
}

// The metrics rule and the peers it admits.
//
// The previous version of this gate asserted only that some rule mentions port
// 9090, and passed on a rule that fences nothing: the template emits `from` only
// under `{{- with .Values.metrics.networkPolicy.from }}`, and the shipped default
// is `from: []`, so the rendered rule carries ports and no peer list — which in
// NetworkPolicy semantics selects every source. A test named "is fenced by
// policy" that passes on an unfenced policy is worse than no test, because the
// name is what the next reader believes.
//
// So both postures are pinned, and neither is described as something it is not.
// The default is deliberate and documented in values.yaml; what must not happen
// is the configured peer list silently failing to reach the rendered rule.
func TestTheMetricsRuleCarriesTheConfiguredPeers(t *testing.T) {
	docs := renderWithMetrics(t,
		"--set-json", `metrics.networkPolicy.from=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"monitoring"}}}]`)

	rule := metricsIngressRule(t, docs)
	peers, ok := rule["from"].([]any)
	if !ok || len(peers) == 0 {
		t.Fatalf("metrics.networkPolicy.from was set and the rendered rule admits every source: %v", rule)
	}
	selector := mapAt(mapAt(peers[0].(map[string]any), "namespaceSelector"), "matchLabels")
	if got, _ := selector["kubernetes.io/metadata.name"].(string); got != "monitoring" {
		t.Errorf("the rendered peer selects namespace %q, want \"monitoring\"; the configured "+
			"peer list did not reach the rule", got)
	}
}

// The shipped default, stated rather than implied. metrics.enabled is false by
// default so nothing is exposed out of the box, but values-dev.yaml turns it on,
// and an operator who enables metrics without naming peers gets a port reachable
// from every pod the cluster lets connect. That is the documented trade in
// values.yaml; this pins that the rendered output really is that trade, so the
// day someone believes it is fenced, the belief is checkable.
func TestTheMetricsRuleWithNoPeersAdmitsEverySource(t *testing.T) {
	rule := metricsIngressRule(t, renderWithMetrics(t))

	if peers, ok := rule["from"]; ok {
		t.Errorf("the default render carries a peer list %v. If the chart now fences the metrics "+
			"port by default that is an improvement, but values.yaml and this test both describe "+
			"the opposite and must be updated together.", peers)
	}
}

// metricsIngressRule returns the vault NetworkPolicy ingress rule that admits the
// metrics port, failing when there is none. A missing rule means a policy in
// force drops every scrape — the mitigation that only became expressible once
// the port was distinct from the public one.
func metricsIngressRule(t *testing.T, docs []map[string]any) map[string]any {
	t.Helper()

	var policy map[string]any
	for _, doc := range docs {
		if kind, _ := doc["kind"].(string); kind != "NetworkPolicy" {
			continue
		}
		selector := mapAt(mapAt(mapAt(doc, "spec"), "podSelector"), "matchLabels")
		if component, _ := selector["app.kubernetes.io/component"].(string); component == "vault" {
			policy = doc
		}
	}
	if policy == nil {
		t.Fatal("no vault NetworkPolicy in the rendered output, although networkPolicy.enabled " +
			"was set for this render; the template stopped emitting it and this gate would " +
			"otherwise have skipped silently")
	}

	rules, _ := mapAt(policy, "spec")["ingress"].([]any)
	for _, entry := range rules {
		rule, _ := entry.(map[string]any)
		ports, _ := rule["ports"].([]any)
		for _, p := range ports {
			port, _ := p.(map[string]any)
			if got, ok := intAt(port, "port"); ok && got == 9090 {
				return rule
			}
		}
	}
	t.Fatal("the vault NetworkPolicy does not admit the metrics port, so with a policy " +
		"in force every scrape is dropped. This rule is the one the old in-code comment " +
		"asked for and could not have: while /metrics was a path on the public port, a " +
		"NetworkPolicy had no way to express it.")
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// renderWithMetrics renders the chart with metrics and the ServiceMonitor on,
// which is the configuration this whole chain exists for.
func renderWithMetrics(t *testing.T, extra ...string) []map[string]any {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH, so the rendered manifests cannot be produced. " +
			"Install helm, or add azure/setup-helm to the job, to run this gate.")
	}

	cmd := exec.Command(helm, // #nosec G204 -- fixed args over paths inside this repo
		"template", "release", chartDir,
		"--namespace", "vault",
		"--set", "metrics.enabled=true",
		"--set", "metrics.serviceMonitor.enabled=true",
		"--set", "networkPolicy.enabled=true",
	)
	cmd.Args = append(cmd.Args, extra...)
	cmd.Dir = repoRoot(t)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, stderr.String())
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

// docOfKind returns the first document of a kind that belongs to the vault
// component itself, skipping the bundled infrastructure that shares the kind.
func docOfKind(t *testing.T, docs []map[string]any, kind string) map[string]any {
	t.Helper()
	for _, doc := range docs {
		if got, _ := doc["kind"].(string); got != kind {
			continue
		}
		name, _ := mapAt(doc, "metadata")["name"].(string)
		if name == "release-vault-auth" {
			return doc
		}
	}
	t.Fatalf("no %s for the vault component in the rendered output", kind)
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
