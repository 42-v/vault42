// Chart wiring gate for the admin gateway's client revocation list.
//
// The gateway treats an unreadable ADMIN_GW_CLIENT_CRL_FILE as fatal on purpose:
// a gateway that comes up reporting revocation checking as configured, while
// checking nothing, is worse than one that refuses to start. The chart set that
// env var from a value and mounted no volume anywhere, so the one supported way
// to turn revocation on -- setting adminGateway.clientCRLFile -- shipped an
// admin plane that CrashLoopBackOffs on its first boot, every time, on a setting
// whose whole purpose is to harden it.
//
// Nothing could catch that from one side. The path is a string in YAML, the
// mount is a different block in the same YAML, and the fatality is a Go error
// return three files away.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// crlValues turns the revocation list on the way an operator now has to.
var crlValues = []string{
	"--set", "adminGateway.enabled=true",
	"--set", "adminGateway.hostNetwork=true",
	"--set", "adminGateway.tls.secretName=admin-tls",
	"--set", "adminGateway.clientCRL.secretName=admin-client-crl",
	"--set", "adminGateway.clientCRL.keys[0]=client.crl",
}

// TestTheChartMountsTheRevocationListItPointsAt walks the wiring the pod does:
// the env names a path, the path lies under a volumeMount, and the mount is
// backed by a volume with a source.
func TestTheChartMountsTheRevocationListItPointsAt(t *testing.T) {
	deployment := adminGatewayDeployment(t, renderAdminGateway(t, crlValues...))
	container := adminGatewayContainer(t, deployment)

	path := envValue(container, "ADMIN_GW_CLIENT_CRL_FILE")
	if path == "" {
		t.Fatal("the rendered admin-gateway container sets no ADMIN_GW_CLIENT_CRL_FILE even though " +
			"adminGateway.clientCRL names a source, so naming one turns nothing on")
	}

	mount := mountCovering(container, path)
	if mount == "" {
		t.Fatalf("ADMIN_GW_CLIENT_CRL_FILE is %q and no volumeMount covers it. The gateway treats an "+
			"unreadable CRL path as fatal, so this renders an admin plane that CrashLoopBackOffs on "+
			"first boot. Mounts present: %v", path, mountPaths(container))
	}
	if !volumeHasSource(t, deployment, mount) {
		t.Fatalf("volume %q backs the CRL mount but names no secret or configMap, so the path is an "+
			"empty directory and the gateway still dies at boot", mount)
	}
}

// TestTheChartRefusesACRLPathWithNothingMountedAtIt pins the other half.
//
// adminGateway.clientCRLFile was the only setting that ever turned revocation
// on, and it mounted nothing. Rendering has to stop and say what to set instead,
// because the alternative is a chart that installs cleanly and a pod that never
// starts.
func TestTheChartRefusesACRLPathWithNothingMountedAtIt(t *testing.T) {
	_, stderr, err := helmTemplate(t,
		"--set", "adminGateway.enabled=true",
		"--set", "adminGateway.hostNetwork=true",
		"--set", "adminGateway.tls.secretName=admin-tls",
		"--set", "adminGateway.clientCRLFile=/run/crl/client.crl",
	)
	if err == nil {
		t.Fatal("helm rendered a deployment with ADMIN_GW_CLIENT_CRL_FILE set and no volume mounted " +
			"at it. That install is an admin plane that CrashLoopBackOffs on first boot, and the " +
			"operator finds out from the pod rather than from the render.")
	}
	for _, want := range []string{"adminGateway.clientCRL", "secretName"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the render failure does not mention %q, so it does not say what to set instead:\n%s",
				want, stderr)
		}
	}
}

// TestTheChartRefusesTwoCRLSources keeps the mount unambiguous. A Secret and a
// ConfigMap cannot both be the one volume, and silently preferring one is how an
// operator ends up debugging a CRL they are certain they replaced.
func TestTheChartRefusesTwoCRLSources(t *testing.T) {
	_, stderr, err := helmTemplate(t, append(crlValues,
		"--set", "adminGateway.clientCRL.configMapName=admin-client-crl")...)
	if err == nil {
		t.Fatal("helm rendered a deployment naming both a Secret and a ConfigMap as the CRL source")
	}
	if !strings.Contains(stderr, "configMapName") {
		t.Errorf("the render failure does not name the conflicting settings:\n%s", stderr)
	}
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// helmTemplate renders the chart and returns stdout, stderr and the exit error,
// so a test can assert on a render that is meant to fail.
func helmTemplate(t *testing.T, extra ...string) (string, string, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not on PATH, so the rendered manifests cannot be produced. " +
			"Install helm, or add azure/setup-helm to the job, to run this gate.")
	}

	cmd := exec.Command(helm, "template", "release", chartDir, "--namespace", "vault") // #nosec G204 -- fixed args over paths inside this repo
	cmd.Args = append(cmd.Args, extra...)
	cmd.Dir = repoRoot(t)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	return stdout.String(), stderr.String(), runErr
}

func renderAdminGateway(t *testing.T, extra ...string) []map[string]any {
	t.Helper()
	stdout, stderr, err := helmTemplate(t, extra...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, stderr)
	}

	var docs []map[string]any
	decoder := yaml.NewDecoder(strings.NewReader(stdout))
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

func adminGatewayDeployment(t *testing.T, docs []map[string]any) map[string]any {
	t.Helper()
	for _, doc := range docs {
		if kind, _ := doc["kind"].(string); kind != "Deployment" {
			continue
		}
		if name, _ := mapAt(doc, "metadata")["name"].(string); strings.HasSuffix(name, "-admin-gateway") {
			return doc
		}
	}
	t.Fatal("no admin-gateway Deployment in the rendered output")
	return nil
}

func adminGatewayContainer(t *testing.T, deployment map[string]any) map[string]any {
	t.Helper()
	spec := mapAt(mapAt(mapAt(deployment, "spec"), "template"), "spec")
	containers, _ := spec["containers"].([]any)
	for _, raw := range containers {
		c, _ := raw.(map[string]any)
		if name, _ := c["name"].(string); name == "admin-gateway" {
			return c
		}
	}
	t.Fatal("the admin-gateway Deployment renders no container named admin-gateway")
	return nil
}

func envValue(container map[string]any, name string) string {
	env, _ := container["env"].([]any)
	for _, raw := range env {
		e, _ := raw.(map[string]any)
		if got, _ := e["name"].(string); got == name {
			value, _ := e["value"].(string)
			return value
		}
	}
	return ""
}

// mountCovering returns the name of the volume mounted at a directory that
// contains every path in the comma-separated setting, or "" when one of them is
// uncovered. ADMIN_GW_CLIENT_CRL_FILE takes one path per CA, and a single
// unmounted path is enough to make the boot fatal.
func mountCovering(container map[string]any, paths string) string {
	var name string
	for _, one := range strings.Split(paths, ",") {
		covering := ""
		for _, mount := range volumeMounts(container) {
			at, _ := mount["mountPath"].(string)
			if at != "" && strings.HasPrefix(one, strings.TrimSuffix(at, "/")+"/") {
				covering, _ = mount["name"].(string)
			}
		}
		if covering == "" {
			return ""
		}
		name = covering
	}
	return name
}

func volumeMounts(container map[string]any) []map[string]any {
	raw, _ := container["volumeMounts"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		if mount, ok := entry.(map[string]any); ok {
			out = append(out, mount)
		}
	}
	return out
}

func mountPaths(container map[string]any) []string {
	var out []string
	for _, mount := range volumeMounts(container) {
		if at, _ := mount["mountPath"].(string); at != "" {
			out = append(out, at)
		}
	}
	return out
}

func volumeHasSource(t *testing.T, deployment map[string]any, name string) bool {
	t.Helper()
	spec := mapAt(mapAt(mapAt(deployment, "spec"), "template"), "spec")
	volumes, _ := spec["volumes"].([]any)
	for _, raw := range volumes {
		v, _ := raw.(map[string]any)
		if got, _ := v["name"].(string); got != name {
			continue
		}
		if secret := mapAt(v, "secret"); secret["secretName"] != nil {
			return true
		}
		if cm := mapAt(v, "configMap"); cm["name"] != nil {
			return true
		}
		return false
	}
	t.Fatalf("the admin-gateway Deployment mounts volume %q but declares no such volume", name)
	return false
}
