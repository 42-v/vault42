// The breach check has to be reachable, not merely enabled.
//
// The chart shipped hibpCheck: true and a NetworkPolicy whose vault egress rules
// named PostgreSQL, Redis, DNS and SMTP and nothing else. api.pwnedpasswords.com
// is none of those, so in a default install every call to the HIBP API was
// dropped by the CNI. service.HIBPClient.IsBreached returns false when the API
// is unreachable, deliberately, because an HIBP outage must not stop a user
// changing their password — and a permanently unreachable API is
// indistinguishable from a permanent outage. The control was on in
// configuration, absent in fact, and silent about it: no error, no log, no
// difference an operator could observe.
//
// Nothing could catch that either. The switch is a Helm value, the reachability
// is a NetworkPolicy egress rule, the fail-open is a Go return statement, and no
// linter reads two of the three. This test does: it renders the chart and
// asserts that whenever the breach check is on, the policy lets the vault reach
// it, and that turning the rule off while leaving the check on is refused rather
// than shipped.
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

// netPolicy is the slice of a NetworkPolicy this gate reasons about.
type netPolicy struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		PodSelector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"podSelector"`
		Egress []struct {
			To []struct {
				IPBlock struct {
					CIDR string `yaml:"cidr"`
				} `yaml:"ipBlock"`
				PodSelector *struct {
					MatchLabels map[string]string `yaml:"matchLabels"`
				} `yaml:"podSelector"`
			} `yaml:"to"`
			Ports []struct {
				Port     int    `yaml:"port"`
				Protocol string `yaml:"protocol"`
			} `yaml:"ports"`
		} `yaml:"egress"`
	} `yaml:"spec"`
}

// renderChart runs `helm template` with extra --set arguments and returns the
// manifest stream.
func renderChart(t *testing.T, sets ...string) []byte {
	t.Helper()
	helm := requireTool(t, "helm",
		"the rendered NetworkPolicy cannot be produced and the breach-check egress rule goes unasserted")
	args := []string{
		"template", "release", chartDir, "--namespace", "vault",
		"--set", "adminGateway.tls.secretName=admin-tls",
	}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	cmd := exec.Command(helm, args...) // #nosec G204 -- fixed args over paths inside this repo
	cmd.Dir = repoRoot(t)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template %v failed: %v\n%s", sets, err, stderr.String())
	}
	return stdout.Bytes()
}

// vaultEgressAllows443 reports whether the vault pod's own NetworkPolicy carries
// an egress rule reaching TCP 443, and how many policies were examined. The
// count is returned so the caller can refuse to draw a conclusion from an empty
// render.
func vaultEgressAllows443(t *testing.T, manifests []byte) (allowed bool, policies int) {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(manifests))
	for {
		var doc netPolicy
		err := dec.Decode(&doc)
		if err != nil {
			break
		}
		// The vault's own policy, not the bridge's or the frontend's: a
		// podSelector is a subset match and the component label is what
		// separates them.
		if doc.Spec.PodSelector.MatchLabels["app.kubernetes.io/component"] != "vault" {
			continue
		}
		policies++
		for _, rule := range doc.Spec.Egress {
			for _, p := range rule.Ports {
				if p.Port == 443 && (p.Protocol == "" || p.Protocol == "TCP") {
					allowed = true
				}
			}
		}
	}
	return allowed, policies
}

func TestChartBreachCheckIsReachableWhereverItIsEnabled(t *testing.T) {
	// Chart defaults: hibpCheck is true and networkPolicy.enabled is true, which
	// is what an operator gets by typing nothing.
	allowed, policies := vaultEgressAllows443(t, renderChart(t))
	if policies < 1 {
		t.Fatal("the default render contains no NetworkPolicy selecting the vault component. " +
			"Either the chart stopped shipping one or this gate no longer recognizes it; " +
			"every assertion below would pass by finding nothing.")
	}
	if !allowed {
		t.Error("the default install sets hibpCheck: true and the vault's NetworkPolicy has no " +
			"egress rule reaching TCP 443, so api.pwnedpasswords.com is unreachable. " +
			"HIBPClient.IsBreached fails open when the API cannot be reached, so the breach " +
			"check is enabled in configuration and does nothing, without saying so. Add the " +
			"egress rule, or default hibpCheck to false so the configuration and the network " +
			"agree.")
	}

	// The combination an operator can still reach by hand. Turning the rule off
	// while leaving the check on rebuilds the exact defect, so the chart must
	// refuse rather than render it.
	allowed, policies = vaultEgressAllows443(t,
		renderChart(t, "networkPolicy.httpsEgress.enabled=false", "hibpCheck=true"))
	if policies < 1 {
		t.Fatal("no vault NetworkPolicy in the httpsEgress=false render")
	}
	if allowed {
		t.Error("networkPolicy.httpsEgress.enabled=false still renders an egress rule to 443; " +
			"the switch does not switch anything")
	}

	// And the honest combination: both off. This is the deployment that wants no
	// outbound HTTPS, and it must not be the one that quietly loses a control.
	allowed, _ = vaultEgressAllows443(t,
		renderChart(t, "networkPolicy.httpsEgress.enabled=false", "hibpCheck=false"))
	if allowed {
		t.Error("httpsEgress disabled but a 443 rule was rendered anyway")
	}

	// The value has to reach the container too, or "hibpCheck: false" is a
	// setting the process never sees.
	rendered := string(renderChart(t, "hibpCheck=false"))
	if !strings.Contains(rendered, `VAULT_HIBP_CHECK: "false"`) {
		t.Error("hibpCheck=false does not reach VAULT_HIBP_CHECK in the rendered ConfigMap, so " +
			"the operator's switch and the process's behavior are two different things")
	}
}
