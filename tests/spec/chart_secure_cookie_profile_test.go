// Secure-cookie gate on the shipped values profiles.
//
// The refresh cookie is named __Host-refresh_token. The __Host- prefix is not
// decoration: a browser rejects a cookie carrying it unless the Set-Cookie also
// carries Secure, so a deployment that serves the cookie without Secure has no
// refresh at all. Every login works, every access token expires, and the session
// ends fifteen minutes later with nothing in the server logs, because the server
// did what it was asked and the browser threw the result away.
//
// charts/vault/values.yaml shipped tls.enabled=false with forceSecureCookies
// =false under profile=production, which is exactly that combination. It did not
// reach a browser only because Config.Validate refuses to start on it, turning
// the defect into a CrashLoopBackOff whose cause is one line deep in the pod
// logs. Both are release blockers and they have one cause, so the gate is on the
// values rather than on either symptom.
//
// helm lint and a rendering check both pass on the broken combination: it is
// well-formed YAML that produces a well-formed Deployment. The contradiction is
// between a value in a chart and a string constant in Go.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// chartDir is the one chart in the repo. Every path below hangs off it.
var chartDir = filepath.Join("charts", "vault")

// devProfile is the only profile Config.Validate lets serve plaintext with
// non-Secure cookies, because it returns before the TLS checks. Every other
// profile reaches them.
const devProfile = "dev"

// TestTheRefreshCookieStillCarriesTheHostPrefix pins the premise. If the cookie
// is ever renamed without the prefix, the Secure requirement below stops being a
// browser rule and becomes an opinion, and this gate should be revisited rather
// than left asserting something no longer true.
func TestTheRefreshCookieStillCarriesTheHostPrefix(t *testing.T) {
	path := filepath.Join(repoRoot(t), "internal", "handler", "auth.go")
	src := readFileString(t, path)
	if !strings.Contains(src, `refreshTokenCookie = "__Host-refresh_token"`) {
		t.Fatalf("%s no longer declares refreshTokenCookie as \"__Host-refresh_token\". "+
			"The values gate below exists because a browser discards a __Host- cookie sent "+
			"without Secure; if the name changed, decide what the new rule is before "+
			"relaxing the chart.", path)
	}
}

// TestEveryShippedValuesProfileServesSecureCookies walks the profiles an
// operator installs with -f and holds each to the rule the cookie name imposes.
func TestEveryShippedValuesProfileServesSecureCookies(t *testing.T) {
	root := repoRoot(t)
	base := loadValues(t, filepath.Join(root, chartDir, "values.yaml"))

	for _, name := range shippedValuesFiles(t, root) {
		t.Run(name, func(t *testing.T) {
			overlay := base
			if name != "values.yaml" {
				overlay = loadValues(t, filepath.Join(root, chartDir, name))
			}

			profile := resolveString(overlay, base, "profile")
			if profile == devProfile {
				// Dev is exempt in Config.Validate for the same reason it is
				// exempt here, and values-dev.yaml serves real TLS anyway.
				return
			}
			tlsOn := resolveBool(overlay, base, "tls", "enabled")
			forceSecure := resolveBool(overlay, base, "forceSecureCookies")
			if tlsOn || forceSecure {
				return
			}
			t.Errorf("%s/%s installs profile %q with tls.enabled=false and "+
				"forceSecureCookies=false. The refresh cookie is __Host-refresh_token, which a "+
				"browser discards unless it arrives with Secure, so refresh is dead for every "+
				"user of this profile; Config.Validate refuses to start on the same pair, so in "+
				"practice the release CrashLoopBackOffs instead. Set forceSecureCookies: true "+
				"when TLS terminates at an ingress or a tunnel, or tls.enabled: true with "+
				"tls.certFile and tls.keyFile to terminate it in the pod.",
				chartDir, name, profile)
		})
	}
}

// TestTheChartRefusesToRenderNonSecureCookiesOutsideDev keeps the render-time
// guard in place. Without it, an operator's own overlay can reach the same
// combination the shipped profiles are now held away from, and the first sign of
// it is a restarting pod rather than a failed install.
func TestTheChartRefusesToRenderNonSecureCookiesOutsideDev(t *testing.T) {
	path := filepath.Join(repoRoot(t), chartDir, "templates", "configmap.yaml")
	src := readFileString(t, path)

	guard := ""
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "fail") && strings.Contains(line, "forceSecureCookies") {
			guard = line
			break
		}
	}
	if guard == "" {
		t.Fatalf("%s/templates/configmap.yaml has no fail guard on forceSecureCookies. "+
			"An overlay that sets tls.enabled and forceSecureCookies both false renders "+
			"cleanly and then CrashLoopBackOffs, and the operator has to read Config.Validate "+
			"to find out why.", chartDir)
	}
	// The message is the whole value of the guard: an operator who hits it needs
	// to be told which values to set, not that something is wrong.
	for _, want := range []string{"tls.enabled", "forceSecureCookies", "__Host-refresh_token"} {
		if !strings.Contains(guard, want) {
			t.Errorf("the fail guard in %s/templates/configmap.yaml does not mention %q. "+
				"It is the only thing the operator sees, so it has to name both values to set "+
				"and the reason the combination cannot work.", chartDir, want)
		}
	}
	if !strings.Contains(src, `ne .Values.profile "dev"`) {
		t.Errorf("the fail guard in %s/templates/configmap.yaml no longer exempts the dev "+
			"profile. Config.Validate returns before the TLS checks in dev, so a dev install "+
			"that legitimately serves plain HTTP would stop rendering.", chartDir)
	}
}

// ---------------------------------------------------------------------------
// Values helpers
// ---------------------------------------------------------------------------

// shippedValuesFiles returns values.yaml plus every overlay beside it, in the
// order an operator finds them. Reading the directory rather than listing the
// names means a new profile is covered the day it is added, which is when it
// would otherwise ship with the wrong pair.
func shippedValuesFiles(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, chartDir))
	if err != nil {
		t.Fatalf("read %s: %v", chartDir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "values") || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		out = append(out, name)
	}
	if len(out) < 2 {
		t.Fatalf("%s holds %d values files; the walk found nothing to check", chartDir, len(out))
	}
	return out
}

func loadValues(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return out
}

// lookup walks a dotted path through parsed YAML.
func lookup(values map[string]any, path ...string) (any, bool) {
	var cur any = values
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// resolveBool reads a value as helm would: the overlay wins where it sets the
// key, and values.yaml supplies the rest. Only leaf keys are read, so the
// shallow form is the same answer a deep merge gives.
func resolveBool(overlay, base map[string]any, path ...string) bool {
	if v, ok := lookup(overlay, path...); ok {
		b, _ := v.(bool)
		return b
	}
	v, ok := lookup(base, path...)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func resolveString(overlay, base map[string]any, path ...string) string {
	if v, ok := lookup(overlay, path...); ok {
		s, _ := v.(string)
		return s
	}
	v, _ := lookup(base, path...)
	s, _ := v.(string)
	return s
}
