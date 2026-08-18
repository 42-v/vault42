// Chart wiring gate for the control switches.
//
// This class has now bitten twice. The metrics listener bound loopback because
// the chart never set VAULT_METRICS_ADDR, and every scrape was refused at
// connect while the pod reported healthy. Then DPoP: `grep -rn dpop charts/`
// returned nothing, VAULT_DPOP_ENABLED defaults to false, and the chart offered
// no way to set it -- so the sender-constraining control the compliance register
// records as Met, with the strongest gates in the tree, was inert in every
// deployment the chart targets. The register row was true about the code and
// false about anything installed.
//
// Both are the same defect: a control the binary reads from the environment, and
// a chart with no way to put that value in the environment. Nothing in the build
// sees both ends. The Go side compiles, the YAML renders, the tests pass, and
// the control is off.
//
// So this gate reads the switch list out of the Go source rather than repeating
// it, the way chart_metrics_listener_test.go reads the env var's name out of
// internal/server. A switch added to internal/config and not to the chart fails
// here, on the commit that adds it, instead of in a deployment nobody audits.
//
// Booleans specifically, and not every setting the config package reads, because
// a boolean is the shape that fails silently. A missing DSN refuses to start; a
// missing feature switch comes up healthy with the feature off, which is
// indistinguishable from an operator who chose that.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// chartUnexposedSwitches is every boolean the config package reads that the
// chart deliberately does not offer, each with the reason.
//
// A reason has to say why the chart is the wrong place for that switch, not that
// nobody has got to it. Five of these are overrides whose entire purpose is to
// countermand a refusal the deployment should not be hitting, and the config
// package already refuses them outside the profile they belong to; putting them
// in values.yaml would advertise them as ordinary settings. The other two are
// switches that cannot be turned on alone, and shipping the switch without its
// companions would render a chart that refuses to boot -- a new instance of this
// same defect rather than a fix for it.
//
// VAULT_MINT_ENABLED was excused on exactly that "cannot be turned on alone"
// ground, and the entry ended "exposing /mint from the chart means exposing all
// four". It now does: mint.enabled, mint.audience, mint.tokenTTL, mint.maxTTL
// and the two allow-lists render together, so the reason no longer describes
// anything and the entry is gone rather than restated.
//
// TestTheUnexposedSetOnlyShrinks holds the size as a ratchet, so an entry may be
// removed but never added. That is the same commitment .coverage-exclusions.json
// makes, for the same reason: a list of exceptions that can grow is not an
// exception list, it is a backlog nobody reads.
var chartUnexposedSwitches = map[string]string{
	"CORS_ALLOW_ALL": "applyProductionDefaults sets CORSAllowAll = false unconditionally, without " +
		"consulting the environment at all, so a chart value would render an env var the " +
		"production profile discards. CORS_ORIGINS is the setting that works here.",
	"VAULT_ALLOW_PLAINTEXT": "overrides Validate's refusal to run without TLS. The chart answers " +
		"that case better than an env var can: configmap.yaml calls fail at render time on the " +
		"tls.enabled/forceSecureCookies pair, so the operator gets the reason at install " +
		"instead of a CrashLoopBackOff whose cause is one line deep in the pod log.",
	"VAULT_ALLOW_RATE_LIMIT_DISABLED": "overrides Validate's refusal to run with rate limiting " +
		"off. rateLimitEnabled is the switch the chart exposes; an operator who means to " +
		"disable a control the production profile refuses is stating that outside the values " +
		"file on purpose.",
	"VAULT_EMBEDDED_TRUSTED_UPSTREAM": "Load returns an error for this outside the embedded " +
		"profile, and this chart deploys production. A value here would be one the chart can " +
		"set and the binary refuses to start on.",
	"VAULT_SMTP_ALLOW_PLAINTEXT": "Load accepts it only for a loopback SMTP_HOST. The chart's " +
		"SMTP host is a Service name, which is never loopback, so the rendered pod could not " +
		"use the value the chart set.",
	"VAULT_SVCDOC_ENABLED": "the document store's quota, size and per-subject limits are read " +
		"from four further env vars the chart does not set, so the switch alone would mount a " +
		"store running on defaults an operator never chose.",
	"VAULT_SVCDOC_SHARED_ENABLED": "sharing is meaningless without VAULT_SVCDOC_ENABLED, which " +
		"is unexposed for the reason above.",
}

// unexposedBaseline is the high-water mark the set may not exceed. It stood at
// nine before VAULT_DPOP_ENABLED was wired and at eight before VAULT_MINT_ENABLED
// was; each wiring lowers it, which is what makes it a ratchet rather than a
// budget somebody can spend back.
const unexposedBaseline = 7

// boolEnvVars parses the switch list out of internal/config/envcheck.go.
//
// Read from the source rather than repeated here so that renaming a variable, or
// adding one, cannot leave this gate asserting against a list that no longer
// describes what the binary reads.
func boolEnvVars(t *testing.T) []string {
	t.Helper()

	src := commentFreeSource(t, filepath.Join(repoRoot(t), "internal", "config", "envcheck.go"))
	block := regexp.MustCompile(`(?s)var boolEnvVars = \[\]string\{(.*?)\n\}`).FindStringSubmatch(src)
	if block == nil {
		t.Fatal("internal/config/envcheck.go no longer declares boolEnvVars. That list is how " +
			"checkEnvValues knows which settings are booleans, and it is what this gate walks " +
			"to decide which controls a deployment has to be able to reach.")
	}

	matches := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(block[1], -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatal("boolEnvVars parsed to an empty list, which would make every assertion below vacuous")
	}
	return names
}

// TestTheChartCanSetEveryControlSwitchTheServerReads is the gate that would have
// caught DPoP.
func TestTheChartCanSetEveryControlSwitchTheServerReads(t *testing.T) {
	configmap := commentFreeSource(t, filepath.Join(repoRoot(t), chartDir, "templates", "configmap.yaml"))

	for _, env := range boolEnvVars(t) {
		if reason, excused := chartUnexposedSwitches[env]; excused {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is listed as deliberately unexposed with no reason. An unexposed "+
					"switch and no explanation is how the DPoP row came to be certified "+
					"against a control no deployment installs.", env)
			}
			continue
		}

		if !containsIdentifier(configmap, env+":") {
			t.Errorf("charts/vault/templates/configmap.yaml does not set %s, and it is not "+
				"listed in chartUnexposedSwitches. The binary reads that switch from the "+
				"environment, so on every chart install the control it gates is whatever "+
				"its compiled default is, and the pod reports healthy either way. Wire it "+
				"to a value, or add it to chartUnexposedSwitches with the reason the chart "+
				"is the wrong place for it.", env)
		}
	}
}

// A reason for a switch that no longer exists is worse than no reason: it reads
// as a considered decision about live code, and re-anchoring exclusion entries
// without re-reading their justifications is exactly how five arguments in
// .coverage-exclusions.json came to cite code that had moved.
func TestNoSwitchIsExcusedThatTheConfigPackageNoLongerReads(t *testing.T) {
	live := make(map[string]bool)
	for _, env := range boolEnvVars(t) {
		live[env] = true
	}

	for env := range chartUnexposedSwitches {
		if !live[env] {
			t.Errorf("chartUnexposedSwitches excuses %s, which internal/config no longer reads "+
				"as a boolean. Either the switch was renamed and the chart now has a real "+
				"gap under the new name, or it is gone and this entry is an argument about "+
				"nothing.", env)
		}
	}
}

// The ratchet. The set may shrink and may not grow.
func TestTheUnexposedSetOnlyShrinks(t *testing.T) {
	if len(chartUnexposedSwitches) > unexposedBaseline {
		t.Errorf("chartUnexposedSwitches holds %d entries, above the baseline of %d. A new "+
			"switch the chart cannot set is the defect this gate exists for; wire it rather "+
			"than widening the exception.", len(chartUnexposedSwitches), unexposedBaseline)
	}
}

// DPoP end to end: the value reaches the ConfigMap, and the shipped default
// leaves an existing install exactly where it was.
func TestTheChartRendersTheDPoPSwitch(t *testing.T) {
	const env = "VAULT_DPOP_ENABLED"

	def := renderedConfigMapValue(t, env)
	if def != "false" {
		t.Errorf("the default render sets %s to %q, want \"false\". The switch is off in the "+
			"binary, so a chart that turns it on by default would start refusing requests "+
			"from every client that cannot send a proof, on upgrade, without anyone asking "+
			"for it.", env, def)
	}

	on := renderedConfigMapValue(t, env, "--set", "dpop.enabled=true")
	if on != "true" {
		t.Errorf("with dpop.enabled=true the ConfigMap sets %s to %q. The value does not reach "+
			"the rendered env, so sender-constrained access tokens stay off however the "+
			"operator configures the release.", env, on)
	}
}

// mintValues is the smallest set of values that turns /mint on and renders.
// Reused by the tests below so each one states only the thing it varies.
var mintValues = []string{
	"--set", "mint.enabled=true",
	"--set", "mint.audience=https://beon3.example",
	"--set", "mint.allowedRoles={service,beon3:coach}",
	"--set", "mint.allowedScopes={profile:read}",
}

// /mint end to end. The endpoint signs a token for a subject vault42 never
// authenticated, so the default has to be the binary's own -- off, no audience,
// and allow-lists that permit nothing -- and turning it on has to be expressible
// in values.yaml alone, because the alternative for the deployment that needs it
// is an out-of-band env var nothing in this repository can see.
func TestTheChartRendersTheMintEndpointAtTheBinarysDefaults(t *testing.T) {
	data := renderedConfigMap(t)

	for _, env := range []string{
		"VAULT_MINT_ENABLED", "VAULT_MINT_AUDIENCE", "VAULT_MINT_TOKEN_TTL",
		"VAULT_MINT_MAX_TTL", "VAULT_MINT_ROLES", "VAULT_MINT_SCOPES",
	} {
		got, rendered := data[env]
		if !rendered {
			t.Errorf("the default render sets no %s. /mint needs all six together: the switch "+
				"without the audience refuses to boot, and the switch without the allow-lists "+
				"mounts a signing oracle that grants nothing.", env)
			continue
		}
		// VAULT_MINT_AUDIENCE is the one of the six internal/config reads
		// through a bare os.Getenv, so binaryDefault states nothing about it.
		// Unset is still its default, and it has to stay unset: an audience the
		// chart invented would be one the operator never agreed to mint for.
		if env == "VAULT_MINT_AUDIENCE" {
			if got != "" {
				t.Errorf("the default render sets %s to %q. /mint is off by default, so the "+
					"chart is naming an audience for an endpoint nobody enabled.", env, got)
			}
			continue
		}
		want, known := binaryDefault(t, env)
		if !known {
			t.Errorf("internal/config no longer reads %s in a form this gate can take a default "+
				"from, so the claim that the chart ships the binary's own default is unchecked", env)
			continue
		}
		if !sameSetting(t, want, got) {
			t.Errorf("the default render sets %s to %q; the binary's own default is %q. A chart "+
				"default that is not the binary's default changes what an existing release does "+
				"on upgrade, for an endpoint nobody asked to turn on.", env, got, want.text)
		}
	}
}

// The other half: a deployment that does want /mint can say so in values.yaml
// and nowhere else.
func TestTheChartCanTurnTheMintEndpointOn(t *testing.T) {
	data := renderedConfigMap(t, mintValues...)

	for env, want := range map[string]string{
		"VAULT_MINT_ENABLED":  "true",
		"VAULT_MINT_AUDIENCE": "https://beon3.example",
		"VAULT_MINT_ROLES":    "service,beon3:coach",
		"VAULT_MINT_SCOPES":   "profile:read",
	} {
		if got := data[env]; got != want {
			t.Errorf("with /mint enabled through values the ConfigMap sets %s to %q, want %q. "+
				"The value does not reach the rendered environment, so the endpoint stays "+
				"unreachable however the operator configures the release.", env, got, want)
		}
	}
}

// Both refusals Config.Validate makes about the mint audience, moved to render
// time. A chart that can render either of these ships an install whose failure
// mode is a CrashLoopBackOff with the reason one line deep in the pod log.
func TestTheChartRefusesAMintAudienceThatWillNotBoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{
			name: "no audience",
			sets: []string{"--set", "mint.enabled=true"},
			want: "mint.audience",
		},
		{
			name: "audience equal to origin",
			sets: []string{"--set", "mint.enabled=true", "--set", "mint.audience=https://auth.example.com"},
			want: "mint.audience equals origin",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, err := helmTemplate(t, tc.sets...)
			if err == nil {
				t.Fatal("helm rendered a release whose vault42 refuses to start. Config.Validate " +
					"checks the mint audience ahead of the dev short-circuit, so this is a " +
					"CrashLoopBackOff in every profile, not a production-only one.")
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("the render failure does not name %q, so the operator is told the "+
					"install failed and not which value to change:\n%s", tc.want, stderr)
			}
		})
	}
}

// A gate an escape hatch can satisfy certifies nothing.
//
// Every assertion in this file is "the chart puts this name in the pod's
// environment". A values key that splices an arbitrary env list into the
// workload would satisfy all of them at once, from a chart that reaches no
// setting in particular -- and it would also make the reasons in
// chartUnexposedSwitches false, because a switch the chart declines to offer
// would be one --set away.
func TestTheChartOffersNoRawEnvironmentPassthrough(t *testing.T) {
	root := repoRoot(t)
	hatches := regexp.MustCompile(`(?i)\bextra_?env|\benv_?vars\b|\badditional_?env`)

	for _, dir := range []string{filepath.Join(root, chartDir), filepath.Join(root, chartDir, "templates")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if _, known := commentSyntaxFor(path); !known {
				continue
			}
			if match := hatches.FindString(commentFreeSource(t, path)); match != "" {
				t.Errorf("%s offers %q. An operator can then put any name in the pod's "+
					"environment from values.yaml, which satisfies every wiring assertion in "+
					"this file without the chart reaching a single setting, and turns each "+
					"reason in chartUnexposedSwitches into a claim the chart does not keep.",
					filepath.Join(chartDir, entry.Name()), match)
			}
		}
	}
}

// renderedConfigMap renders the chart and returns the data of the vault's own
// ConfigMap. An absent key and a key set to the empty string are different
// answers -- the first is a setting the chart cannot reach -- so this returns
// the map rather than a lookup.
func renderedConfigMap(t *testing.T, extra ...string) map[string]string {
	t.Helper()

	stdout, stderr, err := helmTemplate(t, extra...)
	if err != nil {
		t.Fatalf("helm template %v failed: %v\n%s", extra, err, stderr)
	}

	decoder := yaml.NewDecoder(strings.NewReader(stdout))
	for {
		var doc map[string]any
		if err := decoder.Decode(&doc); err != nil {
			break
		}
		if kind, _ := doc["kind"].(string); kind != "ConfigMap" {
			continue
		}
		if name, _ := mapAt(doc, "metadata")["name"].(string); strings.HasSuffix(name, "-honeypot") {
			continue
		}
		data := make(map[string]string)
		for key, value := range mapAt(doc, "data") {
			if s, ok := value.(string); ok {
				data[key] = s
			}
		}
		return data
	}
	t.Fatal("the render produced no ConfigMap for the vault itself")
	return nil
}

// renderedConfigMapValue renders the chart and returns one key from the vault's
// own ConfigMap, or "" when the key is absent.
func renderedConfigMapValue(t *testing.T, key string, extra ...string) string {
	t.Helper()

	stdout, stderr, err := helmTemplate(t, extra...)
	if err != nil {
		t.Fatalf("helm template %v failed: %v\n%s", extra, err, stderr)
	}

	decoder := yaml.NewDecoder(strings.NewReader(stdout))
	for {
		var doc map[string]any
		if err := decoder.Decode(&doc); err != nil {
			break
		}
		if kind, _ := doc["kind"].(string); kind != "ConfigMap" {
			continue
		}
		if value, ok := mapAt(doc, "data")[key].(string); ok {
			return value
		}
	}
	return ""
}
