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
// So this gate reads the setting list out of the Go source rather than repeating
// it, the way chart_metrics_listener_test.go reads the env var's name out of
// internal/server. A setting added to internal/config and not to the chart fails
// here, on the commit that adds it, instead of in a deployment nobody audits.
//
// It covered booleans only to begin with, on the argument that a boolean is the
// shape that fails silently while a missing DSN refuses to start. Half of that
// is right and the conclusion was not. A duration, a limit, an allow-list and a
// credential path fail exactly the way a boolean does: nothing refuses, the
// binary's compiled figure stands, and the pod is Ready. VAULT_MAX_SESSIONS_PER_USER
// was unreachable while VAULT_STRICT_SESSION_LIMIT beside it was exposed, so a
// deployment could choose what happens when the session-count query fails and not
// how many sessions a user may hold; the two Art. 5(1)(e) retention horizons were
// unreachable, so every install kept audit rows forever whatever docs/PRIVACY.md
// said. A gate that watches the booleans while the durations rot has a hole in
// it the size of the class it does not watch.
//
// It now walks three classes, all parsed out of internal/config:
//
//   - every registry checkEnvValues validates -- booleans, durations, integers,
//     enums, address lists and country lists;
//   - every plain string Load reads through os.Getenv, envOr, envList or
//     envListFold;
//   - every secret loadSecrets reads, whose _FILE variable is what the chart has
//     to name.
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

// settingClass says how a setting reaches the pod, and therefore what a gap in
// it costs. Kept as a type rather than a string because the ratchet below is
// held per class: a boolean exclusion traded for a string one would keep a
// single total steady while the class that fails silently grew.
type settingClass string

const (
	// classChecked is a setting checkEnvValues validates: a boolean, duration,
	// integer, enum, address list or country list. Every one is a value an
	// operator is expected to be able to give, and every one holds a compiled
	// figure in silence when they cannot.
	classChecked settingClass = "checked"
	// classPlain is a plain string Load reads.
	classPlain settingClass = "plain"
	// classSecret is a credential loadSecrets reads. The chart has to name its
	// _FILE variable, not the variable itself: putting a secret's value in a
	// ConfigMap would publish it to everything holding get configmaps.
	classSecret settingClass = "secret"
)

// chartUnexposedSettings is every setting the config package reads that the
// chart deliberately does not offer, each with the reason.
//
// A reason has to say why the chart is the wrong place for that setting, not
// that nobody has got to it. Five of these are overrides whose entire purpose is
// to countermand a refusal the deployment should not be hitting, and the config
// package already refuses them outside the profile they belong to; putting them
// in values.yaml would advertise them as ordinary settings. The rest are read
// somewhere this ConfigMap does not reach, or are not settings at all.
//
// VAULT_MINT_ENABLED was excused on a "cannot be turned on alone" ground, and
// the entry ended "exposing /mint from the chart means exposing all four". It
// now does. The two VAULT_SVCDOC_* switches were excused because the store's
// size, count and quota ceilings were unreachable; all three are now rendered
// beside them. Both reasons were true when written and stopped being true the
// moment the companions were wired, so the entries are gone rather than
// restated.
//
// TestTheUnexposedSetOnlyShrinks holds the size as a per-class ratchet, so an
// entry may be removed but never added. That is the same commitment
// .coverage-exclusions.json makes, for the same reason: a list of exceptions
// that can grow is not an exception list, it is a backlog nobody reads.
var chartUnexposedSettings = map[string]string{
	"CORS_ALLOW_ALL": "applyProductionDefaults sets CORSAllowAll = false unconditionally, without " +
		"consulting the environment at all, so a chart value would render an env var the " +
		"production profile discards. corsOrigins is the setting that works here, and it is " +
		"now one the chart renders.",
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

	"LOG_LEVEL": "not a setting. No vault42 binary has a log-verbosity control; Load reads this " +
		"only to announce at startup that it is ignored. Rendering it would put the claim back " +
		"that setting it does something, which is the defect the announcement exists for.",
	"VAULT_SECRET_FILE_CONSUME": "makes the first read of a secret destroy the file, and it is " +
		"the one boolean in the package deliberately not resolved through parseBoolEnv, because " +
		"guessing this one wrong costs the operator their key material. The chart mounts the " +
		"Secret read-only, where the wipe is a no-op that logs two warnings per secret on every " +
		"boot, so the only thing a chart value could produce here is noise or a destroyed mount.",
	"VAULT_EMAIL_TEMPLATES_DIR": "names a directory of template overrides. The chart mounts no " +
		"such volume, and a path with nothing behind it is not a configured override -- the " +
		"embedded templates are used and nothing says so. Exposing the path would have to come " +
		"with the volume that fills it, the way adminGateway.clientCRL does.",
	"VAULT_HONEYPOT_WEBHOOK": "read only in the honeypot profile, and the honeypot instance has " +
		"a ConfigMap of its own -- it is the only workload this chart renders with that profile. " +
		"honeypotInstance.webhookURL renders it there; setting it in the release ConfigMap would " +
		"put it on the production vault, which never reads it.",
	"VAULT_HONEYPOT_TRAP_USERS": "read only in the honeypot profile, and set through " +
		"honeypotInstance.trapUsers on the honeypot's own ConfigMap, for the reason above.",
}

// unexposedBaseline is the high-water mark each class may not exceed.
//
// The checked figure stood at nine when this gate was booleans only, at eight
// after VAULT_DPOP_ENABLED was wired, at seven after VAULT_MINT_ENABLED and at
// five once the service-document store came with its ceilings. The other two
// classes are anchored on the commit that brought them under the gate; five
// plain settings were excused there, none of them for want of effort, and no
// credential was.
var unexposedBaseline = map[settingClass]int{
	classChecked: 5,
	classPlain:   5,
	classSecret:  0,
}

// configSetting is one setting internal/config reads, with the name the chart
// has to put in the pod's environment for it to arrive.
type configSetting struct {
	env   string
	class settingClass
}

// settingsTheConfigPackageReads parses internal/config for every setting it
// reads, in all three classes.
//
// Read from the source rather than repeated here so that renaming a variable, or
// adding one, cannot leave this gate asserting against a list that no longer
// describes what the binary reads.
func settingsTheConfigPackageReads(t *testing.T) []configSetting {
	t.Helper()

	seen := make(map[string]bool)
	var out []configSetting
	add := func(env string, class settingClass) {
		if env == "" || seen[env] {
			return
		}
		seen[env] = true
		out = append(out, configSetting{env: env, class: class})
	}

	for _, env := range checkedEnvVars(t) {
		add(env, classChecked)
	}

	// The plain readers and the secret readers, over every file in the package.
	// A secret's own name is never what the chart sets -- LoadSecret appends
	// _FILE to it -- so the two are collected separately and the secret's env is
	// the one the pod actually carries.
	plain := regexp.MustCompile(`(?:os\.Getenv|envOr|envList|envListFold)\(\s*"([A-Z][A-Z0-9_]*)"`)
	secret := regexp.MustCompile(`(?:LoadSecret|LoadSecretBinary|LoadSecretOptional)\(\s*"([A-Z][A-Z0-9_]*)"`)
	for _, src := range configPackageSources(t) {
		for _, m := range secret.FindAllStringSubmatch(src, -1) {
			add(m[1]+"_FILE", classSecret)
		}
		for _, m := range plain.FindAllStringSubmatch(src, -1) {
			add(m[1], classPlain)
		}
	}

	if len(out) == 0 {
		t.Fatal("nothing parsed out of internal/config, which would make every assertion below vacuous")
	}
	return out
}

// checkedEnvVars parses every registry checkEnvValues walks out of
// internal/config/envcheck.go.
//
// All six, not the boolean list alone. The package curates these as the settings
// whose values are validated, which is the same thing as saying they are the
// settings an operator is expected to be able to give -- and a validated setting
// nobody can reach is a check that never runs.
func checkedEnvVars(t *testing.T) []string {
	t.Helper()

	src := commentFreeSource(t, filepath.Join(repoRoot(t), "internal", "config", "envcheck.go"))

	registries := []struct {
		name    string
		pattern string
		key     string
	}{
		{name: "boolEnvVars", pattern: `(?s)var boolEnvVars = \[\]string\{(.*?)\}`, key: `"([^"]+)"`},
		{name: "cidrEnvVars", pattern: `(?s)var cidrEnvVars = \[\]string\{(.*?)\}`, key: `"([^"]+)"`},
		{name: "countryEnvVars", pattern: `(?s)var countryEnvVars = \[\]string\{(.*?)\}`, key: `"([^"]+)"`},
		{name: "durationEnvVars", pattern: `(?s)var durationEnvVars = map\[[^\]]+\][^{]*\{(.*?)\n\}`, key: `"([^"]+)"\s*:`},
		{name: "intEnvVars", pattern: `(?s)var intEnvVars = map\[[^\]]+\][^{]*\{(.*?)\n\}`, key: `"([^"]+)"\s*:`},
		{name: "enumEnvVars", pattern: `(?s)var enumEnvVars = map\[[^\]]+\][^{]*\{(.*?)\n\}`, key: `"([^"]+)"\s*:`},
	}

	var names []string
	for _, registry := range registries {
		block := regexp.MustCompile(registry.pattern).FindStringSubmatch(src)
		if block == nil {
			t.Fatalf("internal/config/envcheck.go no longer declares %s. That list is how "+
				"checkEnvValues knows what to validate, and it is what this gate walks to decide "+
				"which settings a deployment has to be able to reach.", registry.name)
		}
		found := regexp.MustCompile(registry.key).FindAllStringSubmatch(block[1], -1)
		if len(found) == 0 {
			t.Fatalf("%s parsed to an empty list, which would make every assertion below vacuous",
				registry.name)
		}
		for _, m := range found {
			names = append(names, m[1])
		}
	}
	return names
}

// TestTheChartCanSetEverySettingTheServerReads is the gate that would have
// caught DPoP, and now also the session cap, the retention horizons and the
// statement timeout beside it.
func TestTheChartCanSetEverySettingTheServerReads(t *testing.T) {
	root := repoRoot(t)
	rendered := commentFreeSource(t, filepath.Join(root, chartDir, "templates", "configmap.yaml")) +
		commentFreeSource(t, filepath.Join(root, chartDir, "templates", "deployment.yaml"))

	for _, setting := range settingsTheConfigPackageReads(t) {
		if reason, excused := chartUnexposedSettings[setting.env]; excused {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is listed as deliberately unexposed with no reason. An unexposed "+
					"setting and no explanation is how the DPoP row came to be certified "+
					"against a control no deployment installs.", setting.env)
			}
			continue
		}

		// A ConfigMap key is `NAME:`; a Deployment env entry is `name: NAME`.
		if containsIdentifier(rendered, setting.env+":") || containsIdentifier(rendered, "name: "+setting.env) {
			continue
		}
		t.Errorf("the chart's configmap.yaml and deployment.yaml set neither %s nor anything "+
			"else that puts it in the pod, and it is not listed in chartUnexposedSettings. The "+
			"binary reads it from the environment, so on every chart install it holds whatever "+
			"its compiled default is and the pod reports healthy either way. Wire it to a "+
			"value at that default, or add it to chartUnexposedSettings with the reason the "+
			"chart is the wrong place for it -- and \"nobody needs it\" is not one.", setting.env)
	}
}

// A reason for a setting that no longer exists is worse than no reason: it reads
// as a considered decision about live code, and re-anchoring exclusion entries
// without re-reading their justifications is exactly how five arguments in
// .coverage-exclusions.json came to cite code that had moved.
func TestNoSettingIsExcusedThatTheConfigPackageNoLongerReads(t *testing.T) {
	live := make(map[string]bool)
	for _, setting := range settingsTheConfigPackageReads(t) {
		live[setting.env] = true
	}

	for env := range chartUnexposedSettings {
		if !live[env] {
			t.Errorf("chartUnexposedSettings excuses %s, which internal/config no longer reads. "+
				"Either the setting was renamed and the chart now has a real gap under the new "+
				"name, or it is gone and this entry is an argument about nothing.", env)
		}
	}
}

// The ratchet, held per class. A set that may shrink and may not grow, and one
// class's exclusions cannot be traded for another's.
func TestTheUnexposedSetOnlyShrinks(t *testing.T) {
	class := make(map[string]settingClass)
	for _, setting := range settingsTheConfigPackageReads(t) {
		class[setting.env] = setting.class
	}

	counted := make(map[settingClass]int)
	for env := range chartUnexposedSettings {
		counted[class[env]]++
	}

	for kind, baseline := range unexposedBaseline {
		if counted[kind] > baseline {
			t.Errorf("chartUnexposedSettings holds %d %s entries, above the baseline of %d. A "+
				"new setting the chart cannot set is the defect this gate exists for; wire it "+
				"rather than widening the exception.", counted[kind], kind, baseline)
		}
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
// chartUnexposedSettings false, because a setting the chart declines to offer
// would be one --set away.
//
// Values files and templates only. README.md is prose about the chart, and the
// sentence saying there is no extraEnv is the documentation of this decision,
// not a breach of it.
// minChartFilesScanned is the floor on TestTheChartOffersNoRawEnvironmentPassthrough's
// corpus. That gate proves a negative -- it passes by finding no escape hatch --
// and a walk that reads nothing finds nothing either, so a moved directory or a
// renamed suffix would retire it silently. This is the failure
// tests/compliance/gate_liveness_test.go exists to catch, and it caught this one.
// The chart carries well over ten files; the floor only has to be high enough
// that an empty or truncated read cannot pass.
const minChartFilesScanned = 10

func TestTheChartOffersNoRawEnvironmentPassthrough(t *testing.T) {
	root := repoRoot(t)
	hatches := regexp.MustCompile(`(?i)\bextra_?env|\benv_?vars\b|\badditional_?env`)

	scanned := 0

	for _, dir := range []string{filepath.Join(root, chartDir), filepath.Join(root, chartDir, "templates")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || filepath.Ext(name) == ".md" {
				continue
			}
			path := filepath.Join(dir, name)
			if _, known := commentSyntaxFor(path); !known {
				continue
			}
			if match := hatches.FindString(commentFreeSource(t, path)); match != "" {
				t.Errorf("%s offers %q. An operator can then put any name in the pod's "+
					"environment from values.yaml, which satisfies every wiring assertion in "+
					"this file without the chart reaching a single setting, and turns each "+
					"reason in chartUnexposedSettings into a claim the chart does not keep.",
					filepath.Join(chartDir, name), match)
			}
			scanned++
		}
	}

	if scanned < minChartFilesScanned {
		t.Fatalf("scanned only %d chart files, want at least %d. This gate passes by finding no "+
			"escape hatch, so a corpus this small means it proved nothing: check that %s and its "+
			"templates directory are still where commentSyntaxFor can read them.",
			scanned, minChartFilesScanned, chartDir)
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
