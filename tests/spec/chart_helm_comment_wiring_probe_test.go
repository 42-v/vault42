package spec_test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHelmTemplateCommentsCannotSatisfyTheChartWiringGate is the regression for
// a gate that claimed to refuse every escape hatch and still had one.
//
// charts/vault/templates/configmap.yaml is a Helm template. commentFreeSource
// classified it as plain YAML and blanked only # comments, so a Helm block
// comment:
//
//	{{/* VAULT_DPOP_ENABLED: "false" */}}
//
// survived as live source text. The wiring gate's containsIdentifier look for
// `VAULT_DPOP_ENABLED:` then returned true, the suite stayed green, and the
// rendered ConfigMap never set the variable — exactly the defect the gate was
// written to catch (DPoP certified Met, every chart install inert), reachable
// again by moving the key into a comment the blanker did not know.
//
// values.yaml stays plain YAML: it is not under templates/ and carries no
// Helm comment grammar.
func TestHelmTemplateCommentsCannotSatisfyTheChartWiringGate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "templates", "configmap.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "apiVersion: v1\nkind: ConfigMap\ndata:\n" +
		"  {{- /* VAULT_DPOP_ENABLED: \"false\" */}}\n" +
		"  # VAULT_MFA_REQUIRED: \"true\"\n" +
		"  VAULT_APP_NAME: \"x\"\n"
	writeProbeFile(t, path, body)

	got := commentFreeSource(t, path)
	if containsIdentifier(got, "VAULT_DPOP_ENABLED:") {
		t.Fatalf("a Helm template comment still satisfies containsIdentifier for "+
			"VAULT_DPOP_ENABLED:. The chart wiring gate can be kept green while the "+
			"rendered ConfigMap never sets the switch.\ncomment-free source:\n%s", got)
	}
	if containsIdentifier(got, "VAULT_MFA_REQUIRED:") {
		t.Fatalf("a YAML # comment still satisfies containsIdentifier for "+
			"VAULT_MFA_REQUIRED:.\ncomment-free source:\n%s", got)
	}
	if !containsIdentifier(got, "VAULT_APP_NAME:") {
		t.Fatalf("live ConfigMap key was blanked; every wiring assertion would "+
			"false-fail.\ncomment-free source:\n%s", got)
	}
}

// values.yaml must keep the plain-YAML grammar: it is not a Helm template, and
// a {{/* … */}} sequence there is operator-authored text rather than a comment.
func TestValuesYAMLIsNotTreatedAsAHelmTemplate(t *testing.T) {
	syntax, known := commentSyntaxFor("charts/vault/values.yaml")
	if !known || syntax != syntaxYAML {
		t.Fatalf("commentSyntaxFor(values.yaml) = %q, %v; want %q, true", syntax, known, syntaxYAML)
	}
}
