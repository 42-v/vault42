// Chart environment wiring gate.
//
// cmd/admin-gateway builds its account-erasure service only when it has the
// HMAC secret, because that is what the identity and blob pseudonyms are derived
// from. Without it, DELETE /admin/users/{id} answers 503.
//
// The chart never set HMAC_SECRET_FILE on the admin-gateway deployment. The
// secret was already in the mounted volume, the server's own deployment read it,
// and the gateway's template simply did not name it. So the Article 17 erasure
// path was off in every chart install, silently: the binary starts, the route
// exists, and it answers 503 to the one request it is there to serve.
//
// Nothing could catch that. The env block is YAML, the feature gate is a Go
// length check on a config field, and no compiler, linter or test sees both.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// chartEnvRequirements maps a chart template to the env vars it must set,
// each with the capability that silently disappears without it.
//
// Adding an entry is how a new feature-gating secret gets protected. The
// question to ask is: if this env were missing, would the process refuse to
// start, or would it come up healthy with one capability switched off?
var chartEnvRequirements = map[string]map[string]string{
	"admin-gateway.yaml": {
		"MASTER_KEY_FILE":  "admin TOTP secrets and JWT signing-key wrapping",
		"HMAC_SECRET_FILE": "the account-erasure service, so DELETE /admin/users/{id} answers 503 without it",
	},
	"deployment.yaml": {
		"MASTER_KEY_FILE":  "encryption at rest for TOTP secrets, identity records, blobs and service documents",
		"HMAC_SECRET_FILE": "every pseudonym derivation, including the erasure cascade",
	},
}

// TestChartsProvideEveryFeatureGatingSecret fails when a template stops naming
// an env var a capability is gated on.
func TestChartsProvideEveryFeatureGatingSecret(t *testing.T) {
	root := repoRoot(t)

	for template, required := range chartEnvRequirements {
		t.Run(template, func(t *testing.T) {
			path := filepath.Join(root, "charts", "vault", "templates", template)
			src := readFileString(t, path)

			for env, capability := range required {
				if !strings.Contains(src, "name: "+env) {
					t.Errorf("charts/vault/templates/%s does not set %s. The process starts "+
						"without it and reports healthy, and %s is switched off. An operator "+
						"discovers that from the failing request, not from the install.",
						template, env, capability)
				}
			}
		})
	}
}
