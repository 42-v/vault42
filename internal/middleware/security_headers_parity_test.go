package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// web/nginx.conf configures the optional standalone frontend image. The policy
// that actually reaches a user is this middleware's: the Go binary embeds
// web/dist with go:embed and serves it, and the chart's separate frontend
// Deployment is off by default. So the nginx file is a floor, not a ceiling —
// the moment the container-only policy is stricter than the one the default
// deployment serves, the hardening has been applied to the wrong artifact.
//
// This compares the two rather than restating either. A static assertion that
// the Go policy contains some list of directives cannot notice that the nginx
// policy grew one; this fails the moment they diverge in the wrong direction.

var (
	nginxHeaderRe = regexp.MustCompile(`add_header\s+([A-Za-z-]+)\s+"([^"]*)"`)
	// 'none' is the empty source list. Anything else is a superset of it, so a
	// directive set to 'none' is never weaker than one that is not.
	sourceNone = "'none'"
)

func TestServedPolicyIsNeverWeakerThanTheNginxImage(t *testing.T) {
	nginx := nginxHeaders(t)

	rec := httptest.NewRecorder()
	SecurityHeaders(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	served := rec.Header()

	for header, nginxValue := range nginx {
		servedValue := served.Get(header)
		if servedValue == "" {
			t.Errorf("web/nginx.conf sets %s but the served frontend response does not; "+
				"the container-only policy is stronger than the one the binary serves", header)
			continue
		}
		switch header {
		case "Content-Security-Policy":
			compareDirectives(t, header, parseCSP(servedValue), parseCSP(nginxValue))
		case "Permissions-Policy":
			compareDirectives(t, header, parsePermissionsPolicy(servedValue), parsePermissionsPolicy(nginxValue))
		}
	}
}

// compareDirectives fails for every directive both policies declare where the
// served one permits a source the nginx one does not.
func compareDirectives(t *testing.T, header string, served, nginx map[string][]string) {
	t.Helper()
	compared := 0
	for name, nginxSources := range nginx {
		servedSources, ok := served[name]
		if !ok {
			t.Errorf("%s: web/nginx.conf declares %q but the served policy does not", header, name)
			continue
		}
		compared++
		if len(servedSources) == 1 && servedSources[0] == sourceNone {
			continue
		}
		for _, src := range servedSources {
			if !slices.Contains(nginxSources, src) {
				t.Errorf("%s: the served %q allows %q, which web/nginx.conf does not (%v). "+
					"The served policy is the one users get; it must not be the weaker of the two.",
					header, name, src, nginxSources)
			}
		}
	}
	// A comparison that lines up no directives passes for the wrong reason.
	if compared == 0 {
		t.Fatalf("%s: no directive was compared; the parser or the nginx file changed shape", header)
	}
}

// nginxHeaders reads every add_header from web/nginx.conf.
func nginxHeaders(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../web/nginx.conf")
	if err != nil {
		t.Fatalf("read web/nginx.conf: %v", err)
	}
	headers := map[string]string{}
	for _, m := range nginxHeaderRe.FindAllStringSubmatch(string(raw), -1) {
		headers[http.CanonicalHeaderKey(m[1])] = m[2]
	}
	if len(headers) == 0 {
		t.Fatal("no add_header directives found in web/nginx.conf; the gate is checking nothing")
	}
	return headers
}

// parseCSP splits "default-src 'self'; img-src 'self' data:" into directive
// name -> source list.
func parseCSP(policy string) map[string][]string {
	out := map[string][]string{}
	for _, directive := range strings.Split(policy, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}
		out[fields[0]] = fields[1:]
	}
	return out
}

// parsePermissionsPolicy splits "camera=(), publickey-credentials-get=(self)"
// into feature name -> allowlist.
func parsePermissionsPolicy(policy string) map[string][]string {
	out := map[string][]string{}
	for _, feature := range strings.Split(policy, ",") {
		name, allow, found := strings.Cut(strings.TrimSpace(feature), "=")
		if !found {
			continue
		}
		out[strings.TrimSpace(name)] = strings.Fields(strings.Trim(strings.TrimSpace(allow), "()"))
	}
	return out
}
