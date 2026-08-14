package compliance

import (
	"context"
	"crypto/sha1" // #nosec G505 -- test recomputes the HIBP k-anonymity prefix the shipped client sends
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/service"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// Supply-chain audit re-tests. Each of these replaces a register test that the
// register-audit flagged as weak-met: proving an adjacent control, asserting on
// the wrong artifact, or grepping for a single substring. Every test here drives
// the real shipped artifact or the real service end to end.
// =============================================================================

// -----------------------------------------------------------------------------
// OWASP ASVS 5.0.0 V13.4.1 — the deployed artifact carries no source-control
// metadata (.git/.svn).
//
// The prior test (TestOWASP_A08_2025_DependencyResolutionIsIntegrityPinned)
// asserted dependency-resolution integrity — package-manager hash pin and
// --frozen-lockfile — and never read a Dockerfile. This one reads the real
// shipped artifacts: every production runtime image is a distroless final stage
// that copies ONLY compiled build artifacts (COPY --from=<stage>), so the raw
// build context (which is where a .git/.svn tree would live) is never laid into
// the image; and .dockerignore excludes the VCS metadata from the build context
// in the first place.
// -----------------------------------------------------------------------------

// dockerfileFinalStageCopies returns the COPY/ADD instructions that appear in
// the last build stage of a Dockerfile (everything after the final FROM line).
func dockerfileFinalStageCopies(src string) []string {
	lines := strings.Split(src, "\n")
	lastFrom := -1
	for i, ln := range lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ln)), "FROM ") {
			lastFrom = i
		}
	}
	var copies []string
	if lastFrom < 0 {
		return copies
	}
	for _, ln := range lines[lastFrom+1:] {
		trimmed := strings.TrimSpace(ln)
		up := strings.ToUpper(trimmed)
		if strings.HasPrefix(up, "COPY ") || strings.HasPrefix(up, "ADD ") {
			copies = append(copies, trimmed)
		}
	}
	return copies
}

// copyInstruction describes one COPY/ADD: whether it pulls from a prior build
// stage (--from=), and its source operands (every token that is neither a flag
// nor the final destination).
type copyInstruction struct {
	fromStage bool
	sources   []string
}

func parseCopyInstruction(line string) copyInstruction {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return copyInstruction{}
	}
	inst := copyInstruction{}
	var operands []string
	for _, f := range fields[1:] { // skip the COPY/ADD verb
		if strings.HasPrefix(f, "--") {
			if strings.HasPrefix(f, "--from=") {
				inst.fromStage = true
			}
			continue
		}
		operands = append(operands, f)
	}
	// The last operand is the destination; the rest are sources.
	if len(operands) > 1 {
		inst.sources = operands[:len(operands)-1]
	}
	return inst
}

// copiesSourceControlTree reports whether a source operand would drag the whole
// build context or a VCS metadata tree (.git/.svn) into the image layer.
func copiesSourceControlTree(src string) bool {
	if src == "." || src == "./" {
		return true
	}
	clean := strings.TrimPrefix(src, "./")
	return clean == ".git" || clean == ".svn" ||
		strings.HasPrefix(clean, ".git/") || strings.HasPrefix(clean, ".svn/")
}

func TestASVS_V13_4_1_DeployedImageExcludesSourceControlMetadata(t *testing.T) {
	// 1) .dockerignore keeps VCS metadata out of the build context entirely.
	ignore := readProductionSource(t, ".dockerignore")
	var git, github bool
	for _, ln := range strings.Split(ignore, "\n") {
		switch strings.TrimSpace(ln) {
		case ".git/", ".git":
			git = true
		case ".github/", ".github":
			github = true
		}
	}
	if !git {
		t.Error("V13.4.1: .dockerignore no longer excludes .git/ — the git tree would enter the build context")
	}
	if !github {
		t.Error("V13.4.1: .dockerignore no longer excludes .github/ — CI/VCS metadata would enter the build context")
	}

	// 2) The deciding control on the image layer: every production runtime image
	// ships its binary as a compiled artifact pulled from a prior build stage
	// (COPY --from=), and no final-stage COPY drags the whole build context or a
	// .git/.svn tree into the runtime layer. Copying a specific non-VCS
	// subdirectory (e.g. migrations/) from context is fine; a `COPY . .` or
	// `COPY .git ...` is exactly what V13.4.1 forbids.
	runtimeDockerfiles := []string{"Dockerfile", "Dockerfile.admin-gateway", "Dockerfile.bridge"}
	for _, df := range runtimeDockerfiles {
		src := readProductionSource(t, df)
		copies := dockerfileFinalStageCopies(src)
		if len(copies) == 0 {
			t.Errorf("V13.4.1: %s final stage has no COPY instructions; cannot confirm it ships only build artifacts", df)
			continue
		}
		var fromStage bool
		for _, c := range copies {
			inst := parseCopyInstruction(c)
			if inst.fromStage {
				fromStage = true
			}
			for _, s := range inst.sources {
				if copiesSourceControlTree(s) {
					t.Errorf("V13.4.1: %s final stage copies %q into the runtime image; the build context / .git/.svn tree would ship in the image", df, s)
				}
			}
		}
		if !fromStage {
			t.Errorf("V13.4.1: %s final stage never copies a build artifact via --from=; it may be shipping raw source instead of a compiled binary", df)
		}
	}
}

// -----------------------------------------------------------------------------
// NIST SP 800-53 RA-5 — Vulnerability Monitoring and Scanning.
//
// The prior test (TestOWASP_A03_2025_ReleasePipelineProducesSignedProvenance)
// asserted SBOM/SLSA/cosign in release.yml — the release-signing control (SR-4),
// not scanning. This one reads the real nightly-security.yml and asserts the
// scanners run with a HIGH/CRITICAL gate, and that ci.yml and release.yml both
// call the workflow so the gate covers pull requests and releases, not only the
// 03:00 nightly.
// -----------------------------------------------------------------------------

type ghStep struct {
	Name string                 `yaml:"name"`
	Uses string                 `yaml:"uses"`
	Run  string                 `yaml:"run"`
	With map[string]interface{} `yaml:"with"`
}

type ghJob struct {
	Name  string   `yaml:"name"`
	Steps []ghStep `yaml:"steps"`
}

type ghWorkflow struct {
	Jobs map[string]ghJob `yaml:"jobs"`
}

func TestNIST_RA_5_NightlySecurityScannersEnforceHighCriticalGate(t *testing.T) {
	raw := workflowSource(t, "nightly-security.yml")
	if raw == "" {
		t.Fatal("RA-5: .github/workflows/nightly-security.yml is missing; the vulnerability-scan gate does not exist")
	}
	var wf ghWorkflow
	if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
		t.Fatalf("RA-5: parse nightly-security.yml: %v", err)
	}

	var govulncheck, trivyGate, gosecGate bool
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			// govulncheck scans the module graph for known-vulnerable symbols.
			if strings.Contains(step.Run, "govulncheck ./...") {
				govulncheck = true
			}
			// Trivy must fail the build (exit-code 1) on HIGH/CRITICAL findings.
			if strings.Contains(step.Uses, "aquasecurity/trivy-action") {
				sev := fmt.Sprint(step.With["severity"])
				exit := fmt.Sprint(step.With["exit-code"])
				if strings.Contains(sev, "HIGH") && strings.Contains(sev, "CRITICAL") && exit == "1" {
					trivyGate = true
				}
			}
			// gosec's own exit status is not the gate (it trips on LOW/MEDIUM);
			// the report is parsed and the build fails only on HIGH/CRITICAL.
			if strings.Contains(step.Run, "HIGH") && strings.Contains(step.Run, "CRITICAL") &&
				(strings.Contains(step.Run, "sys.exit") || strings.Contains(step.Run, "exit 1")) {
				gosecGate = true
			}
		}
	}

	if !govulncheck {
		t.Error("RA-5: no job runs `govulncheck ./...`; Go vulnerability scanning is gone")
	}
	if !trivyGate {
		t.Error("RA-5: no Trivy step gates on severity HIGH,CRITICAL with exit-code 1")
	}
	if !gosecGate {
		t.Error("RA-5: no gosec step fails the build on HIGH/CRITICAL findings")
	}

	// The gate has to run on the change-introduction paths, not only nightly.
	for _, caller := range []string{"ci.yml", "release.yml"} {
		src := workflowSource(t, caller)
		if src == "" {
			t.Errorf("RA-5: %s is missing; cannot confirm the scan gate runs on that path", caller)
			continue
		}
		if !strings.Contains(src, "nightly-security.yml") {
			t.Errorf("RA-5: %s no longer calls nightly-security.yml; a HIGH CVE could merge/release without a scan", caller)
		}
	}
}

// -----------------------------------------------------------------------------
// NIST SP 800-53 IA-8 — Identification and Authentication (non-organizational /
// federated users).
//
// The prior test asserted only that the literal substring "doc.Issuer" appears
// in oidc.go. This one drives the real OIDCProvider against a loopback OIDC
// issuer: discovery -> authorize URL (PKCE S256) -> code exchange -> userinfo,
// yielding the federated subject/email; and it proves the issuer binding is
// actually enforced (a mismatched issuer in the discovery document is rejected),
// which is the real check the substring stood in for.
// -----------------------------------------------------------------------------

// fakeOIDCIssuer serves a minimal OIDC issuer over loopback http (which the
// provider's fetchableEndpoint accepts). issuerOverride forces an issuer
// mismatch in the discovery document when non-empty.
func fakeOIDCIssuer(t *testing.T, issuerOverride string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	issuer := srv.URL
	if issuerOverride != "" {
		issuer = issuerOverride
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "federated-at-1", "id_token": "idt-1", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer federated-at-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub": "idp-subject-42", "email": "federated@partner.example", "email_verified": true, "name": "Partner User",
		})
	})
	return srv
}

func TestNIST_IA_8_FederatedIdentityAuthenticatedThroughOIDCFlow(t *testing.T) {
	srv := fakeOIDCIssuer(t, "")
	p := oauth2.NewOIDCProvider("okta", srv.URL, "client-id", "client-secret", "https://app.example/cb", "")

	// Authorize URL must carry a PKCE S256 challenge and the state/nonce.
	authURL := p.AuthURL("state-abc", "nonce-xyz", "challenge-1")
	if authURL == "" {
		t.Fatal("IA-8: AuthURL empty; OIDC discovery failed against the issuer")
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("IA-8: authorize URL unparseable: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != "challenge-1" {
		t.Errorf("IA-8: authorize request lacks PKCE S256 (method=%q challenge=%q)", q.Get("code_challenge_method"), q.Get("code_challenge"))
	}
	if q.Get("state") != "state-abc" || q.Get("nonce") != "nonce-xyz" {
		t.Errorf("IA-8: authorize request lost state/nonce (state=%q nonce=%q)", q.Get("state"), q.Get("nonce"))
	}

	// Exchange the code, then resolve the federated identity via userinfo.
	tok, err := p.Exchange(context.Background(), "auth-code-1", "verifier-1")
	if err != nil {
		t.Fatalf("IA-8: code exchange failed: %v", err)
	}
	if tok.AccessToken != "federated-at-1" {
		t.Fatalf("IA-8: unexpected token from exchange: %+v", tok)
	}

	info, err := p.UserInfo(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("IA-8: userinfo failed: %v", err)
	}
	if info.ID != "idp-subject-42" || info.Email != "federated@partner.example" || !info.EmailVerified {
		t.Fatalf("IA-8: federated identity not resolved correctly: %+v", info)
	}
	if info.Provider != "okta" {
		t.Errorf("IA-8: identity not attributed to the federating provider: Provider=%q", info.Provider)
	}
}

func TestNIST_IA_8_MismatchedIssuerRejected(t *testing.T) {
	// A discovery document whose issuer claim does not match the configured
	// issuer must be rejected (OIDC §3.1.3.7): otherwise a rogue endpoint could
	// impersonate the trusted IdP and authenticate arbitrary subjects.
	srv := fakeOIDCIssuer(t, "https://attacker.example")
	p := oauth2.NewOIDCProvider("okta", srv.URL, "client-id", "client-secret", "https://app.example/cb", "")

	if _, err := p.Exchange(context.Background(), "auth-code-1", "verifier-1"); err == nil {
		t.Fatal("IA-8: exchange succeeded despite issuer mismatch; the issuer binding is not enforced")
	}
	if got := p.AuthURL("s", "n", "c"); got != "" {
		t.Errorf("IA-8: AuthURL non-empty (%q) despite issuer mismatch; discovery accepted an untrusted issuer", got)
	}
}

// -----------------------------------------------------------------------------
// OWASP Top 10 A07:2025 — Identification and Authentication Failures
// (breached-credential check).
//
// The prior test (TestNIST_HIBPBreachCheck) recomputed the SHA-1 and reimplemented
// the k-anonymity prefix/suffix split and matching loop INLINE, asserting nothing
// about the shipped client. This one drives the real service.HIBPClient.IsBreached:
// the client's Transport is nil, so it uses http.DefaultTransport, which we swap
// for a RoundTripper that stubs only the pwnedpasswords socket. The shipped code
// still does its own hashing, prefix/suffix split, GET, and constant-time suffix
// match — we only observe the request and feed the response.
// -----------------------------------------------------------------------------

// pwnedRoundTripper stubs the pwnedpasswords range API and records the outbound
// request. Any other host falls through to the original transport.
type pwnedRoundTripper struct {
	base        http.RoundTripper
	status      int
	body        string
	netErr      bool
	capturedURL string
}

func (rt *pwnedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.pwnedpasswords.com" {
		return rt.base.RoundTrip(req)
	}
	rt.capturedURL = req.URL.String()
	if rt.netErr {
		return nil, fmt.Errorf("simulated HIBP outage")
	}
	return &http.Response{
		StatusCode: rt.status,
		Body:       io.NopCloser(strings.NewReader(rt.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestOWASP_A07_2025_ShippedHIBPClientDetectsBreachViaKAnonymity(t *testing.T) {
	const breached = "hunter2-breached-sample"
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(breached))) // #nosec G401 -- mirrors HIBP's mandated SHA-1 to build the stub response
	prefix, suffix := hash[:5], hash[5:]

	saved := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = saved })

	// Breached: the range response for the prefix contains the password's suffix.
	rt := &pwnedRoundTripper{
		base:   saved,
		status: http.StatusOK,
		body:   fmt.Sprintf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:9\r\n%s:1337\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\r\n", suffix),
	}
	http.DefaultTransport = rt

	client := service.NewHIBPClient()
	if !client.IsBreached(breached) {
		t.Fatal("A07:2025: shipped HIBPClient did not flag a password whose suffix is in the range response")
	}

	// k-anonymity: only the 5-char prefix leaves the process; never the suffix.
	if rt.capturedURL == "" {
		t.Fatal("A07:2025: no request reached the pwnedpasswords range API")
	}
	if !strings.HasSuffix(rt.capturedURL, "/range/"+prefix) {
		t.Errorf("A07:2025: request %q did not send exactly the 5-char prefix /range/%s", rt.capturedURL, prefix)
	}
	if strings.Contains(rt.capturedURL, suffix) || strings.Contains(rt.capturedURL, hash) {
		t.Errorf("A07:2025: k-anonymity violated — the suffix/full hash leaked into %q", rt.capturedURL)
	}

	// Clean: same prefix, response lacks the suffix -> not breached.
	rtClean := &pwnedRoundTripper{
		base:   saved,
		status: http.StatusOK,
		body:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:9\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\r\n",
	}
	http.DefaultTransport = rtClean
	if service.NewHIBPClient().IsBreached(breached) {
		t.Error("A07:2025: shipped HIBPClient flagged a password whose suffix is absent from the range response")
	}

	// Fail-open: an unreachable HIBP must not block registration.
	rtDown := &pwnedRoundTripper{base: saved, netErr: true}
	http.DefaultTransport = rtDown
	if service.NewHIBPClient().IsBreached(breached) {
		t.Error("A07:2025: shipped HIBPClient did not fail open when the range API was unreachable")
	}
}
