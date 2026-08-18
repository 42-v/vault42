package compliance

import (
	"strings"
	"testing"
)

// =============================================================================
// "Not Applicable because it does not exist" — the assertion under the claim.
//
// Sixty of the register's sixty-three Not Applicable rows justify themselves
// with a negative existence claim: no LDAP client, no XML parser, no WebSocket
// channel, no WebRTC, no SAML, no file uploads, no browser-facing application.
// Not one of them named a test.
//
// That asymmetry is how twenty-one rows were misclassified. A Met row has to
// name a test that CI runs, so a Met row cannot quietly become false. An N/A
// row asserting non-existence had no such obligation, so three sentences —
// written once, copied across three chapters — removed twenty-one requirements
// from the denominator, and two real gaps with them. The two that were hiding
// (ASVS V3.4.3 and V3.5.3) were neither Met nor accepted, while the report's
// closing line said there were no standing gaps.
//
// A negative existence claim is exactly as testable as a positive one, and
// usually more cheaply: it is a scan for something that must not be there. This
// file is that scan. TestComplianceRegister_NotApplicableNonExistenceClaimsName
// AnExistingTest is the gate that forces every future such row through it.
// =============================================================================

// absentTechnology is a capability the register asserts vault42 does not have,
// paired with the tokens that would appear in the shipped source if it did.
type absentTechnology struct {
	label       string
	rows        string   // the register rows that rest on this absence
	markers     []string // case-insensitive substrings of shipped Go source
	consequence string   // what the register would be wrong about
}

var absentTechnologies = []absentTechnology{
	{
		label:       "operating-system command execution",
		rows:        "ASVS V1.2.5",
		markers:     []string{"os/exec", "exec.Command", "exec.CommandContext", "syscall.Exec", "syscall.ForkExec"},
		consequence: "the OS command injection row would need a real argument instead of an absence",
	},
	{
		label:       "LDAP or directory integration",
		rows:        "ASVS V1.2.6, V1.3.8",
		markers:     []string{"ldap", "jndi"},
		consequence: "the LDAP injection and JNDI rows would apply, and JNDI is the Log4Shell vector",
	},
	{
		label:       "XML or XPath processing",
		rows:        "ASVS V1.2.7, V1.5.1",
		markers:     []string{"encoding/xml", "xml.Unmarshal", "xml.NewDecoder", "xpath", "libxml"},
		consequence: "XXE and XPath injection would become live requirements",
	},
	{
		label:       "document rendering (LaTeX and friends)",
		rows:        "ASVS V1.2.8",
		markers:     []string{"latex", "pdflatex", "ghostscript", "libreoffice", "wkhtmltopdf"},
		consequence: "the document-generation injection row would apply",
	},
	{
		label:       "memcache",
		rows:        "ASVS V1.3.9",
		markers:     []string{"memcache"},
		consequence: "memcache injection would apply; the cache layer is Redis or in-process",
	},
	{
		label:       "GraphQL or another query language over HTTP",
		rows:        "ASVS V4.3.1, V4.3.2",
		markers:     []string{"graphql", "gqlgen", "graphiql"},
		consequence: "query-depth limiting and introspection disabling would both become requirements",
	},
	{
		label:       "WebSocket channels",
		rows:        "ASVS V4.4.1, V4.4.2, V4.4.3, V4.4.4",
		markers:     []string{"websocket", "websocket.Upgrader", "sec-websocket", "wss://"},
		consequence: "four WebSocket rows — WSS, Origin validation on the handshake, and a dedicated channel token — would all apply",
	},
	{
		label:       "SAML federation",
		rows:        "ASVS V6.8.3",
		markers:     []string{"saml", "urn:oasis:names:tc:saml"},
		consequence: "SAML assertion signature and replay requirements would apply; federation is OAuth 2.0 and OIDC only",
	},
	{
		label:       "SMS or voice (PSTN) delivery",
		rows:        "ASVS V6.6.1, NIST SP 800-63B-4 restricted authenticators",
		markers:     []string{"twilio", "nexmo", "vonage", "plivo", "sinch", "messagebird"},
		consequence: "the PSTN out-of-band authenticator rows would apply, and Rev 4 restricts that channel",
	},
	{
		label:       "push-notification authentication",
		rows:        "ASVS V6.6.4",
		markers:     []string{"firebase", "apns", "gorush", "webpush", "onesignal"},
		consequence: "the push out-of-band factor rows would apply; the only out-of-band factor is an emailed code",
	},
	{
		label:       "WebRTC signaling, media or data channels",
		rows:        "ASVS V17.1.1, V17.2.1, V17.2.2, V17.2.3, V17.2.4, V17.3.1, V17.3.2",
		markers:     []string{"webrtc", "pion/", "rtcpeerconnection", "icecandidate", "stunserver", "datachannel"},
		consequence: "the whole of ASVS chapter V17, seven rows, would apply",
	},
	{
		label:       "biometric verification performed by vault42 itself",
		rows:        "ASVS V6.5.7, NIST SP 800-63B-4 3.2.3",
		markers:     []string{"faceid", "touchid", "biometrictemplate", "minutiae", "falsematchrate", "livenessdetection"},
		consequence: "the biometric false-match-rate and presentation-attack rows would apply; platform biometrics reach vault42 only as a WebAuthn user-verification flag",
	},
}

// TestASVS_AbsentTechnologiesAreActuallyAbsent scans the shipped Go source for
// every capability the register claims vault42 does not have.
//
// Comments are stripped before the scan: several of these words appear in the
// comment that explains why the thing is absent, and matching on that would be
// the wrong way round.
func TestASVS_AbsentTechnologiesAreActuallyAbsent(t *testing.T) {
	files := productionGoFiles(t)
	if len(files) < 50 {
		t.Fatalf("only %d production Go files parsed; the scan is broken and would pass vacuously", len(files))
	}

	// Read each file's code without its comments, once. Comments are dropped
	// because several of these words appear only in the comment explaining why
	// the capability is absent, and matching on that would be the wrong way
	// round.
	type rendered struct {
		path string
		code string
	}
	sources := make([]rendered, 0, len(files))
	for _, pf := range files {
		sources = append(sources, rendered{path: pf.path, code: strings.ToLower(readCodeOnly(t, pf.path))})
	}

	for _, tech := range absentTechnologies {
		for _, marker := range tech.markers {
			needle := strings.ToLower(marker)
			for _, src := range sources {
				if strings.Contains(src.code, needle) {
					t.Errorf("%s: the register says vault42 has no %s, but %s contains %q. "+
						"If this capability now exists, %s.",
						tech.rows, tech.label, src.path, marker, tech.consequence)
				}
			}
		}
	}

	// A negative control. If the scanner cannot find a token that is definitely
	// present, every assertion above passed for the wrong reason.
	var sawControl bool
	for _, src := range sources {
		if strings.Contains(src.code, "argon2") {
			sawControl = true
			break
		}
	}
	if !sawControl {
		t.Fatal("the scanner found no occurrence of \"argon2\" anywhere in the production tree, " +
			"which cannot be true: the scan is not reading what it thinks it is reading, and " +
			"every absence assertion above is vacuous")
	}
}

// TestASVS_AbsentEndpointsAreActuallyAbsent is the route half of the same idea.
//
// Four Not Applicable rows rest on vault42 not being an OpenID Provider or an
// authorization server for third-party clients: no dynamic client registration,
// no back-channel logout, no RP-initiated logout, no consent prompt. Those are
// claims about the route table, so the route table is what gets read.
func TestASVS_AbsentEndpointsAreActuallyAbsent(t *testing.T) {
	routes := strings.ToLower(readCodeOnly(t, "internal/server/server.go"))

	absent := map[string]string{
		"registration_endpoint": "ASVS V10.4.7: dynamic client registration (RFC 7591) is claimed absent; clients are provisioned by an operator",
		"backchannel_logout":    "ASVS V10.5.5: OIDC back-channel logout is claimed absent",
		"end_session":           "ASVS V10.6.2: RP-initiated logout is claimed absent",
		"/graphql":              "ASVS V4.3.1: no query language is exposed over HTTP",
		"/consent":              "ASVS V10.7.2: no consent prompt exists because there is no third-party delegation",
	}
	for token, why := range absent {
		if strings.Contains(routes, token) {
			t.Errorf("internal/server/server.go now mentions %q. %s — that row is no longer "+
				"Not Applicable and needs reclassifying.", token, why)
		}
	}

	// The discovery document is the other place a capability gets claimed. It
	// deliberately omits fields rather than faking them, and the omission is
	// what several rows rest on.
	wellknown := strings.ToLower(readCodeOnly(t, "internal/handler/wellknown.go"))
	for _, advertised := range []string{"registration_endpoint", "end_session_endpoint", "backchannel_logout_supported"} {
		if strings.Contains(wellknown, advertised) {
			t.Errorf("the discovery document advertises %q; a capability advertised to clients "+
				"cannot be Not Applicable in the register", advertised)
		}
	}

	// Negative control: the routes the scan reads really are in this file.
	if !strings.Contains(routes, "/auth/login") {
		t.Fatal("the route scan cannot see /auth/login, so its absence assertions are vacuous")
	}
	if !strings.Contains(wellknown, "issuer") {
		t.Fatal("the discovery scan cannot see the issuer field, so its assertions are vacuous")
	}
}

// TestASVS_V1_3_4_SVGIsRejectedRatherThanAbsent replaces an absence claim with
// the control that actually holds.
//
// The old reason was "No SVG is accepted or rendered". The stronger and truer
// statement is that the one place SVG could arrive — an admin-authored email
// template — rejects it, along with the rest of the active-content families.
func TestASVS_V1_3_4_SVGAndActiveContentAreRejectedInEmailTemplates(t *testing.T) {
	src := readCodeOnly(t, "internal/email/templates.go")

	for _, tag := range []string{"svg", "script", "iframe", "object", "embed", "form", "base", "link"} {
		if !strings.Contains(src, tag) {
			t.Errorf("V1.3.4: the email-template content validator no longer names <%s>. "+
				"That validator is the only thing standing between an admin-authored template "+
				"and active content in a mail body.", tag)
		}
	}
	if !strings.Contains(src, "javascript:") || !strings.Contains(src, "data:") {
		t.Error("V1.3.4: the validator no longer rejects javascript: or data: URIs")
	}
}
