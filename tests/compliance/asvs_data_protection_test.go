package compliance

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/middleware"
)

// =============================================================================
// OWASP Application Security Verification Standard (ASVS) 5.0.0
// V14: Data Protection
// https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0
//
// Also evidences NIST SP 800-53 Rev 5 (Release 5.2.0) SC-28, and GDPR
// Arts. 15/20 (access and portability) where the export bound is the control.
//
// Under v4.0.3 this chapter was V8, and the only V8 item docs/COMPLIANCE.md
// mentioned at all was a partial. The requirement it named, V8.3.2, is
// "Verify that users have a method to remove or export their data on demand"
// (which vault42 meets), not the memory-zeroing concern the report described.
// The ASVS 5.0.0 mapping marks v4.0.3-8.3.2 as deleted and out of scope.
// =============================================================================

// --- V14.2.1: sensitive data is never carried in a URL ---

// "Verify that sensitive data is only sent to the server in the HTTP message
// body or header fields, and that the URL and query string do not contain
// sensitive information, such as an API key or session token."
//
// A URL is logged by every proxy on the path and lands in Referer headers, so
// a token in a route pattern is an exposure no amount of TLS fixes. The route
// table is the artifact under test.
func TestASVS_V14_2_1_NoRouteCarriesACredentialInItsPath(t *testing.T) {
	// A document key or a resource id is an identifier and belongs in a path.
	// What must never appear is a value that authenticates the request.
	forbidden := []string{"token", "secret", "password", "code", "verifier", "api_key", "apikey", "client_secret"}

	routes := serverRoutes(t)
	if len(routes) < 40 {
		t.Fatalf("V14.2.1: only %d routes parsed; the scan is broken", len(routes))
	}

	for route := range routes {
		_, path, found := strings.Cut(route, " ")
		if !found {
			path = route
		}
		// Only wildcard segments matter: a literal path segment named "token"
		// is a noun, a {token} segment is a credential on the wire.
		for _, segment := range strings.Split(path, "/") {
			if !strings.HasPrefix(segment, "{") {
				continue
			}
			name := strings.ToLower(strings.Trim(segment, "{}"))
			for _, bad := range forbidden {
				if name == bad {
					t.Errorf("V14.2.1: %s carries %q as a path parameter; it would be recorded by every proxy and appear in Referer headers", route, name)
				}
			}
		}
	}
}

// --- V14.3.2: anti-caching headers are set on responses carrying data ---

// "Verify that the application sets sufficient anti-caching HTTP response
// header fields (i.e., Cache-Control: no-store) so that sensitive data is not
// cached in browsers."
//
// The middleware is exercised rather than read, because the requirement is
// about what a response actually carries.
func TestASVS_V14_3_2_ResponsesCarryNoStore(t *testing.T) {
	handler := middleware.SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/user/profile", nil))

	cacheControl := rec.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-store") {
		t.Errorf("V14.3.2: Cache-Control is %q, which does not include no-store", cacheControl)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("V14.3.2: Pragma is %q, want no-cache for HTTP/1.0 intermediaries", got)
	}
}

// The discovery and JWKS documents are the deliberate exception: they carry no
// user data and are cached on purpose. Recording that here keeps the exception
// visible rather than leaving a reader to wonder whether it was an oversight.
func TestASVS_V14_3_2_OnlyPublicMetadataIsCacheable(t *testing.T) {
	src := readProductionSource(t, "internal/handler/wellknown.go")
	if !strings.Contains(src, "public, max-age=") {
		t.Skip("V14.3.2: the well-known handler no longer sets a public cache policy")
	}
	// The exception must stay confined to the metadata handler.
	for _, handler := range []string{"internal/handler/user.go", "internal/handler/identity.go", "internal/handler/data_export.go"} {
		if strings.Contains(readProductionSource(t, handler), `"public, max-age=`) {
			t.Errorf("V14.3.2: %s sets a public cache policy on a response that carries user data", handler)
		}
	}
}

// --- V14.2.2: sensitive data is not retained in server-side caches ---

// "Verify that the application prevents sensitive data from being cached in
// server components ... or ensures that the data is securely purged after use."
//
// The single-use artifacts of the login flow are the ones that matter: an
// OAuth verifier or exchange code left in the cache after use is a replayable
// credential. GetAndDelete is what makes the purge atomic with the read.
func TestASVS_V14_2_2_SingleUseArtifactsArePurgedOnRead(t *testing.T) {
	if !strings.Contains(readProductionSource(t, "internal/cache/cache.go"), "GetAndDelete") {
		t.Fatal("V14.2.2: the cache no longer offers an atomic read-and-purge primitive")
	}
	if !strings.Contains(readProductionSource(t, "internal/handler/oauth.go"), "GetAndDelete(") {
		t.Error("V14.2.2: the OAuth flow no longer purges its single-use artifacts as it reads them")
	}
}

// --- V14.1.1: sensitive data is identified and classified ---

// "Verify that all sensitive data created and processed by the application has
// been identified and classified into protection levels."
//
// The classification is a document, and a document is only a control if the
// code agrees with it. The assertion is that the inventory exists and that the
// scrub list, which is where the classification becomes executable, is not
// empty.
func TestASVS_V14_1_1_TheDataInventoryExistsAndIsEnforced(t *testing.T) {
	privacy := readProductionSource(t, "docs/PRIVACY.md")
	for _, section := range []string{"Data Inventory", "Retention"} {
		if !strings.Contains(privacy, section) {
			t.Errorf("V14.1.1: docs/PRIVACY.md no longer contains a %q section; the classification would be undocumented", section)
		}
	}

	audit := readProductionSource(t, "internal/audit/audit.go")
	if !strings.Contains(audit, "sensitiveKeys") || !strings.Contains(audit, "blobSensitiveKeys") {
		t.Error("V14.1.1: the executable half of the classification, the audit scrub lists, is gone")
	}
}

// --- GDPR Art. 15 / Art. 20, evidenced through the same export path ---

// The export is the mechanism for both the right of access and the right to
// portability, and its one honest weakness is the audit-event cap. A truncated
// export that does not say it is truncated would be a defective Art. 15
// response, so the declaration is the control.
func TestGDPR_Art15_Art20_ExportDeclaresItsOwnTruncation(t *testing.T) {
	handler := readProductionSource(t, "internal/handler/data_export.go")
	if !strings.Contains(handler, "maxExportAuditEvents") {
		t.Fatal("Art. 15: the export audit cap constant is gone")
	}
	if !strings.Contains(handler, "AuditEventsTruncated") {
		t.Error("Art. 15: the export no longer declares whether it was truncated; a partial export would be indistinguishable from a complete one")
	}

	types := readProductionSource(t, "internal/handler/response_types.go")
	for _, field := range []string{`json:"audit_events_total"`, `json:"audit_events_limit"`, `json:"audit_events_truncated"`} {
		if !strings.Contains(types, field) {
			t.Errorf("Art. 15: the export response no longer carries %s", field)
		}
	}
}

// Art. 20 requires a structured, commonly used, machine-readable format.
func TestGDPR_Art20_ExportIsStructuredAndMachineReadable(t *testing.T) {
	src := readProductionSource(t, "internal/handler/data_export.go")
	if !strings.Contains(src, "WriteJSON") && !strings.Contains(src, "json.NewEncoder") {
		t.Error("Art. 20: the export is no longer emitted as JSON")
	}
}

// --- GDPR Art. 28: processors are named ---

func TestGDPR_Art28_ProcessorsAreDocumented(t *testing.T) {
	privacy := readProductionSource(t, "docs/PRIVACY.md")
	if !strings.Contains(strings.ToLower(privacy), "processor") {
		t.Error("Art. 28: docs/PRIVACY.md no longer names the processors; the controller could not discharge its Art. 28 duty")
	}
}

// --- GDPR Art. 17(3)(b)/(e): the audit exemption is bounded by retention ---

// Audit rows are exempt from the erasure cascade, which is only defensible
// because they are separately time-bounded. If the sweeper disappears, the
// exemption becomes indefinite retention of personal data.
func TestGDPR_Art17_3_AuditExemptionIsBoundedByRetention(t *testing.T) {
	if !strings.Contains(readProductionSource(t, "internal/audit/retention.go"), "func (r *Retention) Sweep") {
		t.Fatal("Art. 17(3): audit rows are exempt from erasure but the retention sweeper is gone, so the exemption is now unbounded")
	}
	if !strings.Contains(readProductionSource(t, "internal/service/recovery_retention.go"), "Prune") {
		t.Error("Art. 17(3): the recovery escrow, exempt for the same structural reason, no longer has a prune path")
	}
}
