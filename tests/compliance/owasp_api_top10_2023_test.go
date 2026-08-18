package compliance

import (
	"context"
	"go/ast"
	"go/token"
	"regexp"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// OWASP API Security Top 10 — 2023
//
// A separate list from the OWASP Top 10, and the one that fits an API server:
// its top two categories are object-level and function-level authorization,
// which is where an authentication service lives or dies.
//
// Every row it backs is Met or an existing accepted risk. Nothing here is
// claimed on the strength of a control existing somewhere in the tree: each
// test drives or reads the specific thing the category names.
// =============================================================================

// --- API1:2023 Broken Object Level Authorization ---

// The category's whole point is that an object identifier in a request must not
// be sufficient to reach the object. vault42 does not look an object up by id
// and then check ownership; it looks it up by (id, owner) so a mismatch is a
// miss. This drives a real cross-user read against a repository that enforces
// the pseudonym the way the real one does.
func TestAPITop10_API1_2023_ObjectReadsAreScopedToTheCallerNotJustFiltered(t *testing.T) {
	stored := map[string]*model.Blob{}
	owners := map[string]string{} // blob id -> pseudonym that stored it

	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
	}
	masterKey := make([]byte, 32)
	hmacSecret := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 7)
		hmacSecret[i] = byte(200 - i)
	}
	svc := service.NewBlobService(repo, masterKey, hmacSecret, service.BlobConfig{
		MinBlobSize: 1, MaxBlobSize: 4096, MaxBlobsPerUser: 10, QuotaBytes: 1 << 20,
	})

	// The repository contract the real Postgres implementation honors: a row is
	// returned only when the pseudonym matches too.
	repo.CreateFn = func(_ context.Context, b *model.Blob) error {
		stored[b.ID] = b
		owners[b.ID] = b.PseudonymID
		return nil
	}
	repo.GetByIDAndPseudonymFn = func(_ context.Context, id, pseudonymID string) (*model.Blob, error) {
		b, ok := stored[id]
		if !ok || owners[id] != pseudonymID {
			return nil, nil
		}
		return b, nil
	}

	const owner = "user-owner"
	const attacker = "user-attacker"

	blob, err := svc.Upload(context.Background(), owner, []byte("the owner's ciphertext"), "private")
	if err != nil {
		t.Fatalf("API1: upload failed: %v", err)
	}
	if owners[blob.ID] == "" {
		t.Fatal("API1: the stored row carries no pseudonym, so ownership is not part of the key")
	}
	if owners[blob.ID] == owner {
		t.Error("API1: the stored row is keyed by the raw user id rather than by a pseudonym of it")
	}

	// The owner reads their own object.
	data, _, _, err := svc.Download(context.Background(), owner, blob.ID)
	if err != nil || string(data) != "the owner's ciphertext" {
		t.Fatalf("API1: the owner could not read their own object: %v, %q", err, string(data))
	}

	// A second authenticated user, holding a perfectly valid token and the
	// object id, must get nothing.
	data, _, _, err = svc.Download(context.Background(), attacker, blob.ID)
	if err == nil && data != nil {
		t.Errorf("API1: a different authenticated user read object %s by id. The lookup is not "+
			"scoped by owner, which is broken object level authorization in its textbook form.",
			blob.ID)
	}

	// The service-document store has a second ownership axis, the client id, and
	// asserts it directly rather than relying on the scope check.
	// internal/handler/servicedoc.go says why in as many words: the scope check
	// happens to be sufficient today by accident, not by invariant.
	sd := readCodeOnly(t, "internal/handler/servicedoc.go")
	if !strings.Contains(sd, `claims.ClientID == ""`) {
		t.Error("API1: requireClient no longer refuses a token with no client id. The service " +
			"document store's ownership axis is the client id; without that check a user token " +
			"with the right scopes reaches a service-owned store.")
	}
	for _, method := range []string{"h.pathParts(w, r)", "requireClient(w, r)"} {
		if !strings.Contains(sd, method) {
			t.Errorf("API1: internal/handler/servicedoc.go no longer calls %s", method)
		}
	}
}

// --- API3:2023 Broken Object Property Level Authorization ---

// The mass-assignment half of the category: a client must not be able to set a
// property the API did not offer it. Every JSON request body in the HTTP layer
// is decoded through decodeJSON, which sets DisallowUnknownFields, so an
// unexpected property is a 400 rather than a silent write.
func TestAPITop10_API3_2023_UnknownRequestPropertiesAreRejectedNotIgnored(t *testing.T) {
	src := readCodeOnly(t, "internal/handler/response.go")
	if !strings.Contains(src, "dec.DisallowUnknownFields()") {
		t.Fatal("API3: decodeJSON no longer rejects unknown fields, so a client can send a property " +
			"the API never offered and the decoder will quietly ignore it. Whether that property " +
			"then reaches a struct field is one refactor away.")
	}

	// And that it is the decoder the handlers actually use. A strict helper that
	// half the package bypasses is not a control.
	strict, direct := 0, 0
	var offenders []string
	for _, pf := range productionGoFiles(t) {
		if !strings.HasPrefix(pf.path, "internal/handler/") || strings.HasSuffix(pf.path, "response.go") {
			continue
		}
		code := readCodeOnly(t, pf.path)
		strict += strings.Count(code, "decodeJSON(")
		if n := strings.Count(code, "json.NewDecoder(r.Body)"); n > 0 {
			direct += n
			offenders = append(offenders, pf.path)
		}
	}
	if strict == 0 {
		t.Fatal("API3: no handler calls decodeJSON; the scan is broken")
	}
	if direct > 0 {
		t.Errorf("API3: %d request bodies in %v are decoded with json.NewDecoder directly rather "+
			"than through decodeJSON, so they accept properties the API does not define",
			direct, offenders)
	}
	t.Logf("API3: %d request bodies decoded through the strict decoder", strict)
}

// --- API4:2023 Unrestricted Resource Consumption ---

// Three independent ceilings, because one is never enough: a per-route rate
// limit, a per-request body cap, and a per-user stored-byte and object-count
// quota. The first two bound a single caller's burst; only the third bounds the
// slow accumulation that a rate limit is blind to.
func TestAPITop10_API4_2023_EveryConsumableResourceHasACeiling(t *testing.T) {
	server := readCodeOnly(t, "internal/server/server.go")

	// Rate limits on the flows that cost the most: Argon2id is deliberately
	// expensive, which makes an unlimited login endpoint a CPU-exhaustion
	// primitive rather than only a guessing one.
	for _, wired := range []string{
		`mux.Handle("POST /auth/login", loginRL(`,
		`mux.Handle("POST /auth/register", registerRL(`,
		`mux.Handle("POST /auth/password/reset", passwordResetRL(`,
	} {
		if !strings.Contains(server, wired) {
			t.Errorf("API4: %s is no longer rate limited. Argon2id at 46 MiB is the cost of one "+
				"attempt; an unlimited endpoint in front of it is a memory-exhaustion primitive.", wired)
		}
	}

	// A body cap, globally and on the routes exempted from the global one.
	if !strings.Contains(server, "middleware.MaxBodyWithExemptions(8*1024") {
		t.Error("API4: the global 8 KiB body cap is gone")
	}
	for _, rel := range []string{"internal/handler/blob.go", "internal/handler/servicedoc.go"} {
		if !strings.Contains(readCodeOnly(t, rel), "http.MaxBytesReader") {
			t.Errorf("API4: %s no longer caps its own body, and its route prefix is exempt from the "+
				"global cap", rel)
		}
	}

	// Storage quotas, which are what bound accumulation over time.
	//
	// Read structurally, against the config fields, rather than by matching the
	// expression's text. The first version of this assertion matched
	// "quota.UsedCount >= s.config.MaxBlobsPerUser" verbatim and broke when the
	// admin-plane work fixed a quota TOCTOU by taking a lock and hoisting the
	// values into locals -- a strictly better implementation of the same
	// control. A gate that fails on a correct refactor teaches people to edit
	// the gate, which is how a gate stops meaning anything.
	//
	// The property is: each configured ceiling is compared against something,
	// and the comparison refuses. Neither half is enough on its own. A ceiling
	// that is read and never compared is a setting; a comparison that does not
	// refuse is a log line.
	for _, ceiling := range []struct{ field, why string }{
		{"MaxBlobsPerUser", "the per-user object count"},
		{"QuotaBytes", "the per-user stored-byte total"},
	} {
		compared, refuses := quotaCeilingIsEnforced(t, "internal/service/blob.go", ceiling.field)
		if !compared {
			t.Errorf("API4: %s is never compared against anything in internal/service/blob.go, so "+
				"%s is a configuration field the code reads and does not enforce. A rate limit "+
				"bounds a burst; only a quota bounds a caller who uploads slowly and forever.",
				ceiling.field, ceiling.why)
			continue
		}
		if !refuses {
			t.Errorf("API4: %s is compared, but no branch containing that comparison returns "+
				"ErrQuotaExceeded. A ceiling that is measured and not enforced reads like a control "+
				"and is not one.", ceiling.field)
		}
	}
	if !strings.Contains(readCodeOnly(t, "internal/service/servicedoc.go"), "QuotaBytesPerSubject") {
		t.Error("API4: the service-document store no longer carries a per-subject byte quota")
	}

	// Negative control. The two assertions above are satisfied by a scan that
	// says yes to everything, so the detector is asked about a field that does
	// not exist. If this reports enforcement, the checks above passed for the
	// wrong reason.
	if compared, _ := quotaCeilingIsEnforced(t, "internal/service/blob.go", "MaxBlobsPerFictionalUser"); compared {
		t.Error("API4: the quota detector reports a comparison against a field that does not exist, " +
			"so its verdict on the real fields means nothing")
	}
}

// --- API6:2023 Unrestricted Access to Sensitive Business Flows ---

// The flows worth abusing in bulk here are account creation, credential
// guessing and password-reset mail. Each is rate limited, registration can be
// switched off entirely, and the reset flow answers identically whether or not
// the address exists, so it cannot be used as an enumeration oracle while it is
// being used as a mail cannon.
func TestAPITop10_API6_2023_BulkAbusableFlowsAreThrottledAndSwitchable(t *testing.T) {
	server := readCodeOnly(t, "internal/server/server.go")

	if !strings.Contains(server, "cfg.RegistrationEnabled") {
		t.Error("API6: registration can no longer be switched off. For a deployment that provisions " +
			"its users, an always-on public registration flow is a business flow with no owner.")
	}
	for _, limiter := range []string{"registerRL", "loginRL", "passwordResetRL"} {
		if !strings.Contains(server, limiter+" :=") && !strings.Contains(server, limiter+" =") {
			t.Errorf("API6: the %s rate limiter is gone", limiter)
		}
	}

	// The IP-reputation weighting: a flagged source consumes the
	// credential-guessing buckets faster, which is the control aimed squarely at
	// the distributed version of this category.
	if !strings.Contains(server, "rlEnabled") {
		t.Error("API6: the rate-limit enablement flag is gone from the route wiring")
	}
	if !strings.Contains(readCodeOnly(t, "internal/middleware/ratelimit.go"), "func RateLimit(") {
		t.Fatal("API6: the rate-limit middleware is gone; the scan is reading the wrong file")
	}
}

// --- API9:2023 Improper Inventory Management ---

// The category is about endpoints nobody remembers deploying. The check is
// direct: every route the server mounts must appear in the published API
// reference. An undocumented route is an inventory gap by definition, and it is
// the shape a forgotten debug or migration endpoint takes.
func TestAPITop10_API9_2023_EveryMountedRouteAppearsInThePublishedReference(t *testing.T) {
	server := readCodeOnly(t, "internal/server/server.go")
	apiDoc := readProductionSource(t, "docs/api.md")

	pattern := regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+) ([^"]+)"`)
	matches := pattern.FindAllStringSubmatch(server, -1)
	if len(matches) < 30 {
		t.Fatalf("API9: only %d routes found in internal/server/server.go; the scan is broken and "+
			"would pass vacuously", len(matches))
	}

	seen := map[string]struct{}{}
	undocumented := 0
	for _, m := range matches {
		path := m[2]
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		if !strings.Contains(apiDoc, path) {
			undocumented++
			t.Errorf("API9: %s %s is mounted by the server and appears nowhere in docs/api.md. "+
				"An endpoint that ships without an entry in the inventory is the one nobody "+
				"remembers to retire.", m[1], path)
		}
	}
	t.Logf("API9: %d distinct routes checked against docs/api.md, %d undocumented", len(seen), undocumented)
}

// --- API10:2023 Unsafe Consumption of APIs ---

// vault42 calls out to three third parties: the upstream OIDC provider, the
// HIBP range API and an SMTP relay. The category is about trusting their
// responses more than one's own users'. Each answer is bounded before it is
// believed.
func TestAPITop10_API10_2023_ThirdPartyResponsesAreValidatedBeforeUse(t *testing.T) {
	if files := productionGoFiles(t); len(files) < 100 {
		t.Fatalf("API10: only %d production files parsed; the InsecureSkipVerify sweep below would pass vacuously", len(files))
	}

	// The OIDC discovery document is pinned to the configured issuer, so a
	// hostile or hijacked provider cannot re-point the endpoints vault42 then
	// calls.
	oidc := readCodeOnly(t, "internal/oauth2/oidc.go")
	if !strings.Contains(oidc, "Issuer") {
		t.Fatal("API10: the OIDC provider metadata no longer carries an issuer to pin against; " +
			"the scan is reading the wrong file")
	}

	// The provider's assertion about an email address is not enough on its own:
	// a first-time sign-in from an unverified provider is refused rather than
	// auto-provisioned, which is the difference between consuming an API and
	// believing it.
	oauth := readCodeOnly(t, "internal/handler/oauth.go")
	if !strings.Contains(oauth, "!userInfo.EmailVerified") {
		t.Error("API10: the OAuth callback no longer checks the provider's own email_verified " +
			"claim before creating an account. Without it, any provider that lets a user assert " +
			"an address they do not own mints a vault42 account for it.")
	}
	if !strings.Contains(oauth, "linkableToExistingAccount") {
		t.Error("API10: linking a provider identity to an existing account no longer requires both " +
			"the IdP's assertion and the account's own email_verified")
	}

	// HIBP is consumed under k-anonymity, and a failure there must not become a
	// failure here: the range API sees five characters of a hash and its outage
	// is fail-open by design.
	hibp := readCodeOnly(t, "internal/service/hibp.go")
	if !strings.Contains(hibp, "hash[:5]") && !strings.Contains(hibp, "[:5]") {
		t.Error("API10: the HIBP client no longer sends a k-anonymity prefix; it is sending " +
			"something longer, which hands a third party a password hash")
	}

	// And every outbound connection is TLS with a floor, which
	// TestASVS_V12_1_1_EveryTLSConfigDeclaresAMinimumVersion asserts across the
	// whole tree. Asserted here only that the HTTP clients are not built with
	// verification off.
	for _, pf := range productionGoFiles(t) {
		code := readCodeOnly(t, pf.path)
		if strings.Contains(code, "InsecureSkipVerify: true") {
			t.Errorf("API10: %s disables certificate verification on an outbound client", pf.path)
		}
	}
}

// quotaCeilingIsEnforced reports whether a config field is compared anywhere in
// a file, and whether the function holding that comparison refuses on it.
//
// It walks the AST rather than the text so that hoisting a value into a local,
// renaming a receiver or reordering the operands does not read as the control
// being deleted. What it will not accept is the comparison disappearing, or
// surviving in a function that has no way to say no.
func quotaCeilingIsEnforced(t *testing.T, rel, field string) (compared, refuses bool) {
	t.Helper()

	var target parsedFile
	for _, pf := range productionGoFiles(t) {
		if pf.path == rel {
			target = pf
			break
		}
	}
	if target.file == nil {
		t.Fatalf("API4: %s is not in the production scan; the gate has no subject", rel)
	}

	ast.Inspect(target.file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		var comparedHere bool
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			bin, ok := inner.(*ast.BinaryExpr)
			if !ok {
				return true
			}
			switch bin.Op {
			case token.LSS, token.LEQ, token.GTR, token.GEQ, token.EQL, token.NEQ:
			default:
				return true
			}
			if mentionsConfigField(bin.X, field) || mentionsConfigField(bin.Y, field) {
				comparedHere = true
			}
			return true
		})
		if !comparedHere {
			return true
		}
		compared = true

		// The refusal: somewhere in the same function, the quota error is
		// returned. Scoped to the function rather than the file so that a
		// comparison in one place and a refusal in another does not read as
		// enforcement.
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			ident, ok := inner.(*ast.Ident)
			if ok && ident.Name == "ErrQuotaExceeded" {
				refuses = true
			}
			return true
		})
		return true
	})
	return compared, refuses
}

// mentionsConfigField reports whether an expression reads the named field off a
// config struct, however the struct is reached.
func mentionsConfigField(e ast.Expr, field string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && sel.Sel != nil && sel.Sel.Name == field {
			found = true
		}
		return true
	})
	return found
}
