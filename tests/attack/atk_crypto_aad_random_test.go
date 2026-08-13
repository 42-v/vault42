package attack

import (
	"bytes"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// One master key encrypts TOTP secrets, identity documents, service documents,
// user blobs, admin TOTP secrets and the signing keys at rest. The only thing
// keeping those domains apart is the AAD each call site passes, so these tests
// treat the AAD scheme itself as the attack surface.

// A census of every AES-GCM call site outside tests, built from the AST so it
// cannot go stale. The invariant: every Encrypt and Decrypt passes an AAD.
//
// It holds in ten of eleven places. internal/crypto/recovery.go is the
// exception, and it is the subject of
// TestRecoveryAttack_EscrowPayloadIsNotBoundToItsRow. This test is the drift
// gate: if a twelfth call site appears without an AAD, it fails here rather
// than being noticed in review.
func TestAADAttack_EveryAEADCallSiteBindsContext(t *testing.T) {
	type site struct {
		file string
		line int
		fn   string
		args int
	}
	var sites []site

	roots := []string{
		filepath.Join("..", "..", "internal", "service"),
		filepath.Join("..", "..", "internal", "handler"),
		filepath.Join("..", "..", "internal", "keystore"),
		filepath.Join("..", "..", "internal", "kms"),
		filepath.Join("..", "..", "internal", "adminapi"),
		filepath.Join("..", "..", "internal", "crypto"),
	}

	for _, root := range roots {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, root, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", root, err)
		}
		for _, pkg := range pkgs {
			for name, file := range pkg.Files {
				ast.Inspect(file, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}

					// Two shapes reach the same two functions: a qualified call
					// from another package, and a bare call from inside
					// internal/crypto itself. recovery.go uses the bare form,
					// which is exactly the call site this census exists to
					// catch, so missing it would defeat the test.
					var fnName string
					switch fn := call.Fun.(type) {
					case *ast.SelectorExpr:
						pkgIdent, ok := fn.X.(*ast.Ident)
						if !ok || (pkgIdent.Name != "vaultcrypto" && pkgIdent.Name != "crypto") {
							return true
						}
						fnName = fn.Sel.Name
					case *ast.Ident:
						fnName = fn.Name
					default:
						return true
					}
					if fnName != "Encrypt" && fnName != "Decrypt" {
						return true
					}

					sites = append(sites, site{
						file: filepath.Join(filepath.Base(root), filepath.Base(name)),
						line: fset.Position(call.Pos()).Line,
						fn:   fnName,
						args: len(call.Args),
					})
					return true
				})
			}
		}
	}

	if len(sites) < 10 {
		t.Fatalf("found only %d AEAD call sites; the AST walk is broken, not the code", len(sites))
	}

	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		return sites[i].line < sites[j].line
	})

	var unbound []string
	for _, s := range sites {
		bound := "AAD"
		if s.args < 3 {
			bound = "NO AAD"
			unbound = append(unbound, s.file)
		}
		t.Logf("%-28s:%-4d %-8s %s", s.file, s.line, s.fn, bound)
	}

	// recovery.go is the known exception and is reported separately. Anything
	// else appearing here is new.
	for _, u := range unbound {
		if !strings.HasSuffix(u, "recovery.go") {
			t.Errorf("%s calls AES-GCM with no AAD: the ciphertext is not bound to the "+
				"row it lives in and can be moved between records under the same master key", u)
		}
	}
	if len(unbound) == 0 {
		t.Error("no unbound call site found; if recovery.go was fixed, delete that finding")
	}
}

// The blob AAD scheme is built by string concatenation, and the two namespaces
// it produces are not prefix-free:
//
//	internal/service/blob.go:128  dataAAD  = id + ":" + pseudo
//	internal/service/blob.go:139  labelAAD = "label:" + id + ":" + pseudo
//
// A blob whose id is "label:X" produces the same AAD string as the LABEL of a
// blob whose id is "X", for the same owner. Under one master key that means a
// data ciphertext and a label ciphertext are interchangeable: the label of one
// row would decrypt as the body of another.
//
// This is NOT exploitable today and the report says so. blob.go:122 draws the
// id from vaultcrypto.RandomUUID, so it is always a hyphenated hex UUID and can
// never begin with "label:". The collision is a property of the construction,
// not of the deployment, and it survives only as long as nobody makes blob ids
// caller-supplied or human-readable.
//
// The test proves the collision at the layer where it exists, and separately
// proves the id format is what closes it.
func TestAADAttack_BlobLabelAndDataNamespacesCollide(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	const pseudo = "pseudonym-of-the-owner"

	dataAAD := func(id string) []byte { return []byte(id + ":" + pseudo) }
	labelAAD := func(id string) []byte { return []byte("label:" + id + ":" + pseudo) }

	// The two AAD strings a collision needs.
	victimID := "X"
	craftedID := "label:" + victimID

	if !bytes.Equal(dataAAD(craftedID), labelAAD(victimID)) {
		t.Fatalf("no collision: %q vs %q", dataAAD(craftedID), labelAAD(victimID))
	}

	// Seal something as the BODY of the crafted blob.
	body := []byte("attacker-chosen blob body")
	ct, err := vaultcrypto.Encrypt(body, key, dataAAD(craftedID))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Open it as the LABEL of the victim's blob. Same key, same AAD, so GCM
	// cannot tell the two apart.
	got, err := vaultcrypto.Decrypt(ct, key, labelAAD(victimID))
	if err != nil {
		t.Fatalf("the namespaces do not actually collide: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("collision produced %q", got)
	}
	t.Logf("a body sealed under dataAAD(%q) opens as labelAAD(%q): the two AAD "+
		"namespaces are not prefix-free", craftedID, victimID)

	// What closes it in practice. If this ever stops holding, the collision
	// above becomes reachable.
	id, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("RandomUUID: %v", err)
	}
	if strings.Contains(id, ":") || strings.HasPrefix(id, "label") {
		t.Errorf("blob ids can now contain the AAD separator (%q), so the label/data "+
			"collision is reachable", id)
	}
	t.Logf("blob ids are server-generated UUIDs (%s), which cannot carry the "+
		"separator, so the collision is unreachable today", id)

	// The service-document scheme is the one to copy: a fixed "svcdoc:" prefix
	// plus fields whose shapes are validated, so no field can impersonate a
	// separator boundary.
	t.Log("internal/service/servicedoc.go docAAD prefixes its namespace and validates " +
		"every component, which is the shape blob.go should adopt")
}

// Randomness census. Every token, secret and identifier in the product is drawn
// from one of four helpers, all of which read crypto/rand; the risk is not the
// source but the LENGTH each call site asks for. The two short ones are
// deliberate and bounded elsewhere, and this test records why so the report can
// state it rather than guess.
func TestRandomAttack_TokenLengthCensus(t *testing.T) {
	type draw struct {
		file  string
		line  int
		fn    string
		bytes string
	}
	var draws []draw

	roots := []string{
		filepath.Join("..", "..", "internal"),
	}

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err //nolint:wrapcheck // walk callback
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr //nolint:wrapcheck // walk callback
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "RandomBytes", "RandomHex", "RandomToken":
				default:
					return true
				}
				arg := "?"
				if len(call.Args) == 1 {
					if lit, ok := call.Args[0].(*ast.BasicLit); ok {
						arg = lit.Value
					}
				}
				draws = append(draws, draw{
					file:  strings.TrimPrefix(path, filepath.Join("..", "..")+string(filepath.Separator)),
					line:  fset.Position(call.Pos()).Line,
					fn:    sel.Sel.Name,
					bytes: arg,
				})
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if len(draws) < 10 {
		t.Fatalf("found only %d random draws; the walk is broken", len(draws))
	}

	sort.Slice(draws, func(i, j int) bool { return draws[i].file < draws[j].file })

	// Anything below 16 bytes needs a reason. The two that qualify both have
	// one, and both are named here so a third would stand out.
	known := map[string]string{
		"internal/handler/backup_codes.go": "64-bit backup code, single use, argon2-hashed at rest, 10 per user",
		"internal/service/auth.go":         "6-digit email OTP; consumed by GetAndDelete on the first attempt, right or wrong",
	}

	var short []string
	for _, d := range draws {
		note := ""
		if d.bytes != "?" && len(d.bytes) <= 2 {
			n := 0
			for _, c := range d.bytes {
				n = n*10 + int(c-'0')
			}
			if n < 16 {
				note = "  <-- under 128 bits"
				if reason, ok := known[d.file]; ok {
					note += ": " + reason
				} else {
					short = append(short, d.file)
				}
			}
		}
		t.Logf("%-44s:%-5d %s(%s)%s", d.file, d.line, d.fn, d.bytes, note)
	}

	for _, s := range short {
		t.Errorf("%s draws fewer than 16 random bytes with no documented bound; "+
			"either raise it or record why the short value is safe", s)
	}
}

// The email OTP is the shortest secret in the product: four random bytes
// reduced mod 10^6. Modulo reduction of a uint32 is biased, and the bias is
// measured here rather than dismissed, because "it's only a 6-digit code" is
// how a real bias gets waved through.
//
// 2^32 = 4294967296 is not a multiple of 10^6, so codes below 967296 have one
// more preimage than the rest. The resulting skew is about 0.02 percent, which
// is nothing next to the 1-in-10^6 guess the single-shot GetAndDelete already
// caps. Recorded, not reported as a finding.
func TestRandomAttack_MeasureEmailOTPModuloBias(t *testing.T) {
	const (
		space   = 1 << 32
		modulus = 1000000
	)

	buckets := space / modulus   // preimages for the common case
	remainder := space % modulus // codes with one extra preimage
	heavy := float64(buckets+1) / space
	light := float64(buckets) / space
	skew := (heavy - light) / light

	t.Logf("2^32 / 10^6 = %d remainder %d", buckets, remainder)
	t.Logf("codes 0..%d have %d preimages; codes %d..999999 have %d",
		remainder-1, buckets+1, remainder, buckets)
	t.Logf("probability skew between the heaviest and lightest code: %.4f%%", skew*100)

	// A sanity check on the derivation, using the real reduction.
	counts := make(map[string]int)
	for i := 0; i < 100000; i++ {
		b, err := vaultcrypto.RandomBytes(4)
		if err != nil {
			t.Fatalf("RandomBytes: %v", err)
		}
		code := binary.BigEndian.Uint32(b) % modulus
		if code < 10 {
			counts["low"]++
		}
	}
	t.Logf("empirical: %d of 100000 draws landed in the lowest 10 codes (expected ~1)", counts["low"])

	if skew > 0.001 {
		t.Errorf("modulo bias is %.4f%%, large enough to matter", skew*100)
	}
}

// The kid published in JWKS and stamped into every JWT header is a 64-bit
// truncation of SHA-256 over the modulus alone:
//
//	internal/crypto/jwt.go:86  h := sha256.Sum256(pub.N.Bytes())
//	                           s := hex.EncodeToString(h[:8])
//
// Two consequences, both proven below. The exponent is not covered, so two keys
// that share a modulus and differ only in e collide; and 64 bits is a short
// identifier for a value that keys an upsert (keystore Import uses
// ON CONFLICT (kid) DO UPDATE, which overwrites the colliding row's key
// material).
//
// Neither is reachable without the ability to import a chosen signing key,
// which is an admin action, and finding a second preimage against a target kid
// is 2^64 keygens. Reported as robustness, not as a break.
func TestKIDAttack_ExponentIsNotCovered(t *testing.T) {
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	original := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

	// Same modulus, different public exponent. A degenerate key, but a
	// well-formed *rsa.PublicKey, and the kid does not change.
	variant := key.PublicKey
	variant.E = 3
	if key.PublicKey.E == 3 {
		variant.E = 65537
	}
	variantKID := vaultcrypto.KIDFromPublicKey(&variant)

	t.Logf("e=%d -> kid %s", key.PublicKey.E, original)
	t.Logf("e=%d -> kid %s", variant.E, variantKID)

	if original != variantKID {
		t.Log("the exponent is covered after all; this finding does not apply")
		return
	}
	t.Errorf("two public keys differing in their exponent share the kid %s. The kid is "+
		"SHA-256 over pub.N.Bytes() only (internal/crypto/jwt.go:87), so it does not "+
		"uniquely identify a key. keystore.Import upserts ON CONFLICT (kid), so importing "+
		"the second key would overwrite the first key's stored private material, and JWKS "+
		"would publish one of them under an identifier the other also claims.", original)
}

// Kid length, stated as a number. 64 bits is a 2^32 birthday bound for an
// accidental collision across all keys ever generated by all deployments, and
// 2^64 for a targeted one. Fine for an identifier, thin for something that keys
// a destructive upsert.
func TestKIDAttack_MeasureIdentifierWidth(t *testing.T) {
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	kid := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

	hexChars := strings.ReplaceAll(kid, "-", "")
	bits := len(hexChars) * 4
	t.Logf("kid %q: %d hex characters, %d bits of SHA-256", kid, len(hexChars), bits)
	t.Logf("accidental collision at ~2^%d keys; targeted second preimage at ~2^%d", bits/2, bits)

	if bits < 64 {
		t.Errorf("kid is only %d bits wide", bits)
	}
}
