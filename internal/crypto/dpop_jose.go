package crypto

import "errors"

// rejectDPoPJOSEHeaders applies the JOSE header rules a DPoP proof is subject
// to, before anything reads a key out of it.
//
// It exists because the jwt package puts these rejections in the Keyfunc, which
// is the only place that knows which keys a caller trusts, and
// ValidateDPoPProof's Keyfunc is a bare "return the key from the jwk header".
// So the two entry points into the parser had different header hygiene:
// ParseAndValidate refused kid-less tokens, jku, x5u, x5c, jwk and crit, and
// the DPoP path refused only a kid.
//
//   - kid is refused because RFC 9449 4.2 puts the proof's key in the jwk
//     header. A kid names a key from a set the recipient already holds, which
//     for a self-signed proof is a claim about vault42's own keystore.
//
//   - crit is refused because RFC 7515 4.1.11 makes it a MUST-reject for a
//     recipient that does not implement every extension it lists, and vault42
//     implements no JOSE extension at all. Whatever a crit names therefore
//     qualifies, including the empty array the RFC forbids outright and a value
//     that is not a list.
//
// The crit rule is the one that was missing, and the DPoP path is the reachable
// half of it. An access token's header is inside a signature made with
// vault42's signing key, so planting a crit there needs the key. A DPoP proof
// is self-signed with a key its sender invents in the same request, so its
// entire header is attacker-chosen at no cost. The cost of accepting it is the
// one the access-token rule already names: a gateway or relying party that
// honors crit refuses a proof vault42 called valid, and the two sides stop
// agreeing on what a valid proof is.
//
// jku, x5u and x5c are deliberately not listed. They point verification at a
// key the sender supplies, which is what a DPoP proof does by design through
// its jwk header. Refusing them would be decoration: the key this function
// guards is attacker-chosen either way, and the binding that matters is the
// RFC 7638 thumbprint of it.
func rejectDPoPJOSEHeaders(header map[string]any) error {
	if _, ok := header["kid"]; ok {
		return errors.New("dpop: kid header not allowed in DPoP proof")
	}
	if _, ok := header["crit"]; ok {
		return errors.New("dpop: rejected crit header, no JOSE extensions are implemented")
	}
	return nil
}
