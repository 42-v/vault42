package crypto

import "errors"

// dpopPrivateJWKMembers is the JWK private vocabulary: d for an EC key
// (RFC 7518 6.2.2), d, p, q, dp, dq, qi and oth for RSA (6.3.2), and k for an
// octet sequence (6.4).
//
// The whole list matters, not d alone. An RSA private key is spread across six
// members and any one of them is material a public key has no business
// carrying, so a check that knew only about d would pass a jwk that handed over
// p and q.
//
// It is a slice and not a map so the member named in the refusal is the same on
// every run. Go randomizes map iteration, so a jwk carrying two private members
// would be reported as a different one each time and an operator could not
// reconcile the log line with the client's bug report.
var dpopPrivateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

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

// jwkPrivateMember reports the first private member a header jwk carries, and
// whether it carried one at all.
//
// RFC 9449 4.3 step 7 requires a recipient to check that the jwk header does
// not contain a private key. parseJWKHeader reads the jwk into a struct holding
// only the public members, so a private one is read past in silence: it changes
// neither the signature check nor the thumbprint, and the proof validates. That
// is precisely why the refusal has to be written down rather than left to fall
// out of the parser. A client that ships its private key in a header has
// disclosed it to everything on the path, and what it needs back from an
// authorization server is a rejection, not a 200 that hides the disclosure
// until someone reads a packet capture.
func jwkPrivateMember(jwk map[string]any) (string, bool) {
	for _, member := range dpopPrivateJWKMembers {
		if _, ok := jwk[member]; ok {
			return member, true
		}
	}
	return "", false
}
