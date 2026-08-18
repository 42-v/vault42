// Package dpop carries the sender-constraining binding a validated DPoP proof
// establishes (RFC 9449) from the middleware that checks the proof to the code
// that issues the token.
//
// It is a package of its own, and a leaf one, because the two ends of that hop
// sit on opposite sides of the HTTP boundary: internal/middleware validates the
// proof, internal/service mints the token, and neither may import the other. The
// alternative — threading a thumbprint string through every issuance signature
// from the handler down — put a DPoP-shaped parameter on functions that have
// nothing to do with DPoP, including every path that never sees a proof.
package dpop

import "context"

type ctxKey struct{}

// thumbprintKey is the context key holding a validated proof's JWK thumbprint.
// A struct{} key cannot collide with a key from any other package, and the type
// is unexported so nothing outside this package can plant a thumbprint that no
// proof was checked for.
var thumbprintKey ctxKey

// WithThumbprint returns ctx carrying the RFC 7638 JWK thumbprint the token
// about to be issued must be bound to.
//
// There are two callers, and the difference between them is the whole of RFC
// 9449 §5.
//
//   - The DPoP middleware, on every request that carries a proof, and only after
//     the proof's signature, typ, htm, htu, iat, jti and ath have all been
//     checked. What it plants is a key the caller demonstrated possession of for
//     this method, this URI and this instant. On a login that is the right
//     source, because a login is where a binding is established.
//
//   - AuthService.issueRotatedPair, which overwrites it with the binding stored
//     on the rotation family. A rotation must not take the value from the
//     request: whoever holds the opaque refresh cookie reaches that path, so
//     minting cnf.jkt from the current proof let a caller re-bind someone else's
//     session to a key of their own. Overwriting rather than branching keeps
//     fresh issuance and rotation on one code path while giving each the correct
//     source, and an unbound family overwrites with "", so a presented proof
//     cannot upgrade a family that never had a binding.
//
// The second caller plants a value this request proved nothing about, which is
// sound only because the request that established it did, and because the
// rotation is refused outright unless the proof on this request matches it
// (AuthService.enforceDPoPBinding). A third caller would be asserting possession
// of a key nobody demonstrated.
func WithThumbprint(ctx context.Context, jkt string) context.Context {
	return context.WithValue(ctx, thumbprintKey, jkt)
}

// Thumbprint returns the thumbprint a validated DPoP proof established for this
// request, or "" when the request carried no proof.
//
// Issuance treats "" as "not sender-constrained" and omits cnf.jkt, which is the
// behavior every non-DPoP client depends on. It must never be read as "any key
// will do": the middleware refuses a request whose token carries cnf.jkt and
// whose proof is absent, so a bound token can never reach a handler on an empty
// thumbprint.
func Thumbprint(ctx context.Context) string {
	jkt, _ := ctx.Value(thumbprintKey).(string)
	return jkt
}
