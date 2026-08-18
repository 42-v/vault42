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

// WithThumbprint returns ctx carrying the RFC 7638 JWK thumbprint of the key
// that signed the request's DPoP proof.
//
// It is called only from the DPoP middleware, and only after the proof's
// signature, typ, htm, htu, iat, jti and ath have all been checked, so a
// thumbprint in a context is always one the caller demonstrated possession of.
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
