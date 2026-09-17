package jwt

// MinRSAModulusBits and MaxRSAModulusBits bound the RSA modulus this service is
// willing to accept from a JWK it did not mint.
//
// Two importers read such a JWK, and both take the modulus straight off the
// network: crypto.parseJWKHeader reads the self-signed jwk header of a DPoP
// proof, where the sender invents the key outright, and
// oauth2.rsaPublicKeyFromJWK reads the keys an OIDC issuer publishes at its
// jwks_uri, which refreshJWKS then installs as the id_token verification cache.
// Neither modulus is checked against anything this service generated, so in
// both cases the remote end chooses the size.
//
// The floor is the smallest modulus still sound for an RSA signature. The
// ceiling is not a cryptographic judgment -- a larger modulus is stronger, not
// weaker -- it is a cost bound. rsa.VerifyPKCS1v15 does a modular
// exponentiation whose per-multiplication cost grows with the square of the
// modulus size, so verifying against a 32768-bit key costs roughly 64 times
// what the top of this range costs, and the verifier cannot know the key is
// hostile until it has already paid. On the OIDC path that price is charged on
// every id_token carrying the matching kid, for as long as the cache holds it.
//
// The numbers live here, in the package both importers already depend on,
// because they had drifted: the DPoP importer capped the modulus and the OIDC
// one did not, so an issuer's jwks_uri could seed the verification cache with a
// key no DPoP proof would have been allowed to carry. Enforcement still belongs
// to the callers, exactly as the package comment says -- this file states the
// range, it does not act on it.
const (
	MinRSAModulusBits = 2048
	MaxRSAModulusBits = 4096
)
