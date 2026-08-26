package middleware

import (
	"net/http"

	"github.com/42-v/vault42/internal/httputil"
	"github.com/42-v/vault42/internal/repository"
)

// RequireLiveAccount refuses a request whose subject has been erased.
//
// An access token outlives the erasure that invalidated it. Auth validates the
// signature, issuer, audience and token type and never reads the database, which
// is the whole point of a self-contained token and is a trade docs/security.md
// makes deliberately: revocation is bounded by the access-token lifetime, not
// immediate. AR-5 states that for roles.
//
// Erasure is the case that trade does not cover. A stale role grants no more
// than it did when the token was minted; a write reaches into storage the
// erasure has already scrubbed and puts personal data back. The subject asked
// for it to be gone, the operator answered that it was, and neither is true
// afterwards. So this is not a general account-state check bolted onto every
// route -- it is applied to the handful of routes that persist subject-owned
// data, and nowhere else.
//
// Which routes: the ones that write and cannot be guarded in SQL.
// PUT /user/profile is not among them, because auth.users can state the rule
// itself and does -- UserRepo.Update carries AND deleted = FALSE. identity
// profiles cannot: identity.profiles is keyed by an unlinkable pseudonym with no
// user_id and no foreign key, which is what makes it pseudonymous and also what
// makes the database unable to see the connection. Blobs and the MFA setup
// routes are the same shape. For those, the only thing that can know is a
// lookup, so a lookup is what this does.
//
// The cost is one indexed primary-key read on a write path that is already
// doing storage work. Read routes are untouched, and the stateless fast path
// that self-contained tokens exist to provide is unchanged.
//
// Failure is closed. A lookup error is answered 401 rather than passed through:
// this guard exists because the alternative is writing personal data back onto
// an erased subject, and a database that cannot answer is not permission to do
// that.
func RequireLiveAccount(users repository.UserRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			user, err := users.GetByID(r.Context(), claims.Subject)
			if err != nil || user == nil || user.Deleted {
				httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
