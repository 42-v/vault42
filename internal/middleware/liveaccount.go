package middleware

import (
	"context"
	"net/http"

	"github.com/42-v/vault42/internal/httputil"
)

// LiveAccount refuses a request whose subject has been erased.
//
// Auth validates a token's signature, issuer, audience and type and never reads
// the database, which is deliberate and is what AR-5 accepts: the roles on an
// issued token may be up to one TTL out of date. What AR-5 does not say is that
// an issued token may still WRITE. DELETE /user/account tombstones the row and
// revokes the refresh families, but an access token minted a moment earlier
// keeps verifying for the rest of VAULT_ACCESS_TOKEN_TTL, and nothing on an
// authenticated route knew the account was gone.
//
// #82 closed that on PUT /user/profile and said the rest out loud: "PUT
// /user/identity, POST /user/blobs and the 5-minute confirm-window MFA writes
// are still reachable the same way and are not one-liners -- none of those
// handlers reads the user row at all -- so they are filed separately rather
// than half-done here." This is that file. The handlers still do not read the
// user row; this reads it for them, once, in front of every route that can put
// personal data back onto a tombstoned account.
//
// It is a middleware rather than a check per handler because the failure mode
// is omission. The defect being fixed is not that someone wrote the check
// wrongly, it is that four handlers never had one, and a fifth route added next
// year would not either. Wiring it into the route composition means a new write
// route inherits it from the wrapper it is already required to use.
//
// It guards writes only. DELETE /user/account must stay reachable on a
// tombstoned account: the erasure cascade spans nine stores with no
// transaction, every step is idempotent, and re-running an interrupted erasure
// is the documented recovery. Gating it here would make a half-finished erasure
// impossible to finish, which is the opposite of the invariant.
//
// isLive fails closed. A lookup that errors refuses the write rather than
// allowing it, because the alternative is an erasure that a database blip can
// undo, and every route behind this needs the database to serve the request
// anyway -- there is no availability being bought by guessing.
func LiveAccount(isLive func(ctx context.Context, userID string) (bool, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			// 401 rather than 404 or 410: the same answer PUT /user/profile
			// gives, and the same answer an unauthenticated caller gets. The
			// account is gone, so there is nothing to tell its former holder
			// apart from anyone else presenting a token for it.
			live, err := isLive(r.Context(), claims.Subject)
			if err != nil || !live {
				httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
