# Integrating a relying party

What a service consuming vault42 tokens has to decide, and what vault42 has decided for it.

This document exists because the first real integration surfaced four questions that are not
bugs and not features. Each is a place where what vault42 does and what a relying party
expects differ for a reason, and where the answer is a decision somebody has to write down
rather than a gap somebody has to close. They are written here so the second integrator
finds them before the cutover rather than during it.

The examples name BeOn3, because it is the integration these were worked out against. Nothing
here is specific to it.

## What a vault42 token asserts

A vault42 access token says: this subject authenticated, at this time, to this strength, and
holds these roles and scopes. It is signed RS256, carries `kid`, and is verifiable against
`/.well-known/jwks.json` with no call back to vault42.

It does not say the subject still exists, is still enabled, or still holds those roles. It
says they did when it was issued, and it expires in fifteen minutes. Every decision below
follows from that sentence.

## 1. Two audiences, one validator

**The situation.** A `/mint` token carries `VAULT_MINT_AUDIENCE`, which the server refuses to
start unless it differs from `VAULT_ORIGIN`. A `/client/token` token carries vault42's own
audience. A relying party that pins a single `ValidAudience` can validate one or the other,
never both.

**The decision: vault42 keeps them separate, and the relying party validates a set.**

The separation is a control, not an accident. A minted token is an assertion vault42 signed on
somebody else's word about a subject it has never heard of. If it carried vault42's own
audience it would authenticate *against vault42*, and the holder of the mint scope would have
turned "assert a subject downstream" into "act as that subject here". The two-audience rule
and the `token_type: mint` claim are two independent controls saying the same thing, and
collapsing the audiences would remove one of them.

**What the relying party does.** Accept a set rather than a value. In .NET that is
`TokenValidationParameters.ValidAudiences`; most libraries have the same plural. Configure it
once in whatever wraps your JWT validation -- if eleven services each hand-roll their own
`AddJwtAuthentication`, that is eleven edits, which is an argument for the shared wrapper
rather than against the plural.

## 2. Service-to-service identity

**The situation.** `/mint` deliberately omits `client_id`, so a minted token cannot be mistaken
for an authenticated service caller. `/client/token` carries `client_id` but exactly one role,
from the client row. A platform whose internal calls authenticate as, say, `[Admin,
InternalService]` can express that with neither.

**The decision: internal service-to-service auth stays with the platform.**

vault42 is the authority on *who a user is*. It is not the authority on whether your
notifications service may call your payments service. Routing that through vault42 buys
central configuration and costs a runtime dependency on vault42 for every internal call, on a
path that has no user in it and no user-facing failure mode. A shared secret or mTLS between
two of your own services is a smaller mechanism than a signing oracle, and smaller is the
right answer for a trust relationship you fully control at both ends.

If you want it centralised anyway, the honest shape is a `/client/token` that carries a role
*set* rather than a single role. That is a small change to `internal/handler/client.go` and
the client row, and it does not weaken anything: those tokens already carry `client_id` and
already sit in vault42's own audience. Ask for it, do not work around it by minting an
admin-ish subject.

## 3. Revocation is bounded, not immediate

**The situation.** vault42 access tokens are stateless: nothing is stored, nothing is
consulted per request. `POST /auth/logout` and an admin lock revoke *refresh* families, which
stops renewal. They do not reach into an access token already in a client's hands. A platform
that stores every issued access token and re-checks it per call has immediate revocation;
vault42 does not.

**The decision: vault42 stays stateless, and revocation is bounded by the access-token
lifetime.**

Per-request introspection would put a database round-trip in front of every authenticated
request in every consuming service. That is the exact cost self-contained tokens exist to
avoid, and it converts vault42 from a service on the login path into a service on *every*
path -- with the availability requirements that implies. The trade is deliberate and it is the
same one every JWT deployment makes.

So the guarantee is: **a ban, a lock or a logout stops renewal immediately and stops access
within the access-token TTL.** With the default fifteen minutes, the worst case is fifteen
minutes of a token that should not work. Say that number out loud in your own threat model
rather than assuming zero.

If your model genuinely cannot tolerate that window, the options in increasing cost are: lower
`VAULT_ACCESS_TOKEN_TTL`, which is free and linear; have the relying party consult a small
shared denylist of `jti` values for the immediate-ban case only, which keeps the fast path
fast; or ask for that denylist inside vault42. Adding per-call introspection is the option
that is not on this list.

## 4. Minted tokens are short and are not refreshed

**The situation.** `/mint` refuses a TTL above fifteen minutes -- the ceiling is enforced in
the constructor, not left to configuration -- and returns no refresh token. A platform issuing
sixty-minute tokens of its own cannot simply mint one.

**The decision: the ceiling stays, and the caller re-mints.**

A minted token cannot be revoked, because vault42 keeps no record of it beyond the audit
event. Its lifetime is therefore the *only* bound on a leaked one, which makes the ceiling the
security control rather than a configuration default. Raising it to sixty minutes would
quadruple the exposure of every leaked assertion to buy a scheduling convenience.

**What the relying party does.** Mint on demand from its backend-for-frontend and re-mint
before expiry. The rate limit is 60 requests per minute per client, fail-closed, so the
arithmetic is: one mint per user per fifteen minutes supports roughly 900 concurrent users per
client before the limit is the constraint, and a service minting per-request rather than
per-session will hit it far sooner. That is the intended pressure -- minting is an assertion,
not a session.

## Two things vault42 will not assert

**Verified email.** A minted token may carry an `email` claim when the operator has enabled
it, and that claim is the *caller's* assertion about a subject vault42 has never looked up. It
is not proof of address ownership and no login, refresh or client-credentials token carries it
at all. A relying party keying records on it is keying on what it told vault42.

**Anything about tenancy.** `X-Vault-App` is a routing and branding header. There is no data
isolation, no per-app user namespace and no per-app signing key behind it. Two platforms
sharing one vault42 share one user namespace and one JWKS. This is stated at greater length in
[spec.md](spec.md) section 0.8, and it is the decision most likely to be misread from the
outside.

## Before you cut over

- Decide your revocation window and write it down (section 3).
- Move JWT validation into one shared place, if it is not already, and make it accept an
  audience *set* (section 1).
- Keep internal service auth where it is (section 2).
- Size your mint rate against sessions, not requests (section 4).
- Read [api.md](api.md) on `POST /mint` for the claim table, and
  [security.md](security.md) AR-16, which states plainly that vault42 has no client-to-subject
  policy: any holder of the mint scope can name any subject.
