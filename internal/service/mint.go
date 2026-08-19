package service

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"regexp"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/seed"
)

// MintService signs a token for a subject that the calling service
// authenticated somewhere else.
//
// # Threat model
//
// This is a signing oracle. Every other token vault42 issues follows an
// authentication vault42 performed: a password, a second factor, a social
// callback, a client secret. A minted token follows nothing. The caller asserts
// "this is user X" and vault42 signs that assertion with the same key that signs
// every real one. A verifier cannot tell the difference from the signature, so
// whoever holds the mint credential can speak as any subject to every service
// that trusts vault42's JWKS.
//
// It exists because it is the only shape that fits the legacy platform: eleven
// services hold foreign-key copies of the platform's own user ids, so the token
// subject has to stay that id rather than a vault42-native one. The alternative
// is rewriting every one of those tables.
//
// The blast radius is therefore the whole trust model, and the controls are:
//
//   - Off unless configured. The route is not mounted at all when minting is
//     disabled, following the KMS unwrap oracle rather than a soft in-handler
//     403. A vanilla deployment has no mint.
//   - Its own scope. It never reuses the KMS scope: a client authorized to
//     unwrap envelopes must not thereby be authorized to forge subjects.
//   - Minted tokens are structurally rejected by vault42 itself. The token_type
//     claim is "mint", which is not in the allow-list vault42's own auth
//     middleware accepts, and the audience is a separate configured value that
//     is not vault42's own. Either check alone stops a minted token at
//     vault42's door; both are enforced. Without this, a mint credential would
//     be a full account takeover of every vault42 user: mint for any subject,
//     then call the user endpoints: read the identity profile, download the
//     blobs, delete the account.
//   - No credential-bearing claims. A minted token carries no client_id, no
//     fingerprint and no proof-of-possession confirmation, and it has no
//     refresh token and no stored session behind it. It cannot be exchanged,
//     rotated or extended.
//   - Deny-by-default roles and scopes. Both are allow-lists that start empty,
//     so a freshly enabled mint issues bare subject assertions and nothing
//     more. Admin-tier role names are refused unconditionally, whatever the
//     allow-list says.
//   - Short lifetimes. A minted token cannot be revoked before it expires,
//     because vault42 holds no record of it beyond the audit event. The ceiling
//     is enforced in the constructor, not left to configuration.
//
// What is deliberately NOT checked: whether the subject exists in vault42. It
// usually does not, and that is the point. The audit trail therefore records the
// asserted subject alongside the client that asserted it, and a minted token is
// a distinct event type from any self-authenticated one. The token carries the
// same attribution in its minted_by claim, because the audit trail answers "who
// spoke for this subject" only for whoever can read vault42's database, and the
// relying party holding the token cannot.
//
// None of this constrains which subject a given client may assert. Any holder of
// the mint scope can name any subject, and vault42 has no client-to-subject
// policy. That gap is stated in docs/security.md AR-16.

// MintedTokenType is the token_type claim on a minted token.
//
// The value matters: vault42's own auth middleware accepts "Bearer" and, on the
// 2FA verify routes, "2fa_challenge". Anything else is rejected with
// invalid_token_type. Minting into a type outside that allow-list is what stops
// a minted subject assertion from being replayed against vault42's own
// authenticated endpoints.
const MintedTokenType = "mint"

// mintTTLCeiling is the hard upper bound on a minted token's lifetime,
// independent of configuration. A minted token cannot be revoked, so its
// exposure window is its whole security story.
const mintTTLCeiling = 15 * time.Minute

// mintSubjectMaxLen bounds the caller-supplied subject.
const mintSubjectMaxLen = 128

// MintTTLFromSeconds converts a caller-supplied lifetime in seconds into a
// Duration, refusing any value outside the range a minted token could ever be
// granted.
//
// The bound has to be applied to the seconds, before the multiply, and not left
// to the range check on the resulting Duration. A Duration is int64 nanoseconds
// and time.Second is 1e9 = 2^9 * 1953125; the odd factor is invertible modulo a
// power of two, so seconds values differing by 2^55 multiply to the identical
// nanosecond count. 36028797018964268 seconds is about 1.1 billion years and
// converts to exactly five minutes. A ceiling check applied after the multiply
// sees an ordinary lifetime and grants it, so the endpoint answers an
// out-of-range request with a signed subject assertion instead of the refusal
// the contract promises, and neither the caller nor the audit row shows that
// anything was out of range.
//
// The bound is the hard ceiling rather than the configured MaxTTL, because
// MaxTTL is the operator's policy and belongs to Mint; this function's job is
// only to make the conversion exact for everything it lets through.
func MintTTLFromSeconds(seconds int) (time.Duration, error) {
	if seconds < 0 || int64(seconds) > int64(mintTTLCeiling/time.Second) {
		return 0, ErrMintTTLInvalid
	}
	return time.Duration(seconds) * time.Second, nil
}

// mintDeniedScopes can never appear on a minted token, whatever the operator
// configures.
//
// These are vault42's own capability scopes. A minted token that carried one
// would let the mint holder pivot from "assert a subject to a downstream
// service" into "operate vault42's privileged endpoints as that subject",
// which is the escalation this endpoint exists to avoid.
var mintDeniedScopes = map[string]bool{
	"mint:token":   true,
	"kms:unwrap":   true,
	"svcdoc:read":  true,
	"svcdoc:write": true,
	"login:status": true,
	"admin":        true,
	"admin:read":   true,
	"admin:write":  true,
}

// mintSubjectRe constrains the asserted subject. It is caller-supplied and ends
// up in a signed claim and in an audit row, so it is held to a charset that
// cannot smuggle control characters, whitespace or delimiters.
var mintSubjectRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)

// Sentinel errors returned by MintService.
var (
	// ErrMintSubjectInvalid is returned for a missing or malformed subject.
	ErrMintSubjectInvalid = errors.New("invalid mint subject")
	// ErrMintRoleNotPermitted is returned when a requested role is outside the
	// allow-list or is an admin-tier name.
	ErrMintRoleNotPermitted = errors.New("mint role not permitted")
	// ErrMintScopeNotPermitted is returned when a requested scope is outside the
	// allow-list or is a vault42 capability scope.
	ErrMintScopeNotPermitted = errors.New("mint scope not permitted")
	// ErrMintTTLInvalid is returned for a requested lifetime above the ceiling.
	ErrMintTTLInvalid = errors.New("invalid mint ttl")
	// ErrMintUnavailable is returned when no signing key is available.
	ErrMintUnavailable = errors.New("mint signing key unavailable")
)

// SigningKeyProvider returns the currently active signing key and its kid. It
// matches keystore.ActiveKey so a rotating deployment picks up new keys without
// the mint service holding a stale one.
type SigningKeyProvider func() (*rsa.PrivateKey, string)

// MintMetrics is the subset of the metrics collector this service records to.
type MintMetrics interface {
	RecordMintIssued()
	RecordMintRejected()
}

// MintConfig holds the mint policy. Every field is a deny-by-default control;
// the zero value mints nothing.
type MintConfig struct {
	// Issuer is vault42's own issuer, so downstream verifiers can pin it.
	Issuer string
	// Audience is the resource audience minted tokens are addressed to. It must
	// differ from Issuer: a minted token that carried vault42's own audience
	// would pass vault42's own audience validation.
	Audience string
	// DefaultTTL is the lifetime used when a caller requests none.
	DefaultTTL time.Duration
	// MaxTTL is the operator's ceiling, itself capped by mintTTLCeiling.
	MaxTTL time.Duration
	// AllowedRoles is the exhaustive set of roles that may be minted. Empty
	// means no role may be minted.
	AllowedRoles []string
	// AllowedScopes is the exhaustive set of scopes that may be minted. Empty
	// means no scope may be minted.
	AllowedScopes []string
}

// MintService issues subject-assertion tokens on behalf of a trusted service.
type MintService struct {
	signer        SigningKeyProvider
	cfg           MintConfig
	allowedRoles  map[string]bool
	allowedScopes map[string]bool
	metrics       MintMetrics
}

// MintRequest is one validated mint call.
type MintRequest struct {
	// Subject is the caller-asserted subject. vault42 does not verify it and
	// cannot: it is the calling platform's own user id.
	Subject string
	// Roles and Scopes are optional and must be subsets of the configured
	// allow-lists.
	Roles  []string
	Scopes []string
	// TTL is optional; zero means MintConfig.DefaultTTL.
	TTL time.Duration
	// MintedBy is the authenticated client asking for the assertion. It reaches
	// the token as the minted_by claim so a relying party can attribute the
	// assertion without vault42's audit log, which it cannot read. The caller
	// supplies it from its own authenticated context, never from the request
	// body: an attribution a mint client could choose would name whichever
	// tenant it wanted to blame.
	MintedBy string
}

// MintResult is a signed subject assertion.
type MintResult struct {
	Token     string
	Subject   string
	Roles     []string
	Scopes    []string
	Audience  string
	Issuer    string
	JTI       string
	KID       string
	ExpiresAt time.Time
	ExpiresIn int
}

// NewMintService validates the mint policy and returns a service, or an error
// that must abort startup.
//
// Configuration is validated here rather than per request so a deployment that
// would mint dangerous tokens fails to start instead of failing safe once and
// unsafely later.
func NewMintService(signer SigningKeyProvider, cfg MintConfig, metrics MintMetrics) (*MintService, error) {
	if signer == nil {
		return nil, errors.New("mint: signing key provider is required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("mint: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("mint: audience is required")
	}
	// A minted token addressed to vault42's own audience would satisfy
	// vault42's own audience validation, leaving token_type as the single
	// control between a subject assertion and a session. One control is not
	// enough for a signing oracle.
	if cfg.Audience == cfg.Issuer {
		return nil, errors.New("mint: audience must differ from the vault42 issuer")
	}
	if cfg.MaxTTL <= 0 || cfg.MaxTTL > mintTTLCeiling {
		return nil, fmt.Errorf("mint: max ttl must be in (0, %s]", mintTTLCeiling)
	}
	if cfg.DefaultTTL <= 0 || cfg.DefaultTTL > cfg.MaxTTL {
		return nil, errors.New("mint: default ttl must be in (0, max ttl]")
	}

	roles := make(map[string]bool, len(cfg.AllowedRoles))
	for _, r := range cfg.AllowedRoles {
		if seed.ReservedAdminRoles[r] {
			return nil, fmt.Errorf("mint: role %q is admin-tier and cannot be minted", r)
		}
		roles[r] = true
	}
	scopes := make(map[string]bool, len(cfg.AllowedScopes))
	for _, s := range cfg.AllowedScopes {
		if mintDeniedScopes[s] {
			return nil, fmt.Errorf("mint: scope %q is a vault42 capability scope and cannot be minted", s)
		}
		scopes[s] = true
	}

	return &MintService{
		signer:        signer,
		cfg:           cfg,
		allowedRoles:  roles,
		allowedScopes: scopes,
		metrics:       metrics,
	}, nil
}

// Audience returns the configured resource audience.
func (s *MintService) Audience() string { return s.cfg.Audience }

// Mint validates a request against the policy and signs the assertion.
func (s *MintService) Mint(req MintRequest) (*MintResult, error) {
	if err := ValidateMintSubject(req.Subject); err != nil {
		s.rejected()
		return nil, err
	}

	roles, err := s.checkRoles(req.Roles)
	if err != nil {
		s.rejected()
		return nil, err
	}
	scopes, err := s.checkScopes(req.Scopes)
	if err != nil {
		s.rejected()
		return nil, err
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = s.cfg.DefaultTTL
	}
	// A request above the ceiling is refused rather than clamped. Silently
	// issuing something other than what was asked for hides a misconfigured
	// caller until the day its tokens expire mid-flight.
	if ttl < 0 || ttl > s.cfg.MaxTTL {
		s.rejected()
		return nil, ErrMintTTLInvalid
	}

	key, kid := s.signer()
	if key == nil || kid == "" {
		return nil, ErrMintUnavailable
	}

	jti, err := vaultcrypto.RandomUUID()
	if err != nil {
		return nil, fmt.Errorf("mint: generate jti: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Audience:  vjwt.ClaimStrings{s.cfg.Audience},
			Subject:   req.Subject,
			ExpiresAt: vjwt.NewNumericDate(expiresAt),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        jti,
		},
		Roles:  roles,
		Scopes: scopes,
		// ClientID is deliberately absent. Setting it would make a minted token
		// indistinguishable from a client-credentials token to any code that
		// treats the claim's presence as proof of a service caller, including
		// the service document store, which asserts exactly that. The minting
		// client is named in MintedBy, which carries no authority anywhere, so
		// the two meanings stay apart.
		MintedBy:  req.MintedBy,
		TokenType: MintedTokenType,
	}

	token, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		return nil, fmt.Errorf("mint: sign: %w", err)
	}
	if s.metrics != nil {
		s.metrics.RecordMintIssued()
	}

	return &MintResult{
		Token:     token,
		Subject:   req.Subject,
		Roles:     roles,
		Scopes:    scopes,
		Audience:  s.cfg.Audience,
		Issuer:    s.cfg.Issuer,
		JTI:       jti,
		KID:       kid,
		ExpiresAt: expiresAt,
		ExpiresIn: int(ttl.Seconds()),
	}, nil
}

// checkRoles enforces the role allow-list.
//
// seed.FilterUserRoles is applied on top of the allow-list rather than instead
// of it, and the explicit admin-tier check runs first so a request for an
// admin role is a refusal rather than a silent downgrade. On the login path a
// silent strip is right: the user did not ask for the role, a stray database
// row did. Here the caller asked, in a request that would otherwise be granted,
// and a signing oracle that quietly issues something other than what was
// requested hides the misconfiguration that produced the request.
func (s *MintService) checkRoles(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	for _, r := range requested {
		if seed.ReservedAdminRoles[r] || !s.allowedRoles[r] {
			return nil, ErrMintRoleNotPermitted
		}
	}
	// Defense in depth: if the check above is ever weakened, the filter still
	// keeps an admin-tier name out of a signed token.
	filtered := seed.FilterUserRoles(requested)
	if len(filtered) != len(requested) {
		return nil, ErrMintRoleNotPermitted
	}
	return filtered, nil
}

// checkScopes enforces the scope allow-list and the unconditional denylist.
func (s *MintService) checkScopes(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(requested))
	for _, sc := range requested {
		if mintDeniedScopes[sc] || !s.allowedScopes[sc] {
			return nil, ErrMintScopeNotPermitted
		}
		out = append(out, sc)
	}
	return out, nil
}

func (s *MintService) rejected() {
	if s.metrics != nil {
		s.metrics.RecordMintRejected()
	}
}

// ValidateMintSubject checks the caller-asserted subject.
func ValidateMintSubject(subject string) error {
	if subject == "" || len(subject) > mintSubjectMaxLen || !mintSubjectRe.MatchString(subject) {
		return ErrMintSubjectInvalid
	}
	return nil
}
