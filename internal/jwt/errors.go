package jwt

import "errors"

var (
	ErrTokenMalformed            = errors.New("token is malformed")
	ErrTokenUnverifiable         = errors.New("token is unverifiable")
	ErrTokenSignatureInvalid     = errors.New("token signature is invalid")
	ErrTokenExpired              = errors.New("token is expired")
	ErrTokenNotValidYet          = errors.New("token is not valid yet")
	ErrTokenUsedBeforeIssued     = errors.New("token used before issued")
	ErrTokenInvalidAudience      = errors.New("token has invalid audience")
	ErrTokenInvalidIssuer        = errors.New("token has invalid issuer")
	ErrTokenRequiredClaimMissing = errors.New("token is missing required claim")
	ErrInvalidKeyType            = errors.New("key is of invalid type")
)
