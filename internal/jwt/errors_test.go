package jwt

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrors_Is(t *testing.T) {
	sentinels := []error{
		ErrTokenMalformed,
		ErrTokenUnverifiable,
		ErrTokenSignatureInvalid,
		ErrTokenExpired,
		ErrTokenNotValidYet,
		ErrTokenUsedBeforeIssued,
		ErrTokenInvalidAudience,
		ErrTokenInvalidIssuer,
		ErrTokenRequiredClaimMissing,
		ErrInvalidKeyType,
	}

	for _, sentinel := range sentinels {
		t.Run(sentinel.Error(), func(t *testing.T) {
			if !errors.Is(sentinel, sentinel) {
				t.Errorf("errors.Is(%v, %v) = false, want true", sentinel, sentinel)
			}
		})
	}
}

func TestErrors_Wrapping(t *testing.T) {
	wrapped := fmt.Errorf("outer: %w", ErrTokenExpired)
	if !errors.Is(wrapped, ErrTokenExpired) {
		t.Error("errors.Is(wrapped, ErrTokenExpired) = false, want true")
	}

	doubleWrapped := fmt.Errorf("level2: %w", wrapped)
	if !errors.Is(doubleWrapped, ErrTokenExpired) {
		t.Error("errors.Is(doubleWrapped, ErrTokenExpired) = false, want true")
	}
}

func TestErrors_MultipleWrapping(t *testing.T) {
	multi := fmt.Errorf("%w: %w", ErrTokenMalformed, ErrTokenSignatureInvalid)

	if !errors.Is(multi, ErrTokenMalformed) {
		t.Error("errors.Is(multi, ErrTokenMalformed) = false, want true")
	}
	if !errors.Is(multi, ErrTokenSignatureInvalid) {
		t.Error("errors.Is(multi, ErrTokenSignatureInvalid) = false, want true")
	}
}

func TestErrors_NotEqual(t *testing.T) {
	if errors.Is(ErrTokenExpired, ErrTokenMalformed) {
		t.Error("ErrTokenExpired should not match ErrTokenMalformed")
	}
}
