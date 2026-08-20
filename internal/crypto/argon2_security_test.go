package crypto

import (
	"strings"
	"testing"
)

// The parameters come out of the stored hash string, so a row that lands in the
// password column decides how much CPU and memory one verification costs. Both
// ends of every parameter are pinned: too high is a denial of service anybody
// with write access to a hash can trigger, and too low (or zero, which argon2
// panics on) is a hash that verifies far too cheaply.
//
// Each case asserts the specific message as well as the refusal, because the
// bounds are checked in sequence and a case that fell through to the wrong
// branch would still return an error and still look green.
func TestArgon2RejectsOutOfRangeParameters(t *testing.T) {
	// A well-formed argon2id hash with the parameter under test substituted in.
	const (
		salt   = "AAAAAAAAAAAAAAAAAAAAAA"
		digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	)

	tests := []struct {
		name    string
		hash    string
		wantErr string
	}{
		{
			name:    "iterations above the ceiling",
			hash:    "$argon2id$v=19$m=47104,t=99,p=1$" + salt + "$" + digest,
			wantErr: "iterations exceed maximum",
		},
		{
			name:    "iterations of zero",
			hash:    "$argon2id$v=19$m=47104,t=0,p=1$" + salt + "$" + digest,
			wantErr: "iterations must be >= 1",
		},
		{
			name:    "parallelism above the ceiling",
			hash:    "$argon2id$v=19$m=47104,t=1,p=99$" + salt + "$" + digest,
			wantErr: "parallelism exceeds maximum",
		},
		{
			name:    "parallelism of zero",
			hash:    "$argon2id$v=19$m=47104,t=1,p=0$" + salt + "$" + digest,
			wantErr: "parallelism must be >= 1",
		},
		{
			// 999999 KiB is well past the verification ceiling, so accepting it would
			// let one stored hash allocate a gigabyte per login attempt.
			name:    "memory above the ceiling",
			hash:    "$argon2id$v=19$m=999999,t=1,p=1$" + salt + "$" + digest,
			wantErr: "memory exceeds maximum",
		},
		{
			// argon2 requires memory >= 8*parallelism.
			name:    "memory below 8 KiB per lane",
			hash:    "$argon2id$v=19$m=1,t=1,p=1$" + salt + "$" + digest,
			wantErr: "memory too small",
		},
		{
			name:    "an empty hash string",
			hash:    "",
			wantErr: "invalid hash format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := VerifyPassword("password", tt.hash)
			if ok {
				t.Error("the password verified against a hash the parameter check should have refused")
			}
			if err == nil {
				t.Fatalf("VerifyPassword returned no error, want one mentioning %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want one mentioning %q", err, tt.wantErr)
			}
		})
	}
}

func TestArgon2ValidBoundaryParams(t *testing.T) {
	// Normal parameters should still work after adding bounds
	password := "test-boundary-password!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !ok {
		t.Error("valid password should verify with valid hash")
	}
}
