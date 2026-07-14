package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The identity profile is the encrypted PII blob: name, phone, address, and the marketing
// consent record with its provenance. It is encrypted under the master key before it ever
// reaches the database.
//
// If the encryption step failed and the write went ahead, the alternative to ciphertext is
// not "no write" — it is a row containing whatever the failing path left behind. Both
// write paths must refuse rather than store anything they could not encrypt.
func TestIdentityService_UnusableMasterKeyRefusesToWrite(t *testing.T) {
	wrote := false
	repo := &mocks.MockIdentityRepo{
		UpsertFn: func(context.Context, *model.IdentityProfile) error {
			wrote = true
			return nil
		},
	}

	// 7 bytes is not an AES key. Encrypt must reject it, and the service must stop.
	svc := NewIdentityService(repo, bytes.Repeat([]byte{0x42}, 7), []byte("hmac-secret"))

	err := svc.Upsert(context.Background(), "user-1", &IdentityData{Username: "alice"})

	if err == nil {
		t.Fatal("the profile was stored under a key that cannot encrypt")
	}
	if !strings.Contains(err.Error(), "encrypt") {
		t.Errorf("err = %v, want an encryption failure", err)
	}
	if wrote {
		t.Error("the repository was written to despite the encryption failing")
	}
}

// Validate is called on profiles that may be entirely absent — a PUT that carries no
// identity data at all is legitimate. A nil profile is not an invalid one.
func TestIdentityData_NilProfileIsValid(t *testing.T) {
	var d *IdentityData
	if err := d.Validate(); err != nil {
		t.Errorf("a nil profile was rejected: %v", err)
	}
}
