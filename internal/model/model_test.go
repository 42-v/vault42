package model

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// allTypes is every struct the package declares. Adding a new model type here
// is the one manual step; everything below is derived from it by reflection.
func allTypes() []any {
	return []any{
		User{},
		PasswordHistory{},
		SocialAccount{},
		AccountRecovery{},
		Client{},
		RefreshToken{},
		Device{},
		TOTPSecret{},
		WebAuthnCredential{},
		BackupCode{},
		RateLimit{},
		AuditEntry{},
		AdminConfig{},
		IdentityProfile{},
		Blob{},
		BlobQuota{},
		AdminRole{},
		AppRole{},
		EmailBranding{},
		EmailTemplate{},
		AdminUser{},
		AdminSession{},
	}
}

// The model types are persistence rows, but a handler that serialises one
// directly turns them into a wire contract, which is how GET /admin/audit came
// to publish Go field names in an API that is snake_case everywhere else.
// Requiring a tag on every exported field means the next accidental
// serialization still produces the right shape.
func TestModelFieldsCarryJSONTags(t *testing.T) {
	for _, v := range allTypes() {
		typ := reflect.TypeOf(v)
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if !f.IsExported() {
					continue
				}
				tag, ok := f.Tag.Lookup("json")
				if !ok {
					t.Errorf("%s.%s has no json tag, so it would serialise under its Go name", typ.Name(), f.Name)
					continue
				}
				name, _, _ := strings.Cut(tag, ",")
				if name == "-" {
					continue
				}
				if !snakeCase.MatchString(name) {
					t.Errorf("%s.%s is tagged %q, which is not snake_case", typ.Name(), f.Name, name)
				}
			}
		})
	}
}

// Credential material and the fingerprint HMAC must be unreachable by
// serialization, not merely absent from today's views: a view that needs one
// has to name it, and no accidental marshal can put one on the wire.
func TestSecretFieldsAreNeverSerialized(t *testing.T) {
	secrets := map[string][]string{
		"User":            {"PasswordHash"},
		"PasswordHistory": {"PasswordHash"},
		"SocialAccount":   {"AccessTokenEnc", "RefreshTokenEnc"},
		"AccountRecovery": {"Payload", "Pseudonym"},
		"Client":          {"SecretHash"},
		"RefreshToken":    {"TokenHash", "FingerprintHash"},
		"Device":          {"FingerprintHash"},
		"TOTPSecret":      {"SecretEnc"},
		"BackupCode":      {"CodeHash"},
		"AuditEntry":      {"FingerprintHash"},
		"IdentityProfile": {"DataEnc"},
		"Blob":            {"LabelEnc", "DataEnc", "RefHash"},
		"AdminUser":       {"PasswordHash", "TOTPSecretEnc"},
		"AdminSession":    {"TokenHash"},
	}

	byName := map[string]reflect.Type{}
	for _, v := range allTypes() {
		typ := reflect.TypeOf(v)
		byName[typ.Name()] = typ
	}

	for typeName, fields := range secrets {
		typ, ok := byName[typeName]
		if !ok {
			t.Fatalf("%s is no longer a model type; update this test", typeName)
		}
		for _, fieldName := range fields {
			f, ok := typ.FieldByName(fieldName)
			if !ok {
				t.Errorf("%s.%s no longer exists; update this test", typeName, fieldName)
				continue
			}
			if f.Tag.Get("json") != "-" {
				t.Errorf("%s.%s is serializable (tag %q), so credential or correlator material can reach a response body",
					typeName, fieldName, f.Tag.Get("json"))
			}
		}
	}
}
