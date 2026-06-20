package config

import "testing"

// setDefaultBool: env var not set → default is applied verbatim.
func TestSetDefaultBool_EnvUnset(t *testing.T) {
	field := false
	setDefaultBool(&field, true, "VAULT_TEST_BOOL_UNSET")
	if field != true {
		t.Fatalf("field = %v, want true (default applied when env unset)", field)
	}
}

// setDefaultBool: env var set to a parseable false → overrides the true default.
func TestSetDefaultBool_EnvParsedFalse(t *testing.T) {
	t.Setenv("VAULT_TEST_BOOL_SET", "false")
	field := true
	setDefaultBool(&field, true, "VAULT_TEST_BOOL_SET")
	if field != false {
		t.Fatalf("field = %v, want false (env override)", field)
	}
}

// setDefaultBool: env var set to a parseable true while default is false.
func TestSetDefaultBool_EnvParsedTrue(t *testing.T) {
	t.Setenv("VAULT_TEST_BOOL_TRUE", "1")
	field := false
	setDefaultBool(&field, false, "VAULT_TEST_BOOL_TRUE")
	if field != true {
		t.Fatalf("field = %v, want true (env override)", field)
	}
}

// setDefaultBool: env var set to garbage → falls back to the default.
func TestSetDefaultBool_EnvUnparseable(t *testing.T) {
	t.Setenv("VAULT_TEST_BOOL_GARBAGE", "not-a-bool")
	field := false
	setDefaultBool(&field, true, "VAULT_TEST_BOOL_GARBAGE")
	if field != true {
		t.Fatalf("field = %v, want true (default on parse error)", field)
	}
}
