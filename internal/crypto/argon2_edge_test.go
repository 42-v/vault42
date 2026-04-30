package crypto

import (
	"strings"
	"testing"
)

// TestArgon2Edge_EmptyPassword tests hashing and verifying an empty password.
func TestArgon2Edge_EmptyPassword(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("Empty password should be hashable: %v", err)
	}

	match, err := VerifyPassword("", hash)
	if err != nil {
		t.Fatalf("Empty password verification should not error: %v", err)
	}
	if !match {
		t.Fatal("Empty password should verify against its own hash")
	}

	match, _ = VerifyPassword("not-empty", hash)
	if match {
		t.Fatal("Non-empty password should not match empty password hash")
	}
}

// TestArgon2Edge_UnicodePasswords tests passwords with various Unicode content.
func TestArgon2Edge_UnicodePasswords(t *testing.T) {
	passwords := []struct {
		name string
		pw   string
	}{
		{"emoji", "\U0001f512\U0001f511\U0001f6e1\ufe0f"},
		{"cjk", "\u5bc6\u7801\u5b89\u5168\u6027\u5f88\u91cd\u8981"},
		{"arabic", "\u0643\u0644\u0645\u0629 \u0627\u0644\u0633\u0631 \u0627\u0644\u0622\u0645\u0646\u0629"},
		{"diacritics", "\u00dc\u00f1\u00ee\u00e7\u00f6\u00f0\u00e9"},
		{"hangul", "\ube44\ubc00\ubc88\ud638\uc548\uc804"},
		{"devanagari", "\u092a\u093e\u0938\u0935\u0930\u094d\u0921"},
		{"mixed_scripts", "pass\u00f1\u5bc6\u7801\U0001f512word"},
		{"zero_width_joiner", "a\u200db\u200dc"},
		{"combining_chars", "a\u0300\u0301\u0302\u0303"},
		{"rtl_override", "\u202epassword"},
	}

	for _, tc := range passwords {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := HashPassword(tc.pw)
			if err != nil {
				t.Fatalf("Unicode password %s should be hashable: %v", tc.name, err)
			}

			match, err := VerifyPassword(tc.pw, hash)
			if err != nil {
				t.Fatalf("Unicode password %s verification error: %v", tc.name, err)
			}
			if !match {
				t.Fatalf("Unicode password %s should verify", tc.name)
			}

			// Slightly different password should not match
			match, _ = VerifyPassword(tc.pw+"x", hash)
			if match {
				t.Fatalf("Modified unicode password %s should not match", tc.name)
			}
		})
	}
}

// TestArgon2Edge_NullBytes tests passwords containing null bytes.
func TestArgon2Edge_NullBytes(t *testing.T) {
	passwords := []struct {
		name string
		pw   string
	}{
		{"single_null", "\x00"},
		{"null_prefix", "\x00password"},
		{"null_middle", "pass\x00word"},
		{"null_suffix", "password\x00"},
		{"multi_null", "\x00\x00\x00"},
		{"null_between_chars", "a\x00b\x00c"},
	}

	for _, tc := range passwords {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := HashPassword(tc.pw)
			if err != nil {
				t.Fatalf("Password with null bytes should be hashable: %v", err)
			}

			match, _ := VerifyPassword(tc.pw, hash)
			if !match {
				t.Fatalf("Password with null bytes should verify")
			}
		})
	}
}

// TestArgon2Edge_NullByteTruncation verifies that null bytes do NOT cause
// password truncation (C-string behavior).
func TestArgon2Edge_NullByteTruncation(t *testing.T) {
	pw1 := "password\x00A"
	pw2 := "password\x00B"

	hash1, _ := HashPassword(pw1)

	// pw2 should NOT verify against hash1 (they differ after null byte)
	match, _ := VerifyPassword(pw2, hash1)
	if match {
		t.Fatal("Null byte truncation detected — passwords differing after \\x00 should not match")
	}

	// pw1 truncated to "password" should NOT match
	match, _ = VerifyPassword("password", hash1)
	if match {
		t.Fatal("Password without null byte should not match hash with null byte")
	}
}

// TestArgon2Edge_VeryLongPasswords tests extremely long passwords.
func TestArgon2Edge_VeryLongPasswords(t *testing.T) {
	lengths := []int{100, 500, 1000, 5000, 10000}

	for _, n := range lengths {
		pw := strings.Repeat("a", n)
		hash, err := HashPassword(pw)
		if err != nil {
			t.Fatalf("Password of length %d should be hashable: %v", n, err)
		}

		match, err := VerifyPassword(pw, hash)
		if err != nil {
			t.Fatalf("Password of length %d verification error: %v", n, err)
		}
		if !match {
			t.Fatalf("Password of length %d should verify", n)
		}
	}
}

// TestArgon2Edge_AllByteValues tests a password containing every possible byte value.
func TestArgon2Edge_AllByteValues(t *testing.T) {
	pw := make([]byte, 256)
	for i := range pw {
		pw[i] = byte(i)
	}

	hash, err := HashPassword(string(pw))
	if err != nil {
		t.Fatalf("All-bytes password should be hashable: %v", err)
	}

	match, _ := VerifyPassword(string(pw), hash)
	if !match {
		t.Fatal("All-bytes password should verify")
	}
}

// TestArgon2Edge_MalformedHashFormats tests various malformed PHC hash strings.
func TestArgon2Edge_MalformedHashFormats(t *testing.T) {
	malformed := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"garbage", "not-a-hash-at-all"},
		{"wrong_algo", "$bcrypt$v=19$m=47104,t=1,p=1$salt$hash"},
		{"wrong_variant", "$argon2d$v=19$m=47104,t=1,p=1$salt$hash"},
		{"too_few_parts", "$argon2id$v=19$m=47104,t=1,p=1$salt"},
		{"too_many_parts", "$argon2id$v=19$m=47104,t=1,p=1$salt$hash$extra$parts"},
		{"missing_params", "$argon2id$v=19$$salt$hash"},
		{"partial_params", "$argon2id$v=19$m=47104$salt$hash"},
		{"two_params", "$argon2id$v=19$m=47104,t=1$salt$hash"},
		{"invalid_memory", "$argon2id$v=19$m=-1,t=1,p=1$AAAA$AAAA"},
		{"float_memory", "$argon2id$v=19$m=47104.5,t=1,p=1$AAAA$AAAA"},
		{"overflow_memory", "$argon2id$v=19$m=99999999999999,t=1,p=1$AAAA$AAAA"},
		{"param_no_equals", "$argon2id$v=19$m47104,t1,p1$salt$hash"},
		{"param_no_value", "$argon2id$v=19$m=,t=,p=$salt$hash"},
		{"empty_salt", "$argon2id$v=19$m=47104,t=1,p=1$$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"empty_hash_field", "$argon2id$v=19$m=47104,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$"},
	}

	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			match, _ := VerifyPassword("test-password", tc.hash)
			if match {
				t.Fatalf("Malformed hash %q should never verify", tc.name)
			}
		})
	}
}

// TestArgon2Edge_ParameterBounds tests Argon2id parameter boundary enforcement.
func TestArgon2Edge_ParameterBounds(t *testing.T) {
	cases := []struct {
		name    string
		hash    string
		wantErr string
	}{
		{
			"max_valid_iterations",
			"$argon2id$v=19$m=47104,t=10,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"", // Should succeed (t=10 is max)
		},
		{
			"over_max_iterations",
			"$argon2id$v=19$m=47104,t=11,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"iterations exceed maximum",
		},
		{
			"max_valid_parallelism",
			"$argon2id$v=19$m=47104,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"", // p=4 is max
		},
		{
			"over_max_parallelism",
			"$argon2id$v=19$m=47104,t=1,p=5$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"parallelism exceeds maximum",
		},
		{
			"max_valid_memory",
			"$argon2id$v=19$m=131072,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"", // 128 MiB = 131072 KiB is max
		},
		{
			"over_max_memory",
			"$argon2id$v=19$m=131073,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"memory exceeds maximum",
		},
		{
			"min_valid_memory",
			"$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"", // 8 KiB = 8*p (p=1) is minimum
		},
		{
			"below_min_memory",
			"$argon2id$v=19$m=7,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"memory too small",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			match, err := VerifyPassword("test", tc.hash)
			if match {
				// Should not match since we're using a real password against a dummy hash
				// But the parameter validation matters more
				return
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Expected error containing %q, got: %v", tc.wantErr, err)
				}
			}
		})
	}
}

// TestArgon2Edge_OutputFormat tests the PHC format structure in detail.
func TestArgon2Edge_OutputFormat(t *testing.T) {
	hash, _ := HashPassword("format-test-password!")

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("PHC format should have 6 parts, got %d", len(parts))
	}

	// Part 0: empty (before first $)
	if parts[0] != "" {
		t.Fatalf("First part should be empty, got %q", parts[0])
	}

	// Part 1: algorithm
	if parts[1] != "argon2id" {
		t.Fatalf("Algorithm should be argon2id, got %q", parts[1])
	}

	// Part 2: version
	if parts[2] != "v=19" {
		t.Fatalf("Version should be v=19, got %q", parts[2])
	}

	// Part 3: parameters
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		t.Fatalf("Should have 3 parameters, got %d", len(params))
	}

	expectedParams := map[string]string{
		"m": "47104",
		"t": "1",
		"p": "1",
	}

	for _, p := range params {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			t.Fatalf("Parameter %q should be key=value", p)
		}
		expected, ok := expectedParams[kv[0]]
		if !ok {
			t.Fatalf("Unexpected parameter key: %q", kv[0])
		}
		if kv[1] != expected {
			t.Fatalf("Parameter %s should be %s, got %s", kv[0], expected, kv[1])
		}
	}

	// Part 4: salt (base64 without padding)
	if parts[4] == "" {
		t.Fatal("Salt should not be empty")
	}

	// Part 5: hash (base64 without padding)
	if parts[5] == "" {
		t.Fatal("Hash should not be empty")
	}
}

// TestArgon2Edge_WhitespacePasswords tests passwords consisting of various
// whitespace characters.
func TestArgon2Edge_WhitespacePasswords(t *testing.T) {
	passwords := []struct {
		name string
		pw   string
	}{
		{"spaces", "               "}, // 15 spaces
		{"tabs", "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"},
		{"newlines", "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"},
		{"mixed_whitespace", " \t\n\r \t\n\r \t\n\r \t\n\r"},
		{"trailing_space", "password       "},
		{"leading_space", "       password"},
	}

	for _, tc := range passwords {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := HashPassword(tc.pw)
			if err != nil {
				t.Fatalf("Whitespace password %s should be hashable: %v", tc.name, err)
			}
			match, _ := VerifyPassword(tc.pw, hash)
			if !match {
				t.Fatalf("Whitespace password %s should verify", tc.name)
			}
		})
	}
}
