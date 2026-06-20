package service

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestIdentityData_Validate(t *testing.T) {
	big := make(map[string]json.RawMessage)
	big["legacy.blob"] = json.RawMessage(`"` + strings.Repeat("x", dynamicMaxBytes) + `"`)

	tests := []struct {
		name    string
		data    IdentityData
		wantErr bool
	}{
		{"empty is valid", IdentityData{}, false},
		{"full valid profile", IdentityData{
			GivenName: "Ada", FamilyName: "Lovelace", Username: "ada",
			Country: "GB", State: "ENG", DateOfBirth: "1815-12-10", Sex: "female",
			MarketingEmails: boolPtr(true),
			Dynamic:         map[string]json.RawMessage{"legacy.forum": json.RawMessage(`{"reputation":42}`)},
		}, false},
		{"username too short", IdentityData{Username: "ab"}, true},
		{"username too long", IdentityData{Username: strings.Repeat("a", 33)}, true},
		{"country not 2 letters", IdentityData{Country: "GBR"}, true},
		{"state too long", IdentityData{State: "ABCD"}, true},
		{"sex invalid", IdentityData{Sex: "other"}, true},
		{"dob wrong format", IdentityData{DateOfBirth: "10/12/1815"}, true},
		{"dob impossible date", IdentityData{DateOfBirth: "2021-02-30"}, true},
		{"dynamic key uppercase", IdentityData{Dynamic: map[string]json.RawMessage{"the legacy platform": json.RawMessage(`1`)}}, true},
		{"dynamic value invalid json", IdentityData{Dynamic: map[string]json.RawMessage{"legacy.x": json.RawMessage(`{`)}}, true},
		{"dynamic oversized", IdentityData{Dynamic: big}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.data.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("error should wrap ErrInvalidProfile, got %v", err)
			}
		})
	}
}

// New fields must survive a JSON round-trip (this is how the blob is stored).
func TestIdentityData_RoundTrip(t *testing.T) {
	in := IdentityData{
		Username: "rider", State: "CA", MarketingEmails: boolPtr(false),
		Dynamic: map[string]json.RawMessage{"legacy.garage": json.RawMessage(`{"vehicles":3}`)},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out IdentityData
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Username != "rider" || out.State != "CA" {
		t.Fatalf("fields lost: %+v", out)
	}
	if out.MarketingEmails == nil || *out.MarketingEmails != false {
		t.Fatalf("marketing flag lost: %+v", out.MarketingEmails)
	}
	if string(out.Dynamic["legacy.garage"]) != `{"vehicles":3}` {
		t.Fatalf("dynamic lost: %s", out.Dynamic["legacy.garage"])
	}
}

// A pre-extension blob (only the old fields) must still decode cleanly.
func TestIdentityData_BackwardCompatDecode(t *testing.T) {
	legacy := `{"given_name":"Old","family_name":"Record","country":"SK","sex":"male"}`
	var out IdentityData
	if err := json.Unmarshal([]byte(legacy), &out); err != nil {
		t.Fatalf("legacy blob failed to decode: %v", err)
	}
	if out.GivenName != "Old" || out.Country != "SK" {
		t.Fatalf("legacy fields lost: %+v", out)
	}
	if out.MarketingEmails != nil || out.Dynamic != nil {
		t.Fatalf("absent new fields should be nil: %+v", out)
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("legacy record should validate: %v", err)
	}
}
