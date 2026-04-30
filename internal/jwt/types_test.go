package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNumericDate_MarshalJSON(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	nd := NewNumericDate(ts)

	b, err := json.Marshal(nd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "1700000000" {
		t.Errorf("got %s, want 1700000000", string(b))
	}
}

func TestNumericDate_MarshalJSON_NoFraction(t *testing.T) {
	ts := time.Unix(1700000000, 500000000) // 0.5s of nanos
	nd := NewNumericDate(ts)

	b, err := json.Marshal(nd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Truncated to second, so no fraction
	if string(b) != "1700000000" {
		t.Errorf("got %s, want 1700000000", string(b))
	}
}

func TestNumericDate_UnmarshalJSON_Integer(t *testing.T) {
	var nd NumericDate
	if err := json.Unmarshal([]byte("1700000000"), &nd); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := time.Unix(1700000000, 0)
	if !nd.Equal(want) {
		t.Errorf("got %v, want %v", nd.Time, want)
	}
}

func TestNumericDate_UnmarshalJSON_Float(t *testing.T) {
	var nd NumericDate
	if err := json.Unmarshal([]byte("1700000000.5"), &nd); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Truncated to second
	want := time.Unix(1700000000, 0)
	if !nd.Equal(want) {
		t.Errorf("got %v, want %v", nd.Time, want)
	}
}

func TestNumericDate_Nil(t *testing.T) {
	var nd *NumericDate
	b, err := json.Marshal(nd)
	if err != nil {
		t.Fatalf("marshal nil: %v", err)
	}
	if string(b) != "null" {
		t.Errorf("got %s, want null", string(b))
	}
}

func TestNumericDate_Zero(t *testing.T) {
	nd := NewNumericDate(time.Time{})
	b, err := json.Marshal(nd)
	if err != nil {
		t.Fatalf("marshal zero: %v", err)
	}
	// time.Time{} Unix epoch is negative, but marshaling should still work
	if len(b) == 0 {
		t.Error("zero time marshal produced empty output")
	}
}

func TestNumericDate_RoundTrip(t *testing.T) {
	original := NewNumericDate(time.Unix(1700000000, 0))
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored NumericDate
	if err := json.Unmarshal(b, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !original.Equal(restored.Time) {
		t.Errorf("round-trip mismatch: %v != %v", original.Time, restored.Time)
	}
}

func TestNumericDate_Truncation(t *testing.T) {
	ts := time.Unix(1700000000, 999999999) // Just under +1s
	nd := NewNumericDate(ts)
	if nd.Unix() != 1700000000 {
		t.Errorf("expected truncation to 1700000000, got %d", nd.Unix())
	}
}

func TestClaimStrings_UnmarshalJSON_String(t *testing.T) {
	var cs ClaimStrings
	if err := json.Unmarshal([]byte(`"single"`), &cs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cs) != 1 || cs[0] != "single" {
		t.Errorf("got %v, want [single]", cs)
	}
}

func TestClaimStrings_UnmarshalJSON_Array(t *testing.T) {
	var cs ClaimStrings
	if err := json.Unmarshal([]byte(`["a","b","c"]`), &cs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cs) != 3 || cs[0] != "a" || cs[1] != "b" || cs[2] != "c" {
		t.Errorf("got %v, want [a b c]", cs)
	}
}

func TestClaimStrings_MarshalJSON(t *testing.T) {
	cs := ClaimStrings{"x", "y"}
	b, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `["x","y"]` {
		t.Errorf("got %s, want [\"x\",\"y\"]", string(b))
	}
}

func TestClaimStrings_MarshalJSON_Single(t *testing.T) {
	cs := ClaimStrings{"only"}
	b, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Always marshals as array
	if string(b) != `["only"]` {
		t.Errorf("got %s, want [\"only\"]", string(b))
	}
}

func TestClaimStrings_Empty(t *testing.T) {
	var cs ClaimStrings
	if err := json.Unmarshal([]byte("null"), &cs); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if cs != nil {
		t.Errorf("expected nil, got %v", cs)
	}
}

func TestClaimStrings_EmptyArray(t *testing.T) {
	var cs ClaimStrings
	if err := json.Unmarshal([]byte("[]"), &cs); err != nil {
		t.Fatalf("unmarshal empty array: %v", err)
	}
	if len(cs) != 0 {
		t.Errorf("expected empty, got %v", cs)
	}
}

func TestClaimStrings_InvalidType(t *testing.T) {
	var cs ClaimStrings
	if err := json.Unmarshal([]byte("123"), &cs); err == nil {
		t.Error("expected error for number, got nil")
	}
}

func TestClaimStrings_ArrayWithNonString(t *testing.T) {
	var cs ClaimStrings
	if err := json.Unmarshal([]byte(`["valid", 123]`), &cs); err == nil {
		t.Error("expected error for mixed types, got nil")
	}
}
