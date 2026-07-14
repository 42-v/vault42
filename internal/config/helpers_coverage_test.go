package config

import (
	"reflect"
	"testing"
)

func TestSplitTrimLower(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"Acme.TEST", []string{"acme.test"}},
		{"a, B ,, c", []string{"a", "b", "c"}},
		{" , , ", nil},
	}
	for _, tt := range tests {
		if got := splitTrimLower(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitTrimLower(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestPresence(t *testing.T) {
	if presence(nil) != "<not set>" {
		t.Error("presence(nil) should be <not set>")
	}
	if presence([]byte{}) != "<not set>" {
		t.Error("presence(empty) should be <not set>")
	}
	if presence([]byte("key")) != "set" {
		t.Error("presence(non-empty) should be set")
	}
}

func TestIsValidHexColor(t *testing.T) {
	for _, s := range []string{"#00FF42", "#000000", "#abcdef"} {
		if !isValidHexColor(s) {
			t.Errorf("isValidHexColor(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "00FF42", "#FFF", "#gggggg", "#00FF4Z", "#00FF422"} {
		if isValidHexColor(s) {
			t.Errorf("isValidHexColor(%q) = true, want false", s)
		}
	}
}
