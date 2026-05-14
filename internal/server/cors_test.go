package server

import (
	"reflect"
	"testing"
)

func TestParseCORSOriginsEmpty(t *testing.T) {
	if got := parseCORSOrigins(""); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestParseCORSOriginsSingle(t *testing.T) {
	got := parseCORSOrigins("https://app.example.com")
	want := []string{"https://app.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseCORSOriginsMultipleWithWhitespace(t *testing.T) {
	got := parseCORSOrigins("  https://a.example.com , https://b.example.com,  ,https://c.example.com  ")
	want := []string{"https://a.example.com", "https://b.example.com", "https://c.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
