package fuzz

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/service"
)

// FuzzServiceDocumentJSON walks the token-stream validator that sits in
// front of every service-document write. A 64 KiB nest of '[' used to be
// a stack-bomb; this target exists so that class of input stays a
// structured rejection.
func FuzzServiceDocumentJSON(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":{"b":[1,2,{"c":true}]}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(``))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{"a":1}{"b":2}`))
	f.Add([]byte("\xff\xfe"))
	f.Add([]byte(`{"` + strings.Repeat("k", 200) + `":1}`))
	deep := bytes.Repeat([]byte(`{"x":`), 40)
	deep = append(deep, '1')
	deep = append(deep, bytes.Repeat([]byte(`}`), 40)...)
	f.Add(deep)
	bomb := bytes.Repeat([]byte{'['}, 64)
	f.Add(bomb)

	f.Fuzz(func(t *testing.T, raw []byte) {
		err := service.ValidateDocumentStructure(raw)
		if err != nil {
			if err != service.ErrSvcDocInvalidDocument && err != service.ErrSvcDocTooLarge {
				t.Fatalf("unexpected error %v (want ErrSvcDocInvalidDocument or ErrSvcDocTooLarge)", err)
			}
			return
		}
		if jsonObjectHasDuplicateKeys(raw) {
			t.Fatalf("validator accepted a document with a duplicate key: %q", raw)
		}
		// An accepted body must be a single JSON object that unmarshals.
		var decoded map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if decErr := dec.Decode(&decoded); decErr != nil {
			t.Fatalf("validator accepted %q but json.Decoder rejected it: %v", raw, decErr)
		}
		if _, trail := dec.Token(); trail == nil {
			t.Fatalf("validator accepted a body with trailing tokens: %q", raw)
		}
	})
}

// FuzzMintSubject is the charset gate on the POST /mint "subject" field.
func FuzzMintSubject(f *testing.F) {
	f.Add("user-1")
	f.Add("alice@example.com")
	f.Add("")
	f.Add("1")
	f.Add("_leading_underscore")
	f.Add("has space")
	f.Add("has/slash")
	f.Add(strings.Repeat("a", 128))
	f.Add(strings.Repeat("a", 129))
	f.Add("user\n1")
	f.Add("user\x00id")

	f.Fuzz(func(t *testing.T, subject string) {
		err := service.ValidateMintSubject(subject)
		if err != nil {
			if err != service.ErrMintSubjectInvalid {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if subject == "" || len(subject) > 128 {
			t.Fatalf("accepted an empty or over-long subject %q", subject)
		}
		if subject[0] < '0' || (subject[0] > '9' && subject[0] < 'A') || (subject[0] > 'Z' && subject[0] < 'a') || subject[0] > 'z' {
			t.Fatalf("accepted a subject that does not start with alphanumeric: %q", subject)
		}
		for i := 1; i < len(subject); i++ {
			c := subject[i]
			ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '.' || c == '_' || c == '@' || c == '-'
			if !ok {
				t.Fatalf("accepted a subject with a forbidden byte %q at %d: %q", c, i, subject)
			}
		}
	})
}

// FuzzMintTTLFromSeconds is the seconds-to-Duration conversion that must
// refuse values that wrap int64 nanoseconds back inside the ceiling.
func FuzzMintTTLFromSeconds(f *testing.F) {
	f.Add(0)
	f.Add(1)
	f.Add(300)
	f.Add(900)
	f.Add(901)
	f.Add(-1)
	f.Add(int(1 << 30))

	f.Fuzz(func(t *testing.T, seconds int) {
		d, err := service.MintTTLFromSeconds(seconds)
		if seconds < 0 || seconds > 900 {
			if err == nil {
				t.Fatalf("MintTTLFromSeconds(%d) = %v, want error", seconds, d)
			}
			return
		}
		if err != nil {
			t.Fatalf("MintTTLFromSeconds(%d) rejected an in-range value: %v", seconds, err)
		}
		if d != 0 && int(d.Seconds()) != seconds {
			t.Fatalf("MintTTLFromSeconds(%d) = %v, seconds do not round-trip", seconds, d)
		}
	})
}

// jsonObjectHasDuplicateKeys reports a repeated key at any nesting level.
// encoding/json last-wins, so an accept-path that only unmarshals cannot
// see the duplicate the store must refuse.
func jsonObjectHasDuplicateKeys(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return walkDup(dec)
}

func walkDup(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return false
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return false
			}
			ks, ok := k.(string)
			if !ok {
				return false
			}
			if _, dup := seen[ks]; dup {
				return true
			}
			seen[ks] = struct{}{}
			if walkDup(dec) {
				return true
			}
		}
		_, _ = dec.Token() // closing }
	case '[':
		for dec.More() {
			if walkDup(dec) {
				return true
			}
		}
		_, _ = dec.Token()
	}
	return false
}
