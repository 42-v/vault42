package fuzz

import (
	"encoding/json"
	"testing"

	"github.com/42-v/vault42/internal/service"
)

// FuzzIdentityValidate feeds random JSON to the user-controllable identity
// profile parser + validator (the PUT /user/identity path: decode -> Validate).
// The new username/state/sex/dynamic-JSON validation must never panic on
// attacker-supplied input — it should only ever return nil or ErrInvalidProfile.
func FuzzIdentityValidate(f *testing.F) {
	f.Add(`{"username":"v","sex":"male","country":"SK","state":"BA"}`)
	f.Add(`{"dynamic":{"forum.posts":123,"garage.cars":["a"]}}`)
	f.Add(`{"date_of_birth":"1990-01-01","marketing_emails":true}`)
	f.Add(`{"username":""}`)
	f.Add(`{"dynamic":{"BAD KEY":1}}`)
	f.Add(``)
	f.Add(`{`)
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, raw string) {
		var d service.IdentityData
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			return // malformed JSON is rejected upstream by the handler decoder
		}
		// Must never panic regardless of input.
		_ = d.Validate()
	})
}
