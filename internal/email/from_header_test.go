package email

import (
	"strings"
	"testing"
)

// The From header is assembled from a tenant-controlled display name and an address. A
// display name that is allowed to carry its own angle brackets or a comma can turn one
// header into two addresses, or make the mail appear to come from somebody else — the
// display name is what a mail client actually shows the recipient, so a forged one is a
// phishing mail sent from our own infrastructure, over our own DKIM signature.
//
// A name that sanitises down to nothing must leave the bare address rather than an empty
// display name that brackets it strangely.
func TestFormatFromHeader(t *testing.T) {
	cases := []struct {
		name    string
		display string
		addr    string
		want    string
	}{
		{"no display name leaves the bare address", "", "noreply@vault.example", "noreply@vault.example"},
		{"a name that sanitises to nothing leaves the bare address", "\r\n", "noreply@vault.example", "noreply@vault.example"},
		{"a plain name is quoted properly", "BeOn3", "noreply@vault.example", `"BeOn3" <noreply@vault.example>`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatFromHeader(tc.display, tc.addr)

			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			for _, bad := range []string{"\r", "\n"} {
				if strings.Contains(got, bad) {
					t.Errorf("a control character survived into the From header: %q", got)
				}
			}
		})
	}
}
