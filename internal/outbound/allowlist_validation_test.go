package outbound

import (
	"strconv"
	"strings"
	"testing"
)

// The allowlist and the destination check have to agree about what a host name
// is, and this is the second time in this package that they did not.
//
// hostOf refuses a URL whose host carries non-ASCII bytes, because net/http
// dials the UTS-46 form of a name while a string comparison reads the bytes it
// was given. An operator entry written in the Unicode form is dead under that
// rule: the discovery document arrives as punycode, the entry says something
// else, and the destination is refused while the operator looks at their own
// configuration listing it. ValidateAllowedHosts exists so that mismatch is a
// startup error naming the fix rather than a runtime refusal naming nothing.

func TestValidateAllowedHostsAcceptsWhatTheDestinationCheckCanMatch(t *testing.T) {
	// Every entry here survives hostOf, so every one of them can match a real
	// destination. Punycode is included deliberately: it is the spelling the
	// error message tells operators to use, so it had better be accepted.
	hosts := []string{
		"keys.partner.test",
		"WWW.GOOGLEAPIS.COM",
		"xn--xample-9ua.com",
		"localhost",
		"login.microsoftonline.com",
		"",
		"   ",
	}
	if err := ValidateAllowedHosts(hosts); err != nil {
		t.Errorf("ValidateAllowedHosts(%q) = %v, want nil", hosts, err)
	}
}

func TestValidateAllowedHostsRefusesAnEntryNoDestinationCanMatch(t *testing.T) {
	for _, host := range []string{
		"éxample.com",  // the spelling an operator actually writes
		"exämple.test", // a single non-ASCII byte is enough
		"日本.example",
		"partner .test",    // a non-breaking space, invisible in a shell
		"pa\x00rtner.test", // NUL, below the printable range
	} {
		err := ValidateAllowedHosts([]string{"keys.partner.test", host})
		if err == nil {
			t.Errorf("ValidateAllowedHosts accepted %q, which hostOf refuses; the entry would "+
				"sit in the configuration matching nothing", host)
			continue
		}
		// The operator has to be able to find the offending entry among the
		// others, and to learn the spelling that works.
		if !strings.Contains(err.Error(), strconv.Quote(host)) {
			t.Errorf("refusal of %q does not name it: %v", host, err)
		}
		if !strings.Contains(err.Error(), "punycode") {
			t.Errorf("refusal of %q does not say what to write instead: %v", host, err)
		}
	}
}

// A host this validator accepts must be one hostOf can produce, or the two
// rules have drifted apart again in the direction that made the entry dead.
func TestValidateAllowedHostsAgreesWithHostOf(t *testing.T) {
	for _, host := range []string{"keys.partner.test", "éxample.com", "exämple.test"} {
		validated := ValidateAllowedHosts([]string{host}) == nil
		_, err := hostOf("https://" + host + "/.well-known/openid-configuration")
		reachable := err == nil

		if validated != reachable {
			t.Errorf("%q: allowlist accepts=%v but hostOf accepts=%v. The two checks decide "+
				"what a host name is, and an entry accepted by one and refused by the other is "+
				"configuration that silently does nothing.", host, validated, reachable)
		}
	}
}
