package main

import (
	"testing"
)

// The allowlist used to be one flat list of strings compared against the common
// name, then the DNS SANs, then the email SANs, then the URI SANs. An operator
// who wrote ADMIN_GW_CLIENT_CN_ALLOWLIST=admin-operator meaning "the common
// name" got a pin whose field the certificate holder chose: a certificate with
// CN=some-service and DNSNames=["admin-operator"] passed, and so did the email
// and URI spellings.
//
// That matters beyond tidiness. Go applies X.509 name constraints to SANs only,
// so a name-constrained sub-CA in the bundle -- one an operator added precisely
// to bound what it may issue -- can still mint a certificate carrying an
// allowlisted common name and no SANs at all.
//
// An entry now names its field: cn:, dns:, email: or uri:.
func TestAllowlistEntriesNameTheFieldTheyPin(t *testing.T) {
	const (
		spiffeID = "spiffe://vault42.test/ns/admin/sa/operator"
		mailbox  = "ops@vault.test"
		hostname = "ops.vault.internal"
	)

	tests := []struct {
		name string
		// entry is the allowlist the gateway boots with.
		entry string
		// pinned carries the identity in the field entry names.
		pinned clientSpec
		// misfiled carries the same string in a different field, which must not
		// be enough. This is the confusion the untyped list allowed.
		misfiled clientSpec
	}{
		{
			name:     "cn: pins the common name",
			entry:    "cn:admin-operator",
			pinned:   clientSpec{cn: "admin-operator"},
			misfiled: clientSpec{cn: "some-service", dns: []string{"admin-operator"}},
		},
		{
			name:     "dns: pins a DNS SAN",
			entry:    "dns:" + hostname,
			pinned:   clientSpec{cn: "decorative", dns: []string{hostname}},
			misfiled: clientSpec{cn: hostname},
		},
		{
			name:     "email: pins an email SAN",
			entry:    "email:" + mailbox,
			pinned:   clientSpec{cn: "decorative", emails: []string{mailbox}},
			misfiled: clientSpec{cn: "decorative", dns: []string{mailbox}},
		},
		{
			name:     "uri: pins a URI SAN",
			entry:    "uri:" + spiffeID,
			pinned:   clientSpec{cn: "mesh-issued", uris: []string{spiffeID}},
			misfiled: clientSpec{cn: "mesh-issued", dns: []string{spiffeID}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST="+tt.entry)

			f.mustReach(t, f.pki.issueClientSpec(t, tt.pinned),
				"the certificate carrying "+tt.entry+" in the field the entry names")
			f.mustBeRefused(t, f.pki.issueClientSpec(t, tt.misfiled),
				"a certificate carrying the pinned string in a field the entry does not name")

			c.stopCleanly(t)
		})
	}
}

// A leaf that carries any SAN is one whose common name means nothing. That is
// the CA/Browser Forum rule and RFC 5280 has called the CN deprecated for
// identity for twenty years, but the reason it belongs in a gateway is narrower:
// the CN is the one name field X.509 name constraints do not cover, so honoring
// it on a certificate that also carries SANs hands the pin to whoever holds a
// constrained sub-CA key.
//
// So an allowlist entry -- typed cn: or untyped -- matches the common name only
// on a certificate with no SAN at all.
func TestACommonNamePinIsIgnoredWhenTheCertificateCarriesSANs(t *testing.T) {
	f := newFixture(t)
	c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST=admin-operator")

	f.mustBeRefused(t, f.pki.issueClientSpec(t, clientSpec{
		cn:  "admin-operator",
		dns: []string{"workload.svc.cluster.local"},
	}), "a certificate whose allowlisted common name sits beside an unallowlisted SAN")

	// And the compatibility half: the same allowlist still admits the certificate
	// it was written for, which carries no SAN.
	f.mustReach(t, f.pki.clientCert, "the SAN-less operator certificate the entry was written for")

	c.stopCleanly(t)
}

// An untyped entry has to keep working, because every deployment that set the
// variable before this change has one. What it may mean is the question, and the
// answer has to be the narrow one: a DNS SAN, plus the common name only when
// there is no SAN to prefer.
//
// Anything wider puts the choice back in the certificate holder's hands, which
// is the defect. Email and URI identities are still pinnable -- with email: and
// uri:, which say so.
func TestAnUntypedAllowlistEntryMatchesOnlyDNSNamesAndASANLessCommonName(t *testing.T) {
	const spiffeID = "spiffe://vault42.test/ns/admin/sa/operator"
	const mailbox = "ops@vault.test"
	const hostname = "ops.vault.internal"

	t.Run("an email SAN is not matched", func(t *testing.T) {
		f := newFixture(t)
		c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST="+mailbox)
		f.mustBeRefused(t, f.pki.issueClientSpec(t, clientSpec{cn: "decorative", emails: []string{mailbox}}),
			"an email SAN matched against an untyped entry")
		c.stopCleanly(t)
	})

	t.Run("a URI SAN is not matched", func(t *testing.T) {
		f := newFixture(t)
		c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST="+spiffeID)
		f.mustBeRefused(t, f.pki.issueClientSpec(t, clientSpec{cn: "mesh-issued", uris: []string{spiffeID}}),
			"a URI SAN matched against an untyped entry")
		c.stopCleanly(t)
	})

	t.Run("a DNS SAN is matched", func(t *testing.T) {
		f := newFixture(t)
		c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST="+hostname)
		f.mustReach(t, f.pki.issueClientSpec(t, clientSpec{cn: "decorative", dns: []string{hostname}}),
			"a DNS SAN matched against an untyped entry")
		c.stopCleanly(t)
	})
}

// An untyped entry is a guess the gateway makes on the operator's behalf, and
// the operator has to be able to read that off the startup log -- the same shape
// the empty-allowlist warning already has. Without it, the narrowing above is
// silent: a deployment that pinned a URI SAN with an untyped entry stops
// admitting anyone on upgrade and the log says nothing about why.
func TestUntypedAllowlistEntriesAreNamedAtStartup(t *testing.T) {
	f := newFixture(t)
	c := f.start(t, "ADMIN_GW_CLIENT_CN_ALLOWLIST=admin-operator,dns:ops.vault.internal")

	c.waitForLog(t, "carry no field prefix")
	c.waitForLog(t, "admin-operator")

	c.stopCleanly(t)
}
