package main

// The inactivity timeout, observed in a running process.
//
// VAULT_INACTIVITY_TIMEOUT is measured from a refresh-token family's last
// rotation, and a client in normal use rotates about once per access-token
// lifetime. Set at or below that TTL it stops being an idle bound and becomes a
// hard cap on every session, in use or not: the user is logged out mid-session,
// the audit log calls it session_inactivity_exceeded, and nothing about the
// deployment looks misconfigured. It is a two-character typo away from the
// supported configuration — 15m instead of 15h — so it has to announce itself
// at startup rather than at the first refusal.

import (
	"strings"
	"syscall"
	"testing"
)

// TestAnInactivityTimeoutInsideTheAccessTokenTTLIsAnnouncedAtStartup drives the
// misconfiguration through the real binary.
func TestAnInactivityTimeoutInsideTheAccessTokenTTLIsAnnouncedAtStartup(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)

	env := bootEnv(t, stub, addr)
	env["VAULT_INACTIVITY_TIMEOUT"] = "10m"
	env["VAULT_ACCESS_TOKEN_TTL"] = "15m"

	res := bootAndShutdown(t, vaultRun{env: env}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0,
		"WARNING: VAULT_INACTIVITY_TIMEOUT (10m0s) is not longer than the access token TTL (15m0s)")
	if !strings.Contains(res.stderr, "terminated as if they were idle") {
		t.Fatalf("the inactivity warning does not say what breaks\nstderr:\n%s", res.stderr)
	}
}

// The control for the test above, and it is the half that matters more. The
// shipped default is 1h against a 15m access token TTL, which is the supported
// configuration; a warning that also fired there would appear on every healthy
// deployment and be scrolled past by the time it mattered.
func TestTheDefaultInactivityTimeoutIsNotWarnedAbout(t *testing.T) {
	stub := bootedStub(t)
	addr := freeAddr(t)

	res := bootAndShutdown(t, vaultRun{env: bootEnv(t, stub, addr)}, addr, syscall.SIGTERM, nil)

	requireExit(t, res, 0, "")
	if strings.Contains(res.stderr, "VAULT_INACTIVITY_TIMEOUT") {
		t.Errorf("the shipped default was warned about\nstderr:\n%s", res.stderr)
	}
}
