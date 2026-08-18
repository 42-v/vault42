//go:build !linux

package main

// hardenProcess has no portable equivalent outside Linux, so on other platforms
// the recovery key is only as protected as the operator's own core-dump and
// ptrace settings. It returns nil rather than an error because failing a legal
// recovery request over a hardening step that does not exist on this build would
// be the worse outcome; the tool is documented to run on the offline Linux host
// that holds the key.
//
// Nothing in this repository exercises this file, on any platform, and that is
// deliberate rather than an oversight waiting to be filled in. CI builds and
// tests Linux only, so a !linux build tag puts this body out of reach of every
// test that could be written for it; and there is nothing here to test - the
// function is a permanent no-op whose entire content is the decision above,
// which is a decision about the build and not about behaviour. Said out loud
// because a body with no test and no note reads the same as a gap.
//
// If a non-Linux build ever becomes something the project ships, this stops
// being a no-op and the equivalent step for that platform belongs here, with a
// test beside it in a file tagged for that platform - the shape
// harden_linux.go and harden_linux_test.go already have.
func hardenProcess() error { return nil }
