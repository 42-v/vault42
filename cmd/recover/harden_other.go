//go:build !linux

package main

// hardenProcess has no portable equivalent outside Linux, so on other platforms
// the recovery key is only as protected as the operator's own core-dump and
// ptrace settings. It returns nil rather than an error because failing a legal
// recovery request over a hardening step that does not exist on this build would
// be the worse outcome; the tool is documented to run on the offline Linux host
// that holds the key.
func hardenProcess() error { return nil }
