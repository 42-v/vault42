//go:build linux

package main

import (
	"syscall"
	"testing"
)

// prGetDumpable reads back what prSetDumpable wrote (<sys/prctl.h>).
const prGetDumpable = 3

func dumpable(t *testing.T) uintptr {
	t.Helper()
	v, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		t.Fatalf("prctl(PR_GET_DUMPABLE): %v", errno)
	}
	return v
}

// For the length of a run this process holds an RSA private key that opens every
// escrow record the deployment has ever written. A dumpable process can be core
// dumped onto the operator's disk by any crash, and can be ptrace-attached by any
// other process running as the same account - a compromised editor, a browser
// extension host, anything the operator happens to be running on the workstation
// they grabbed for the recovery. Clearing the flag closes both without needing
// root.
//
// This test runs in the test binary rather than a subprocess, so it also proves
// the call is not silently failing on this kernel.
func TestHardenProcess_LeavesTheProcessUndumpable(t *testing.T) {
	// Without this the assertion below could pass on a process that was already
	// undumpable for some unrelated reason, and hardenProcess could be a no-op.
	if before := dumpable(t); before != 1 {
		t.Fatalf("the test process starts at dumpable=%d, so this proves nothing about hardenProcess", before)
	}

	if err := hardenProcess(); err != nil {
		t.Fatalf("hardenProcess: %v", err)
	}

	if after := dumpable(t); after != 0 {
		t.Errorf("dumpable = %d after hardening, want 0: the recovery key stays exposed to core dumps and to same-user ptrace", after)
	}
}
