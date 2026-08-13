//go:build linux

package main

import (
	"syscall"
	"testing"
)

// prGetDumpable reads back what prSetDumpable wrote, and dumpUser is
// SUID_DUMP_USER, the value a process starts life with (<sys/prctl.h>).
const (
	prGetDumpable = 3
	dumpUser      = 1
)

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
	// run() hardens the process it is called in, so any test above this one has
	// already cleared the flag and the assertion below would pass on a process
	// hardenProcess never touched. Put the kernel default back first: without a
	// known starting value this test cannot tell a working prctl from a no-op.
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, dumpUser, 0); errno != 0 {
		t.Fatalf("prctl(PR_SET_DUMPABLE, SUID_DUMP_USER): %v", errno)
	}
	if before := dumpable(t); before != dumpUser {
		t.Fatalf("the test process starts at dumpable=%d, so this proves nothing about hardenProcess", before)
	}

	if err := hardenProcess(); err != nil {
		t.Fatalf("hardenProcess: %v", err)
	}

	if after := dumpable(t); after != 0 {
		t.Errorf("dumpable = %d after hardening, want 0: the recovery key stays exposed to core dumps and to same-user ptrace", after)
	}
}
