//go:build linux

package main

import (
	"os"
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

// procSelfOwner reports the uid owning this process's own /proc entries.
//
// It is a second, independent view of the dumpable flag, and it is the one that
// shows what the flag buys: the kernel reassigns /proc/<pid>/* to root the
// moment a process becomes undumpable (fs/proc/base.c task_dump_owner), and
// /proc/<pid>/mem is mode 0600, so the same-user process that could have read
// the recovery key straight out of memory can no longer open it. prctl
// (PR_GET_DUMPABLE) on its own only reports back what prctl was told.
//
// /proc/<pid>/status carries no Dumpable line on any Linux - the flag is not
// published there - so this stat is the readable substitute.
//
// Vacuous for a test binary running as root, since the owner is already 0 and
// CAP_DAC_OVERRIDE opens the file either way; callers below skip it in that case
// rather than assert something that cannot fail.
func procSelfOwner(t *testing.T) uint32 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/status", &st); err != nil {
		t.Fatalf("stat /proc/self/status: %v", err)
	}
	return st.Uid
}

// procOwnerIsMeaningful is false when the test binary runs as root, where the
// /proc owner is 0 whether or not the process is dumpable.
func procOwnerIsMeaningful() bool { return os.Getuid() != 0 }

// resetDumpable puts the kernel default back and refuses to continue if it did
// not take. run() hardens the process it is called in, so by the time any test
// here runs another test has almost certainly cleared the flag already, and an
// assertion made without this preamble would pass against code that never
// touched it.
func resetDumpable(t *testing.T) {
	t.Helper()
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, dumpUser, 0); errno != 0 {
		t.Fatalf("prctl(PR_SET_DUMPABLE, SUID_DUMP_USER): %v", errno)
	}
	if before := dumpable(t); before != dumpUser {
		t.Fatalf("the test process starts at dumpable=%d, so nothing below proves anything about the hardening", before)
	}
	if !procOwnerIsMeaningful() {
		return
	}
	if before, me := procSelfOwner(t), uint32(os.Getuid()); before != me { // #nosec G115 -- a uid is non-negative
		t.Fatalf("/proc/self is owned by uid %d and not by this process's own uid %d before the run, "+
			"so the ownership check below cannot tell the hardening from the starting state", before, me)
	}
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
	resetDumpable(t)

	if err := hardenProcess(); err != nil {
		t.Fatalf("hardenProcess: %v", err)
	}

	if after := dumpable(t); after != 0 {
		t.Errorf("dumpable = %d after hardening, want 0: the recovery key stays exposed to core dumps and to same-user ptrace", after)
	}
}

// The wiring, not the function. The test above calls hardenProcess() itself, so
// it says nothing about whether the tool ever calls it: replacing run()'s first
// statement with `_ = hardenProcess` left the entire suite green, and the
// shipped tool then held the recovery private key - the key that opens every
// escrow record the deployment has ever written - in a process that stayed
// core-dumpable and ptrace-attachable for the whole run.
//
// So this asserts on the state run() leaves behind rather than on the step it is
// supposed to take, and it does so on both an ordinary run and one that returns
// early, because the hardening has to happen before the key is read rather than
// somewhere along the successful path.
func TestRun_LeavesTheProcessUndumpable(t *testing.T) {
	tests := []struct {
		name     string
		args     func(t *testing.T) ([]string, *opened)
		wantCode int
	}{
		{
			name: "a run that recovers a record",
			args: func(t *testing.T) ([]string, *opened) {
				o, base := withRows(t, goodRow(t, sampleEmail))
				return base, o
			},
			wantCode: 0,
		},
		{
			// Returns at the flag parser, long before the key file is opened.
			// The hardening still has to have happened: run() is what holds the
			// key on every path, so the flag is cleared as its first statement
			// and not somewhere further down.
			name: "a run that stops at an unparseable command line",
			args: func(t *testing.T) ([]string, *opened) {
				o := &opened{rows: &fakeRows{}}
				return []string{"--dump-key"}, o
			},
			wantCode: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, o := tc.args(t)
			resetDumpable(t)

			got := exercise(t, args, o)
			if got.code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d\n%s", got.code, tc.wantCode, got.stderr)
			}

			if after := dumpable(t); after != 0 {
				t.Errorf("dumpable = %d after run() returned, want 0: the tool never hardened the process "+
					"it holds the recovery key in, so a crash core-dumps the key and any same-user process can ptrace it out", after)
			}
			if procOwnerIsMeaningful() {
				if after := procSelfOwner(t); after != 0 {
					t.Errorf("/proc/self is still owned by uid %d after run() returned, want root: "+
						"/proc/<pid>/mem is readable to any other process running as this operator, "+
						"which is the recovery key in plain memory", after)
				}
			}
		})
	}
}
