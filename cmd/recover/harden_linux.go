//go:build linux

package main

import "syscall"

// prSetDumpable is PR_SET_DUMPABLE from <sys/prctl.h>, and 0 is SUID_DUMP_DISABLE.
// Spelled out rather than taken from golang.org/x/sys so the offline recovery tool
// keeps building from the standard library alone.
const (
	prSetDumpable = 4
	dumpDisable   = 0
)

// hardenProcess clears the process's dumpable flag for the life of the run.
//
// This process holds the recovery private key in memory, and that key opens every
// escrow record the deployment has ever written, including records already swept
// past the retention horizon but still present in a backup. Two things follow from
// dumpable=0 and neither needs root: the kernel writes no core dump if the process
// crashes, and ptrace_may_access refuses an attach from any process without
// CAP_SYS_PTRACE, including one running as the same operator account.
func hardenProcess() error {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, dumpDisable, 0); errno != 0 {
		return errno
	}
	return nil
}
