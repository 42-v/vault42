package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
)

// `bridge --version` is what a container healthcheck, a release pipeline and a
// `docker run image --version` smoke test call, on a host where nothing else
// about the deployment exists yet. Two things have to hold and neither is
// obvious from reading main().
//
// It has to be answered before LoadConfig. The test below clears every BRIDGE_*
// variable first, so if the flag check ever moved below the config load, main
// would reach log.Fatalf("bridge: config error") on the two missing upstreams
// and take the whole test binary down with it rather than fail an assertion.
//
// The three values have to come from linker-settable package variables. This
// binary shipped for its whole life reporting "dev" because .goreleaser.yaml
// stamped -X against symbols cmd/bridge did not declare, and a -X naming a
// symbol the binary does not link is dropped without a warning and with exit 0.
// Assigning to all three here is the compile-time half of that guard: turning
// any of them into a constant, or moving them to another package, stops this
// file building. Reading them back out of the printed line is the runtime half.
func TestVersionFlagIsAnsweredFromTheLinkerStampsBeforeAnyConfiguration(t *testing.T) {
	clearBridgeEnv(t)

	oldVersion, oldCommit, oldBuild := Version, GitCommit, BuildTime
	t.Cleanup(func() { Version, GitCommit, BuildTime = oldVersion, oldCommit, oldBuild })
	Version, GitCommit, BuildTime = "1.2.3-stamped", "0ff1ce0", "2026-08-13T00:00:00Z"

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"bridge", "--version"}

	got := captureBridgeStdout(t, main)

	want := fmt.Sprintf("bridge %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
	if got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

// captureBridgeStdout runs fn with os.Stdout redirected to a pipe and returns
// what it wrote. main prints with fmt.Printf, which resolves os.Stdout at call
// time, so the swap is enough.
func captureBridgeStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w

	fn()

	os.Stdout = old
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("close pipe writer: %v", closeErr)
	}

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("read captured stdout: %v", copyErr)
	}
	return buf.String()
}
