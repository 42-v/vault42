package testutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Container-runtime detection for every suite that starts a testcontainer.
//
// Detection used to be `os.Stat(sock)`: the first candidate socket whose inode
// existed won. A rootless podman can leave its socket file in place while the
// API stops answering, and that is not a hypothetical — it is the state of the
// development host this was written on. Presence-based detection then picks the
// wedged socket over a working docker one, testcontainers dials it, and the
// whole package blocks until the test binary's timeout fires. One suite bought
// a 60-second panic where the first second could have reported the truth, and
// the suites behind a sync.Once shared container blocked forever behind it.
//
// scripts/lib/coverage-env.sh learned this in "fix(coverage): probe the
// container socket instead of trusting its presence". The Go side had not, so
// the lesson is applied here in the same shape: probe, walk past a candidate
// that does not answer, and bound every wait.

const (
	// containerProbeTimeout bounds one candidate probe end to end — dial,
	// request and body read. Every wait in this file is bounded by it, so the
	// worst case for detection is len(candidates) * containerProbeTimeout and
	// never an indefinite block.
	containerProbeTimeout = 4 * time.Second

	// containerProbePath is the endpoint a live daemon answers and a wedged one
	// does not. /_ping is deliberately NOT used: it is the endpoint that keeps
	// returning OK from a rootless podman whose /version and /info have stopped
	// responding, so probing it reproduces the presence bug over HTTP.
	containerProbePath = "/v1.41/version"
)

// containerRuntime is the resolved detection result: the DOCKER_HOST of a
// daemon that answered, plus what every candidate did on the way there.
type containerRuntime struct {
	host  string
	trace []string
}

// resolveContainerRuntime probes once per test binary and caches the answer.
//
// Once rather than per call because a probe costs a round trip and the skip
// path is taken by every test in a suite; caching a negative result also means
// a runtime-free machine pays the probe budget one time instead of once per
// test function.
var resolveContainerRuntime = sync.OnceValue(func() containerRuntime {
	rt := pickContainerHost(containerCandidates())
	if rt.host == "" {
		return rt
	}
	// os.Setenv, not t.Setenv. t.Setenv restores the previous value when the
	// test that called it ends, so the next test in the package would re-probe,
	// and it panics outright in any test that has called t.Parallel. The value
	// set here is only ever set, never cleared, so nothing observes a torn state.
	_ = os.Setenv("DOCKER_HOST", rt.host)
	// Ryuk (testcontainers' reaper) needs write access to the container socket,
	// which trips SELinux AVC denials on rootless podman + Fedora. The canonical
	// coverage run disables it for that reason; a bare `go test ./...` did not,
	// so the same host produced two different outcomes. Only set when the
	// operator has expressed no opinion.
	if os.Getenv("TESTCONTAINERS_RYUK_DISABLED") == "" {
		_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	}
	return rt
})

// containerCandidates lists the hosts to probe, most specific first.
//
// A set DOCKER_HOST is returned alone and no fallback follows it. It is an
// explicit operator choice, and silently starting containers on some other
// daemon because the named one was down would be a worse answer than skipping.
func containerCandidates() []string {
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
		return []string{host}
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = "/run/user/" + strconv.Itoa(os.Getuid())
	}
	return []string{
		"unix://" + runtimeDir + "/podman/podman.sock",
		"unix:///run/podman/podman.sock",
		"unix://" + runtimeDir + "/docker.sock",
		"unix:///var/run/docker.sock",
		"unix:///run/docker.sock",
	}
}

// pickContainerHost returns the first candidate that answers, and a trace line
// per candidate saying what it did. It is separate from resolveContainerRuntime
// so the walk-past-a-wedged-socket behaviour can be tested against sockets a
// test controls rather than against whatever the host happens to be running.
func pickContainerHost(candidates []string) containerRuntime {
	rt := containerRuntime{}
	for _, host := range candidates {
		if err := probeContainerHost(host); err != nil {
			rt.trace = append(rt.trace, host+": "+err.Error())
			continue
		}
		rt.trace = append(rt.trace, host+": answered "+containerProbePath)
		rt.host = host
		return rt
	}
	return rt
}

// containerDialTarget maps a DOCKER_HOST URL onto a net.Dial network/address.
//
// ok is false for the schemes this probe cannot speak (ssh://, npipe://). Those
// are trusted rather than rejected: an operator who points DOCKER_HOST at an SSH
// remote has made a deliberate choice, and refusing it because the probe is
// unimplemented would break a working setup.
func containerDialTarget(host string) (network, address string, ok bool) {
	if rest, found := strings.CutPrefix(host, "unix://"); found {
		return "unix", rest, true
	}
	if rest, found := strings.CutPrefix(host, "tcp://"); found {
		return "tcp", rest, true
	}
	if rest, found := strings.CutPrefix(host, "http://"); found {
		return "tcp", rest, true
	}
	return "", "", false
}

// probeContainerHost reports whether a daemon is not merely listening but
// serving. nil means it answered containerProbePath with 200 inside the budget.
func probeContainerHost(host string) error {
	network, address, ok := containerDialTarget(host)
	if !ok {
		return nil
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	// Both a Client.Timeout and a request context: the timeout covers the whole
	// exchange including the body read, which is where a half-wedged daemon that
	// sends headers and then stops would otherwise park a test forever.
	client := &http.Client{Transport: transport, Timeout: containerProbeTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), containerProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://containers"+containerProbePath, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)); err != nil {
		return fmt.Errorf("reading %s: %w", containerProbePath, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", containerProbePath, resp.StatusCode)
	}
	return nil
}

// ContainerRuntimeAvailable reports whether a container daemon answered.
//
// It never blocks longer than the detection budget, and the answer is computed
// once per test binary.
func ContainerRuntimeAvailable() bool {
	return resolveContainerRuntime().host != ""
}

// ContainerRuntimeHost returns the DOCKER_HOST of the daemon that answered, or
// "" when none did. DOCKER_HOST is exported to the process as a side effect of
// the first call, so testcontainers picks up the same daemon this probed.
func ContainerRuntimeHost() string {
	return resolveContainerRuntime().host
}

// RequireContainerRuntime points DOCKER_HOST at a container daemon that answers,
// or skips the test.
//
// Skipping rather than failing keeps a runtime-free machine distinguishable from
// a broken repository; the canonical coverage run refuses to start without a
// runtime (cov_require_runtime), so nothing is silently skipped there. The skip
// message carries the full probe trace, because "no container runtime" and "the
// runtime you have is wedged" need different fixes and an operator cannot tell
// them apart from the outcome alone.
func RequireContainerRuntime(t *testing.T) {
	t.Helper()
	if os.Getenv("SKIP_INTEGRATION") == "1" {
		t.Skip("SKIP_INTEGRATION=1")
	}
	rt := resolveContainerRuntime()
	if rt.host == "" {
		t.Skipf("no container runtime answered %s within %s per candidate; probed:\n\t%s\n"+
			"Start a daemon or set DOCKER_HOST to one that answers.",
			containerProbePath, containerProbeTimeout, strings.Join(rt.trace, "\n\t"))
	}
}
