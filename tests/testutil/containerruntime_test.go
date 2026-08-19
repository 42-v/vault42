package testutil

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The bug these tests hold shut: detection used to accept any socket whose
// inode existed. A rootless podman that has stopped answering leaves its socket
// in place, so presence-based detection selected it over a working docker
// daemon and every container-backed suite blocked until its test timeout.
//
// Both halves of that condition are reproduced below with sockets the test
// owns: a wedged listener that accepts connections and then never replies, and
// a healthy one that answers /version. A presence-only detector passes nothing
// here — it cannot even distinguish the two, since both files exist.

// listenUnix starts srv on a unix socket inside the test's temp dir and returns
// the DOCKER_HOST spelling of its path.
//
// The path is deliberately short: a unix socket address is capped at ~108 bytes
// by the kernel, and the default t.TempDir() name plus a socket name can exceed
// it on a long TMPDIR.
func listenUnix(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "crt")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "unix://" + path
}

// wedgedSocket reproduces the failure mode exactly: /_ping answers OK, and
// every other endpoint accepts the request and then never replies. That is what
// /run/user/1000/podman/podman.sock does on the host this was written on.
func wedgedSocket(t *testing.T) string {
	t.Helper()
	return listenUnix(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			_, _ = w.Write([]byte("OK"))
			return
		}
		<-r.Context().Done()
	}))
}

// healthySocket answers the probe endpoint the way a live daemon does.
func healthySocket(t *testing.T) string {
	t.Helper()
	return listenUnix(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/version") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"Version":"29.6.0","ApiVersion":"1.55"}`))
	}))
}

func TestProbeRejectsASocketThatIsPresentButNotAnswering(t *testing.T) {
	host := wedgedSocket(t)

	start := time.Now()
	err := probeContainerHost(host)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("probe accepted a socket that never answered; presence is not evidence of service")
	}
	// The point of the probe is that it returns. A budget that could be
	// exceeded silently would put the hang back one level down.
	if elapsed > 2*containerProbeTimeout {
		t.Errorf("probe took %s, budget is %s", elapsed, containerProbeTimeout)
	}
}

func TestProbeAcceptsASocketThatAnswers(t *testing.T) {
	if err := probeContainerHost(healthySocket(t)); err != nil {
		t.Fatalf("probe rejected a daemon that answered: %v", err)
	}
}

// A socket serving something that is not a container daemon is rejected: the
// probe is about the API answering, not about the port being open.
func TestProbeRejectsASocketThatAnswersWithAnError(t *testing.T) {
	host := listenUnix(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	if err := probeContainerHost(host); err == nil {
		t.Fatal("probe accepted an HTTP 500 from the version endpoint")
	}
}

// The regression itself: a wedged candidate ahead of a working one must not win.
func TestDetectionWalksPastAWedgedCandidateToAWorkingOne(t *testing.T) {
	wedged := wedgedSocket(t)
	healthy := healthySocket(t)

	rt := pickContainerHost([]string{wedged, healthy})

	if rt.host != healthy {
		t.Fatalf("selected %q, want the daemon that answers (%q)", rt.host, healthy)
	}
	if len(rt.trace) != 2 {
		t.Fatalf("trace = %v, want one line per candidate probed", rt.trace)
	}
	if !strings.Contains(rt.trace[0], wedged) {
		t.Errorf("trace does not name the candidate it walked past: %v", rt.trace)
	}
}

// No candidate answering must produce an empty result promptly, not a block.
// The suites call this on every skip, so an unbounded path here would stall a
// machine that simply has no container runtime.
func TestDetectionReturnsNothingWhenNoCandidateAnswers(t *testing.T) {
	wedged := wedgedSocket(t)
	missing := "unix:///nonexistent/vault42-no-such.sock"

	start := time.Now()
	rt := pickContainerHost([]string{missing, wedged})
	elapsed := time.Since(start)

	if rt.host != "" {
		t.Fatalf("selected %q with no candidate answering", rt.host)
	}
	if elapsed > 3*containerProbeTimeout {
		t.Errorf("detection took %s for 2 candidates, budget is %s each", elapsed, containerProbeTimeout)
	}
	if len(rt.trace) != 2 {
		t.Fatalf("trace = %v, want one line per candidate probed", rt.trace)
	}
}

// A DOCKER_HOST the probe cannot speak is trusted rather than rejected, so an
// operator pointing at an SSH remote is not skipped by an unimplemented probe.
func TestAnUnprobeableSchemeIsTrusted(t *testing.T) {
	if err := probeContainerHost("ssh://builder@example.invalid"); err != nil {
		t.Fatalf("ssh:// DOCKER_HOST rejected by a probe that cannot speak it: %v", err)
	}
}

// A set DOCKER_HOST is the only candidate. Falling through to a local socket
// would start containers on a daemon the operator did not name.
func TestASetDockerHostIsTheOnlyCandidate(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	got := containerCandidates()
	if len(got) != 1 || got[0] != "tcp://127.0.0.1:1" {
		t.Fatalf("candidates = %v, want only the operator's DOCKER_HOST", got)
	}
}

func TestCandidatesCoverRootlessPodmanAndDockerWhenDockerHostIsUnset(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/4242")

	got := containerCandidates()

	if len(got) == 0 || got[0] != "unix:///run/user/4242/podman/podman.sock" {
		t.Fatalf("candidates = %v, want rootless podman probed first", got)
	}
	if !containsString(got, "unix:///var/run/docker.sock") {
		t.Errorf("candidates = %v, want the docker socket among them", got)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// A tcp:// DOCKER_HOST is probed over tcp, not silently trusted.
func TestATCPDockerHostIsProbed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"Version":"29.6.0"}`))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	if err := probeContainerHost("tcp://" + ln.Addr().String()); err != nil {
		t.Fatalf("probe rejected a tcp daemon that answered: %v", err)
	}
}
