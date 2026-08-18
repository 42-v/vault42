package server

import (
	"bytes"
	"log"
	"net"
	"strings"
	"testing"
)

// A metrics listener that binds before the API listener can take the API's port.
//
// The metrics bind failure is deliberately non-fatal — losing a scrape must never
// cost the service — and started first that leniency ran backwards: name the API
// port in VAULT_METRICS_ADDR and the collector wins, the API's own bind then fails
// fatally, and for the width of the crash loop the port the Ingress routes to
// answers with an unauthenticated read of every counter in the process. ":8080" is
// the documented public port, so it is the plausible typo, not an exotic one.
func TestTheMetricsListenerRefusesTheAPIPort(t *testing.T) {
	addr := freeAddr(t)
	t.Setenv(metricsAddrEnv, addr)

	s := &Server{deps: &Deps{Metrics: testCollector()}}
	s.startMetrics(addr)

	if s.metricsSrv != nil {
		t.Fatal("the metrics listener started on the address the API listens on")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the API's own address is no longer bindable: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
}

// The refusal is by port, so the wildcard and loopback spellings of the same port
// are caught too: ":9090", "0.0.0.0:9090" and "127.0.0.1:9090" are three names for
// one contended port, and only one of them is a string match.
func TestTheMetricsListenerRefusesTheAPIPortUnderAnySpelling(t *testing.T) {
	for _, c := range []struct{ metrics, api string }{
		{":8080", "0.0.0.0:8080"},
		{"0.0.0.0:8080", ":8080"},
		{"127.0.0.1:8080", ":8080"},
	} {
		t.Run(c.metrics+" vs "+c.api, func(t *testing.T) {
			if !sameListenAddress(c.metrics, c.api) {
				t.Errorf("sameListenAddress(%q, %q) = false; the collector would be published "+
					"on the port the API serves", c.metrics, c.api)
			}
		})
	}
	if sameListenAddress("127.0.0.1:9090", ":8080") {
		t.Error("sameListenAddress refused a metrics address on a different port")
	}
	if sameListenAddress("not-an-address", ":8080") {
		t.Error("sameListenAddress treated an unparseable address as a collision")
	}
}

// The operator has to be able to tell which variable is wrong. A bare
// "address already in use" from a listener that is allowed to fail is not that.
func TestTheRefusalNamesTheVariable(t *testing.T) {
	addr := freeAddr(t)
	t.Setenv(metricsAddrEnv, addr)

	s := &Server{deps: &Deps{Metrics: testCollector()}}
	out := captureServerLog(t, func() { s.startMetrics(addr) })

	if !strings.Contains(out, metricsAddrEnv) {
		t.Errorf("the refusal does not name %s:\n%s", metricsAddrEnv, out)
	}
}

// captureServerLog redirects the standard logger for the duration of fn.
func captureServerLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	fn()
	return buf.String()
}
