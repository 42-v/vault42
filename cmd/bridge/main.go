// Command bridge is vault42's deception reverse proxy. It sits in front of two
// upstreams, the real vault and a honeypot vault, and decides per request which
// one answers.
//
// The decision is a per-IP score accumulated from automation-looking user
// agents, request rate, and failed logins observed in the real upstream's
// responses. An IP that crosses the configured threshold is flagged, and every
// subsequent request from it goes to the honeypot instead of the real service.
// Touching one of the decoy login paths this binary serves itself skips the
// score entirely and flags on the first request, since no legitimate client
// asks vault42 for /wp-admin. Flags carry a TTL and optionally persist in Redis
// so a fleet of bridges shares one view and a restart does not clear an
// attacker's status.
//
// The routing decision is invisible to the client on purpose: a flagged
// attacker gets plausible responses from the honeypot rather than a block page,
// so probing continues against a system with nothing real behind it. The cost
// of a false positive is that a legitimate user is quietly served fake data,
// which is why the client-IP source is configurable and why trusted proxy
// ranges must be set correctly in any deployment behind a load balancer.
//
// A small token-authenticated admin API on the same listener exposes the flag
// list for manual flag and unflag, alongside liveness and readiness probes that
// report on both upstreams. Configuration is entirely BRIDGE_* environment
// variables; see Config and docs/bridge.md.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Set at build time via -ldflags, matching cmd/vault and cmd/admin-gateway.
//
// These have to be declared here rather than borrowed from a shared package.
// cmd/bridge is deliberately stdlib-only and imports nothing under internal/,
// and a -X naming a symbol the binary does not link is dropped by the linker
// without a warning and with exit 0. .goreleaser.yaml carried the three stamps
// for this build from the start and none of them ever landed, so every release
// shipped a bridge that reported no version while the config read as though it
// were stamped like the other two.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("bridge %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		return
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("bridge: config error: %v", err)
	}

	bridge, err := NewBridge(cfg)
	if err != nil {
		log.Fatalf("bridge: initialization error: %v", err)
	}
	defer bridge.Close()

	bridge.StartReaper(60 * time.Second)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           bridge,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("bridge: listening on %s", cfg.ListenAddr)
		log.Printf("bridge: real=%s honeypot=%s", cfg.RealUpstream, cfg.HoneypotUpstream)
		if cfg.RedisAddr != "" {
			log.Printf("bridge: redis=%s", cfg.RedisAddr)
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("bridge: listen error: %v", err)
		}
	}()

	<-done
	log.Println("bridge: shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("bridge: shutdown error: %v", err)
	}

	log.Println("bridge: stopped")
}
