package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
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
