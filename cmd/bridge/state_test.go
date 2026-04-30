package main

import (
	"testing"
	"time"
)

func TestFlagStore(t *testing.T) {
	fs := NewFlagStore(100*time.Millisecond, "")

	// Initially not flagged
	if fs.IsFlagged("1.2.3.4") {
		t.Error("IP should not be flagged initially")
	}

	// Flag it
	fs.Flag("1.2.3.4", "test", 100)
	if !fs.IsFlagged("1.2.3.4") {
		t.Error("IP should be flagged")
	}

	// Check list
	entries := fs.List()
	if len(entries) != 1 {
		t.Errorf("List() = %d entries, want 1", len(entries))
	}
	if entries[0].IP != "1.2.3.4" {
		t.Errorf("List()[0].IP = %q, want %q", entries[0].IP, "1.2.3.4")
	}

	// Unflag
	if !fs.Unflag("1.2.3.4") {
		t.Error("Unflag should return true for flagged IP")
	}
	if fs.IsFlagged("1.2.3.4") {
		t.Error("IP should not be flagged after unflag")
	}

	// Unflag non-existent
	if fs.Unflag("5.5.5.5") {
		t.Error("Unflag should return false for non-flagged IP")
	}
}

func TestFlagStoreTTL(t *testing.T) {
	fs := NewFlagStore(50*time.Millisecond, "")

	fs.Flag("1.2.3.4", "test", 100)
	if !fs.IsFlagged("1.2.3.4") {
		t.Error("IP should be flagged")
	}

	time.Sleep(80 * time.Millisecond)

	if fs.IsFlagged("1.2.3.4") {
		t.Error("IP should have expired")
	}
}

func TestFlagStoreReap(t *testing.T) {
	fs := NewFlagStore(50*time.Millisecond, "")

	fs.Flag("1.1.1.1", "test", 100)
	fs.Flag("2.2.2.2", "test", 100)

	time.Sleep(80 * time.Millisecond)
	fs.Reap()

	fs.mu.RLock()
	count := len(fs.flags)
	fs.mu.RUnlock()

	if count != 0 {
		t.Errorf("Reap: %d entries remain, want 0", count)
	}
}
