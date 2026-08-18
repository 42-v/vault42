package firstboot

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The sink's directory is writable by whoever shares it — a memory-backed
// emptyDir, or /tmp when an operator points the variable there. These tests pin
// the three ways that access turns into the credential leaving the file the
// operator named.

// Refusing a symlink is not new; refusing it in the kernel is. An Lstat-then-open
// implementation rejects a symlink that is standing there when it looks, and this
// asserts the rejection comes from the open instead, because that is the version
// with no window between the decision and the write. The error text is the
// observable difference: ELOOP names the symlink, the stat path reports only that
// the mode is not regular.
func TestOpenCredentialFileRefusesASymlinkAtTheOpen(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-readable")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "first-boot.env")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	f, err := openCredentialFile(link)
	if err == nil {
		_ = f.Close()
		t.Fatal("openCredentialFile opened a symlinked sink")
	}
	if !strings.Contains(err.Error(), "is a symlink") {
		t.Errorf("the refusal did not come from O_NOFOLLOW: %v", err)
	}
	got, err := os.ReadFile(target) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("the symlink target was written to: %q", got)
	}
}

// A hardlink to an inode the attacker already holds is a regular file at 0600
// owned by this process, so it passes every test the mode can express, and the
// credential is still readable through their name for it.
func TestOpenCredentialFileRefusesAHardLinkedSink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "first-boot.env")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(dir, "attacker-name")); err != nil {
		t.Skipf("the filesystem under the temp dir does not support hard links: %v", err)
	}

	f, err := openCredentialFile(path)
	if err == nil {
		_ = f.Close()
		t.Fatal("openCredentialFile accepted a sink with a second name")
	}
	if !strings.Contains(err.Error(), "hard links") {
		t.Errorf("the refusal did not name the second link: %v", err)
	}
}

// The race the O_NOFOLLOW closes: be a regular 0600 file when the implementation
// looks, be a symlink by the time it writes. An Lstat-then-open version loses
// this within a few dozen iterations; O_NOFOLLOW cannot lose it at all, because
// there is only one lookup and the kernel performs the check inside it.
//
// The assertion is on the target's contents rather than on the error, so a lost
// race is not mistaken for a passing test: the swapper either wins and the
// credential appears where it must never appear, or it never wins and the file
// stays empty.
func TestOpenCredentialFileDoesNotLoseTheSymlinkSwapRace(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "first-boot.env")
	target := filepath.Join(dir, "attacker-readable")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = os.Remove(sink)
			_ = os.Symlink(target, sink)
			_ = os.Remove(sink)
			_ = os.WriteFile(sink, nil, 0o600)
		}
	}()

	for range 4000 {
		f, err := openCredentialFile(sink)
		if err != nil {
			continue
		}
		if _, err := f.WriteString("VAULT_ADMIN_TOKEN=s3cret\n"); err != nil {
			t.Error(err)
		}
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}
	stop.Store(true)
	wg.Wait()

	got, err := os.ReadFile(target) // #nosec G304 -- path built by the test
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("the credential was written through a swapped symlink: %q", got)
	}
}
