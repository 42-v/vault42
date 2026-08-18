package firstboot

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// fakeFileInfo is an os.FileInfo whose mode and Stat_t the test chooses, so the
// refusals checkCredentialSink makes on the descriptor can be exercised without
// building a filesystem that produces each shape. Two of them cannot be built at
// all on a Linux test host: a non-regular file cannot survive the O_NOFOLLOW
// open (a directory fails with EISDIR first), and Sys() always returns a
// *syscall.Stat_t, so the arm that tolerates a platform where it does not is
// unreachable through the real call path.
type fakeFileInfo struct {
	os.FileInfo
	mode os.FileMode
	sys  any
}

func (f fakeFileInfo) Mode() os.FileMode { return f.mode }
func (f fakeFileInfo) Sys() any          { return f.sys }

// checkCredentialSink is the half of the open that runs against the descriptor,
// and each of its refusals is a different way the credential would end up
// readable by someone other than this process.
func TestCheckCredentialSinkRefusals(t *testing.T) {
	const path = "/run/first-boot/creds.env"
	self := uint32(os.Getuid()) // #nosec G115 -- a uid fits a uint32 by definition

	for _, c := range []struct {
		name string
		fi   os.FileInfo
		want string
	}{
		{
			name: "not a regular file",
			fi:   fakeFileInfo{mode: os.ModeDir | 0o600, sys: &syscall.Stat_t{Uid: self, Nlink: 1}},
			want: "is not a regular file",
		},
		{
			name: "readable by others",
			fi:   fakeFileInfo{mode: 0o644, sys: &syscall.Stat_t{Uid: self, Nlink: 1}},
			want: "chmod 600 it",
		},
		{
			name: "owned by another account",
			fi:   fakeFileInfo{mode: 0o600, sys: &syscall.Stat_t{Uid: self + 1, Nlink: 1}},
			want: "chown it",
		},
		{
			name: "reachable through a second name",
			fi:   fakeFileInfo{mode: 0o600, sys: &syscall.Stat_t{Uid: self, Nlink: 2}},
			want: "hard links",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := checkCredentialSink(path, c.fi)
			if err == nil {
				t.Fatalf("checkCredentialSink accepted a sink that is %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error does not tell the operator what to do about it: %v", err)
			}
		})
	}
}

// A platform whose FileInfo.Sys() is not a *syscall.Stat_t cannot be asked about
// ownership or link count, and the mode checks above have already run. Accepting
// is the only honest answer; refusing every sink on such a platform would be a
// refusal about the platform rather than about the file.
func TestCheckCredentialSinkToleratesAnUnknownStatShape(t *testing.T) {
	fi := fakeFileInfo{mode: 0o600, sys: "not a Stat_t"}
	if err := checkCredentialSink("/run/first-boot/creds.env", fi); err != nil {
		t.Errorf("checkCredentialSink refused a private regular file for want of a Stat_t: %v", err)
	}
}
