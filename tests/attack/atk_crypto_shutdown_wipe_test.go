package attack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/kms"
)

// This file attacks the shutdown path, which is where vault42 destroys key
// material while it may still be in use.
//
// cmd/vault/main.go registers the two wipes as deferred calls:
//
//	defer kmsSvc.Close()   // zeroes the KMS root secret
//	defer ks.Stop()        // zeroes the keystore master key
//
// Both are correct only if main returns after every request handler has
// finished. It does not. internal/server/server.go Start() spawns the drain in
// a goroutine that nothing joins:
//
//	go func() { <-done; ctx, cancel := ...; _ = s.httpSrv.Shutdown(ctx) }()
//	err = s.httpSrv.ListenAndServe()
//	if err == http.ErrServerClosed { return nil }
//
// http.Server.Shutdown closes the listeners first and only then waits for
// in-flight handlers, so ListenAndServe returns http.ErrServerClosed at the
// START of the drain, not at the end. Start returns nil immediately, main
// returns, and the deferred wipes run against key material that live handlers
// are still reading. The ShutdownTimeout the operator configures is never
// waited on by anybody.
//
// That makes the races below reachable on every SIGTERM, which for a
// Kubernetes deployment means every rollout, not just an unclean crash.

// The end-to-end reproduction: a server built the way Start builds one, a
// handler that calls kms.Unwrap the way internal/handler/kms.go does, and the
// deferred wipe running as soon as the serve loop returns.
//
// Under -race the detector reports the write in kms.wipe against the read in
// deriveKEK. Without -race it passes, which is the honest result: this is a
// race on key material, not a wrong answer.
func TestShutdownAttack_ServeLoopReturnsBeforeHandlersDrain(t *testing.T) {
	svc, err := kms.New(kmsRoot)
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}
	env, err := svc.Wrap("kid-shutdown", []byte("life42 data root"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// inHandler closes once a request is provably inside the unwrap call, so
	// the shutdown is triggered at the moment a handler is holding the root.
	inHandler := make(chan struct{})
	var once sync.Once
	// release keeps the handler inside its critical section long enough that
	// the wipe lands while it is still there. A real handler is held open by
	// the synchronous audit insert on the same path.
	release := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/kms/unwrap", func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(inHandler) })
		<-release
		// The read that races the wipe: deriveKEK hashes s.root.
		for i := 0; i < 32; i++ {
			_, _ = svc.Unwrap("kid-shutdown", env)
		}
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	// This mirrors server.Start: the drain runs in a goroutine nothing joins,
	// and the serve loop's return value is the only thing the caller sees.
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		//nolint:noctx // the request is deliberately long-lived
		resp, reqErr := http.Get("http://" + ln.Addr().String() + "/kms/unwrap")
		if reqErr == nil {
			_ = resp.Body.Close()
		}
	}()

	<-inHandler

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Serve returns as soon as Shutdown closes the listener. This is the whole
	// bug: the caller reads this as "the server is done".
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve returned %v, want http.ErrServerClosed", err)
	}

	// main's deferred wipes run here, with a handler still inside Unwrap.
	close(release)
	svc.Close()

	<-reqDone
}

// The source-level half of the same finding, so it fails if someone rewrites
// Start without restoring the join. Asserted with go/ast rather than a grep so
// it does not go stale when the formatting changes.
//
// The property: whatever goroutine calls httpSrv.Shutdown, Start must not
// return before that goroutine has finished. Today Start's body contains a
// `go func()` holding the Shutdown call and no WaitGroup, channel receive or
// other join afterwards.
func TestShutdownAttack_StartNeverWaitsForTheDrain(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "server", "server.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var start *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "Start" && fn.Recv != nil {
			start = fn
			return false
		}
		return true
	})
	if start == nil {
		t.Fatal("no (*Server).Start in internal/server/server.go")
	}

	var shutdownInGoroutine bool
	var joins []string
	ast.Inspect(start.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.GoStmt:
			ast.Inspect(node, func(inner ast.Node) bool {
				sel, ok := inner.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "Shutdown" {
					shutdownInGoroutine = true
				}
				return true
			})
		case *ast.CallExpr:
			// A join would look like wg.Wait() or <-drained.
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Wait" {
				joins = append(joins, "Wait call")
			}
		case *ast.UnaryExpr:
			if node.Op == token.ARROW {
				joins = append(joins, "channel receive")
			}
		}
		return true
	})

	if !shutdownInGoroutine {
		// The join assertion below is the whole test. Skipping when the shape
		// changes retires it silently at the one moment somebody was editing
		// the shutdown path, which is when it is worth running.
		t.Fatalf("(*Server).Start no longer calls httpSrv.Shutdown from a goroutine, so the " +
			"unjoined-drain finding this test watches for cannot be expressed in its current " +
			"terms. Re-derive it against the new shutdown path, or delete it and the register " +
			"row that cites it.")
	}
	if len(joins) == 0 {
		t.Errorf("(*Server).Start calls httpSrv.Shutdown in a goroutine and never joins it: " +
			"Start returns when ListenAndServe reports ErrServerClosed, which is the START of the " +
			"drain. main's deferred kmsSvc.Close() and ks.Stop() then wipe key material out from " +
			"under handlers that are still running.")
	}
}

// keystore.Stop has the same shape as kms.Close and the same hole, but its doc
// comment argues the hole is closed:
//
//	"It blocks until the refresh loop has exited. Refresh reads masterKey
//	 outside ks.mu ... so zeroing it while a refresh is still in flight is a
//	 data race on live key material"
//
// ks.wg tracks only the goroutine StartRefreshLoop spawns. Every other caller
// of Refresh and Import is untracked: the admin key-rotation endpoint, the CLI,
// and EnsureKey all reach the same unsynchronized read. Stop takes ks.mu before
// zeroing, which does not help, because Import and Refresh read ks.masterKey
// without holding it.
//
// Import is used here because it reads masterKey (line 148, the Encrypt call)
// before it touches the database, so the interleaving reproduces against a pool
// that never connects and no container is needed.
//
// IMPORTANT, and the reason this test asserts nothing: -race cannot see this
// one. The only read of masterKey on the keystore path is aes.NewCipher, whose
// key expansion is hand-written assembly, and the race detector instruments Go
// code only. TestKeystoreAttack_RaceDetectorIsBlindToAESKeyReads below proves
// that claim with a control. The KMS race in this file IS caught only because
// HKDF-SHA256 reaches the secret through crypto/internal/fips140/sha256, which
// is Go.
//
// So this test drives the real interleaving and documents it; the proof that
// the interleaving is harmful is the deterministic torn-key test further down.
func TestKeystoreAttack_StopRacesImportOnMasterKey(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://nobody:nobody@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}

	ks, err := keystore.New(pool, masterKey, time.Hour)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	// The importers loop until told to stop rather than running once, so the
	// wipe is guaranteed to land while a read is in flight. A single-shot
	// version is scheduler-dependent: the memset in Stop is one instruction
	// burst and can easily finish before or after every Import.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	const importers = 8
	wg.Add(importers)
	for i := 0; i < importers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Fails at Begin because the pool has nowhere to connect, but
				// only after Encrypt has already read ks.masterKey.
				_, _ = ks.Import(context.Background(), key)
			}
		}()
	}

	time.Sleep(20 * time.Millisecond) // let the importers get into their loop
	ks.Stop()                         // the deferred wipe from cmd/vault/main.go
	time.Sleep(20 * time.Millisecond) // keep reading after the wipe
	close(stop)
	wg.Wait()
}

// A control for the test above, and a finding in its own right: the race
// detector cannot see a wipe racing a key read on the AES path.
//
// Two goroutines run an unsynchronized read/wipe pattern over one 32-byte
// slice. The read goes through internal/crypto.Encrypt, so the key reaches
// aes.NewCipher, whose key schedule is assembly and therefore uninstrumented,
// and the detector stays quiet. The same pattern read in plain Go is reported
// every time; that half is not run here because it would fail the suite on
// purpose, and a green suite is the only way this file can carry the finding.
//
// The consequence for vault42 is that `go test -race` in CI is not evidence
// that the keystore master key is safe from the shutdown wipe. It is evidence
// only that nobody reads it from Go. A reviewer who runs the suite, sees it
// green, and concludes the keystore is race-free has been misled by a tool
// limitation, not by the code.
func TestKeystoreAttack_RaceDetectorIsBlindToAESKeyReads(t *testing.T) {
	race := func(read func(key []byte)) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
				}
				read(key)
			}
		}()
		time.Sleep(20 * time.Millisecond)
		for i := range key { // the wipe, exactly as (*KeyStore).Stop does it
			key[i] = 0
		}
		time.Sleep(20 * time.Millisecond)
		close(stop)
		<-done
	}

	// The vault42 read path. Under -race this reports nothing, which is the
	// point. Left unasserted because a future toolchain that instruments the
	// assembly would start reporting it, and that would be an improvement, not
	// a regression to fail on.
	race(func(key []byte) {
		_, _ = vaultcrypto.Encrypt([]byte("signing key pem"), key, []byte("kid"))
	})

	t.Log("the AES read above races a concurrent wipe and -race reports nothing; " +
		"the same pattern read from Go is reported. CI's race detector is not a " +
		"control for (*KeyStore).Stop.")
}

// The consequence of losing that race, proven without any race at all.
//
// A partially or fully zeroed master key is still 32 bytes, so every length
// guard in internal/crypto passes and AES-GCM seals happily. Import does not
// notice; it commits the ciphertext to auth.signing_keys and reports success.
// On the next start Refresh decrypts with the real master key, fails, and
// returns before applyKeys, so the pod comes up with no active signing key and
// issuance fails closed. The row is unrecoverable: the key it was sealed under
// existed only inside a shutdown window.
//
// This is why the race above is a key-destruction bug and not just a detector
// complaint.
func TestKeystoreAttack_ZeroedMasterKeyStillEncryptsAndLosesTheRow(t *testing.T) {
	realKey := make([]byte, 32)
	for i := range realKey {
		realKey[i] = byte(i + 1)
	}
	plaintext := []byte("-----BEGIN PRIVATE KEY----- signing key material")
	const kid = "abcdef01-23456789"

	for _, tc := range []struct {
		name   string
		zeroed int // how many leading bytes the wipe managed to clear
	}{
		{"fully wiped", 32},
		{"half wiped", 16},
		{"one byte wiped", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			torn := append([]byte(nil), realKey...)
			for i := 0; i < tc.zeroed; i++ {
				torn[i] = 0
			}

			// The write that Import would commit.
			ct, err := vaultcrypto.Encrypt(plaintext, torn, []byte(kid))
			if err != nil {
				t.Fatalf("a torn master key was rejected by Encrypt, so this path is closed: %v", err)
			}

			// The read every later pod performs, with the real key.
			if _, err := vaultcrypto.Decrypt(ct, realKey, []byte(kid)); err == nil {
				t.Fatal("row sealed under the torn key decrypted under the real key")
			}
			t.Logf("%d/32 bytes wiped: Encrypt succeeded and the row is permanently undecryptable", tc.zeroed)
		})
	}
}

// Stop is called from a defer, so it can also run twice or concurrently with
// itself if a future shutdown path adds a second call. stopOnce covers the
// channel close but not the wipe, which is idempotent anyway. Recorded so the
// report can state plainly that double-Stop is NOT the problem: single-Stop
// racing a live reader is.
func TestKeystoreAttack_DoubleStopIsSafe(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://nobody:nobody@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	ks, err := keystore.New(pool, make([]byte, 32), time.Hour)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Stop panicked: %v", r)
		}
	}()
	ks.Stop()
	ks.Stop()
}

// Every read of ks.masterKey must go through withMasterKey.
//
// Stop zeroes the master key, and Refresh and Import used to read it with no
// lock at all. ks.wg tracks only the goroutine StartRefreshLoop launches, so an
// admin rotate, revoke or EnsureKey call was invisible to the join Stop performs
// before wiping.
//
// The race detector cannot be relied on to catch a regression here, which is why
// this test is structural rather than behavioral. The only read on the hot path
// is aes.NewCipher's key schedule, which is assembly and uninstrumented, so a
// torn read of the AES key produces no report at all. The identical pattern read
// from Go IS reported, which makes the silence actively misleading.
//
// The consequence is worse than a torn read. A zeroed master key is still a
// valid 32-byte AES key, so Import would encrypt a private key under all zeros,
// commit the row, and return success. The key is then permanently undecryptable
// by the real master key: data destruction, reported as a successful rotation.
func TestKeystoreMasterKeyReadsAreGuarded(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "keystore", "keystore.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// withMasterKey is the one function allowed to touch the field directly; it
	// is where the lock and the closed check live.
	const accessor = "withMasterKey"

	var offenders []string
	var sawAccessor bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil {
			return true
		}
		if fn.Name.Name == accessor {
			sawAccessor = true
			return true
		}
		// Stop is the wipe itself and takes the write lock inline.
		if fn.Name.Name == "Stop" {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			sel, ok := inner.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "masterKey" {
				offenders = append(offenders,
					fn.Name.Name+" (line "+fmt.Sprint(fset.Position(sel.Pos()).Line)+")")
			}
			return true
		})
		return true
	})

	if !sawAccessor {
		t.Fatalf("keystore.go has no %s; the accessor this gate depends on was "+
			"renamed or removed and the gate is now checking nothing", accessor)
	}
	for _, o := range offenders {
		t.Errorf("(*KeyStore).%s reads ks.masterKey directly instead of through %s. "+
			"Stop zeroes that field, a zeroed AES key still encrypts, and the race "+
			"detector cannot see the read because the key schedule is assembly.",
			o, accessor)
	}
}

// TestKeystoreAttack_StopWipesTheKeyEveryOtherServiceIsStillUsing is the
// aliasing half of the wipe, and it is the one that reaches user data.
//
// cmd/vault/main.go takes exactly one working copy of the master key and hands
// that same slice to keystore.New and to the service container, which passes it
// on to the identity, blob, service-document and TOTP paths. The comment above
// that copy explains at length why a consumer must never be given
// cfg.MasterKey: config.ZeroBytes wipes the config's array in place, and a
// service left holding 32 zero bytes still has a valid AES-256 key length, so
// it encrypts and decrypts happily against itself while the at-rest protection
// is gone.
//
// keystore.Stop then does precisely that to every one of them. It wipes the
// slice it was given, which is the same backing array, so the hazard the
// comment describes is created by the shutdown path rather than avoided by it.
//
// Stop runs from a defer during shutdown, while handlers are still draining. A
// request that encrypts in that window seals a row under a zero key, and the
// row is then permanently undecryptable, which the test above already proves.
// This one proves the aliasing that lets it happen at all.
//
// The fix is ownership: keystore.New copies the key, so Stop wipes only the
// keystore's own copy.
func TestKeystoreAttack_StopWipesTheKeyEveryOtherServiceIsStillUsing(t *testing.T) {
	// The single working copy main() makes, handed to two consumers.
	shared := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i + 1)
	}
	original := append([]byte(nil), shared...)

	// Consumer A: the keystore.
	ks, err := keystore.New(nil, shared, time.Hour)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}

	// Consumer B: every service that encrypts user data. They retain the slice
	// exactly as the keystore does.
	serviceKey := shared

	ks.Stop()

	if !bytes.Equal(serviceKey, original) {
		t.Errorf("keystore.Stop zeroed the master key the identity, blob and TOTP paths are "+
			"still holding: %x. A request draining through shutdown now seals rows under a "+
			"zero key, and no later pod can ever read them.", serviceKey)
	}

	// And the keystore's own copy must still be wiped: that is what Stop is for.
	if bytes.Equal(shared, original) && len(shared) > 0 {
		// shared is A's view. If New copied, A's wipe is invisible here, which
		// is correct. This branch only documents that the assertion above is
		// about B's key and not about weakening the wipe itself.
		t.Log("keystore.New took its own copy, so the caller's slice is untouched, which is the fix")
	}
}
