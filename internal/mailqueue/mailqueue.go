// Package mailqueue runs sends that outlive the request that triggered them,
// on a bounded pool that shutdown drains.
//
// Four call sites used to `go` a send directly — signup verification, password
// reset, the import-claim link and the account-locked notice — and every one of
// them is reachable by an unauthenticated caller. That put two things in that
// caller's hands: how many goroutines this process runs, and how many
// connections it opens against the operator's mail relay. The bridge's webhook
// sender had already reasoned this through and capped itself at eight workers
// with a bounded queue; the same argument applies to SMTP and had not been
// applied.
//
// The second problem was shutdown. A detached send was invisible to it:
// Server.Start returns after the HTTP drain and main's defers then close the
// cache and the pool, so a verification send that writes its token to the cache
// and then mails the link could write to a cache that was already closed. The
// user got a verification link that never worked — on every rollout, for
// anyone who registered inside the shutdown window. Close drains the queue
// before main gets that far.
package mailqueue

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
)

// Defaults, matching cmd/bridge's webhook pool, for the same reason: deep
// enough that ordinary traffic never reaches the bound, bounded so a flood
// costs fixed memory and a fixed number of relay connections.
const (
	DefaultWorkers    = 8
	DefaultQueueDepth = 1024
)

// Job is a unit of deferred work. It is handed a context that is cancelled when
// the dispatcher is closing, so a job that outlives the drain deadline can stop
// rather than write into torn-down state.
type Job func(ctx context.Context)

// Dispatcher is a bounded worker pool for deferred sends.
type Dispatcher struct {
	queue chan Job
	wg    sync.WaitGroup

	// ctx is cancelled by Close, and every job receives it.
	ctx    context.Context
	cancel context.CancelFunc

	// mu guards closed against the queue send. Enqueue holds it for read and
	// Close takes it for write before closing the channel, so no send can be
	// sitting in the select when the close happens.
	mu     sync.RWMutex
	closed bool

	closeOnce sync.Once
	dropOnce  sync.Once
	dropped   atomic.Uint64
}

// New starts a dispatcher with the given pool size and queue depth.
func New(workers, queueDepth int) *Dispatcher {
	if workers < 1 {
		workers = 1
	}
	if queueDepth < 1 {
		queueDepth = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{
		queue:  make(chan Job, queueDepth),
		ctx:    ctx,
		cancel: cancel,
	}
	d.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer d.wg.Done()
			for job := range d.queue {
				job(d.ctx)
			}
		}()
	}
	return d
}

// Enqueue hands off a job and returns immediately.
//
// It drops rather than blocks. Blocking would put relay latency back on the
// request path, which is the timing leak the deferred send exists to avoid, and
// the caller controls the event rate. A drop is counted, because each one is a
// user who never received their reset link.
func (d *Dispatcher) Enqueue(job Job) {
	if d == nil || job == nil {
		return
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return
	}
	select {
	case d.queue <- job:
	default:
		n := d.dropped.Add(1)
		d.dropOnce.Do(func() {
			log.Printf("mailqueue: workers saturated, deferred sends are being dropped (first at %d)", n)
		})
	}
}

// Dropped reports jobs discarded because the workers were saturated.
func (d *Dispatcher) Dropped() uint64 {
	if d == nil {
		return 0
	}
	return d.dropped.Load()
}

// QueueDepth reports queued-but-unstarted jobs, so saturation is visible before
// it becomes loss.
func (d *Dispatcher) QueueDepth() int {
	if d == nil {
		return 0
	}
	return len(d.queue)
}

// Close stops accepting work and waits for what is queued, up to the caller's
// deadline.
//
// It must run BEFORE the cache and the database pool are closed, so a send that
// is mid-flight cannot write into either after they are gone. In cmd/vault that
// means registering the defer after theirs, since defers run last-in-first-out.
func (d *Dispatcher) Close(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		close(d.queue)
	})

	drained := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(drained)
	}()

	var err error
	select {
	case <-drained:
	case <-ctx.Done():
		// The deadline expired with sends still running. Cancel their context
		// so they stop touching state the caller is about to tear down, and
		// report it: a send abandoned here is a mail nobody sent.
		err = ctx.Err()
		log.Printf("mailqueue: drain deadline expired with %d queued jobs", len(d.queue))
	}
	d.cancel()

	if n := d.dropped.Load(); n > 0 {
		log.Printf("mailqueue: %d deferred sends were dropped", n)
	}
	return err
}

// defaultDispatcher is the process-wide pool.
//
// A package-level default rather than a handle threaded through every
// constructor, because the bound has to hold whether or not somebody remembered
// to wire it. A service built without the wiring would otherwise be back to an
// unbounded `go`, which is the defect.
var defaultDispatcher = New(DefaultWorkers, DefaultQueueDepth)

// Go enqueues a job on the process-wide pool.
func Go(job Job) { defaultDispatcher.Enqueue(job) }

// Close drains the process-wide pool. Called from main during shutdown.
func Close(ctx context.Context) error { return defaultDispatcher.Close(ctx) }

// Dropped reports drops on the process-wide pool.
func Dropped() uint64 { return defaultDispatcher.Dropped() }

// QueueDepth reports the process-wide pool's queued jobs.
func QueueDepth() int { return defaultDispatcher.QueueDepth() }
