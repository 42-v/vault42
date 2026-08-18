package email

import (
	"sync"
	"testing"
	"time"
)

// The package-level renderer is published once at startup and read for the
// lifetime of the process, and that shape is exactly what makes it easy to get
// wrong. SetRenderer guards its write with a sync.Once, which reads as
// synchronization but is not: sync.Once orders the writer against other
// goroutines that also call Do, and against nothing else. A goroutine that only
// ever reads the variable never calls Do, so it takes no ordering from the Once
// at all, and the write to the pointer races with its read.
//
// The read side is not hypothetical. NewMailer falls back to the same variable
// whenever it is handed a nil renderer, which is how internal/service and
// internal/handler build theirs. It is reached from
// goroutines that outlive the request that spawned them: internal/service
// finishes verification and password-reset mail asynchronously so the HTTP
// handler can return, and those goroutines are still running while startup
// wiring in cmd/vault is calling SetRenderer. The window is small but it is a
// genuine one, and the failure mode of losing it is a torn pointer read on a
// path that renders credential-bearing email.
//
// This test drives both sides at once so -race adjudicates it. It fails if the
// reader ever goes back to reading the variable directly instead of through an
// atomic load.

// emailPublicationStorm runs writer and reader concurrently for a bounded
// number of iterations. The reader loops far more than the writer runs so the
// single publication lands somewhere in the middle of the read stream rather
// than before it starts.
const emailPublicationReads = 2000

func TestSetRenderer_PublicationIsSafeForReadersThatNeverCallOnce(t *testing.T) {
	// SetRenderer is deliberately one-shot for the process, and this package's
	// other tests rely on the Once still being virgin. Take the sentinel back to
	// its startup state before the storm and put it back afterwards so test
	// order in this binary stays irrelevant.
	original := currentRenderer()
	setRendererOnce = sync.Once{}
	t.Cleanup(func() {
		defaultRenderer.Store(original)
		setRendererOnce = sync.Once{}
	})

	replacement, err := NewTemplateRenderer("")
	if err != nil {
		t.Fatalf("build the replacement renderer: %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})

	// The writer: one goroutine doing what cmd/vault does at startup.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		// A short delay puts the publication inside the reader's loop rather
		// than ahead of it, which is where the production window actually is.
		time.Sleep(time.Millisecond)
		SetRenderer(replacement)
	}()

	// The readers: goroutines that never call Do and therefore inherit no
	// ordering from the Once. NewMailer is the read that ships, so it is the one
	// driven, and the renderer it settled on is used to render.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := 0; n < emailPublicationReads; n++ {
				m := NewMailer(nil, nil, nil, Branding{}, nil)
				if m.renderer == nil {
					t.Error("NewMailer fell back to a nil package renderer, which means it read the variable before publication finished")
					return
				}
				subject, html, text := m.renderer.Render(TemplateVerification, TemplateData{AppName: "PublicationTest"})
				if subject == "" || html == "" || text == "" {
					t.Errorf("a concurrently published renderer produced an empty render (subject=%q html=%d bytes text=%d bytes)",
						subject, len(html), len(text))
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()

	if currentRenderer() != replacement {
		t.Error("SetRenderer did not publish the replacement renderer")
	}
}
