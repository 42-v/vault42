//go:build stress

package stress

import (
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// StressResult aggregates metrics from stress test workers.
type StressResult struct {
	Total        int64
	Success      int64         // 2xx
	RateLimited  int64         // 429
	Backpressure int64         // 503 (server_busy — healthy load-shedding)
	ClientErr    int64         // 4xx (non-429)
	ServerErr    int64         // 5xx (non-503)
	Timeouts     int64         // net errors / timeouts
	Latencies    []time.Duration
	Duration     time.Duration // wall clock
}

// workerResult is the per-worker atomic counters used during collection.
type workerResult struct {
	total        atomic.Int64
	success      atomic.Int64
	rateLimited  atomic.Int64
	backpressure atomic.Int64
	clientErr    atomic.Int64
	serverErr    atomic.Int64
	timeouts     atomic.Int64
}

func (w *workerResult) record(status int, lat time.Duration) {
	w.total.Add(1)
	switch {
	case status == 0:
		w.timeouts.Add(1)
	case status == 429:
		w.rateLimited.Add(1)
	case status == 502 || status == 503:
		w.backpressure.Add(1)
	case status >= 200 && status < 300:
		w.success.Add(1)
	case status >= 400 && status < 500:
		w.clientErr.Add(1)
	default:
		w.serverErr.Add(1)
	}
}

func (w *workerResult) toResult() *StressResult {
	return &StressResult{
		Total:        w.total.Load(),
		Success:      w.success.Load(),
		RateLimited:  w.rateLimited.Load(),
		Backpressure: w.backpressure.Load(),
		ClientErr:    w.clientErr.Load(),
		ServerErr:    w.serverErr.Load(),
		Timeouts:     w.timeouts.Load(),
	}
}

// Merge combines results from another worker into this one.
func (r *StressResult) Merge(other *StressResult) {
	r.Total += other.Total
	r.Success += other.Success
	r.RateLimited += other.RateLimited
	r.Backpressure += other.Backpressure
	r.ClientErr += other.ClientErr
	r.ServerErr += other.ServerErr
	r.Timeouts += other.Timeouts
	r.Latencies = append(r.Latencies, other.Latencies...)
}

// Report prints a structured summary of the stress test results.
func (r *StressResult) Report(t *testing.T, name string) {
	t.Helper()
	sort.Slice(r.Latencies, func(i, j int) bool { return r.Latencies[i] < r.Latencies[j] })

	dur := r.Duration.Seconds()
	throughput := 0.0
	if dur > 0 {
		throughput = float64(r.Total) / dur
	}
	successPct := 0.0
	if r.Total > 0 {
		successPct = float64(r.Success) / float64(r.Total) * 100
	}

	t.Logf("")
	t.Logf("=== STRESS: %s ===", name)
	t.Logf("  Duration:     %.1fs", dur)
	t.Logf("  Total:        %s", fmtInt(r.Total))
	t.Logf("  Success:      %s (%.1f%%)", fmtInt(r.Success), successPct)
	t.Logf("  Rate Limited: %s", fmtInt(r.RateLimited))
	t.Logf("  Backpressure: %s", fmtInt(r.Backpressure))
	t.Logf("  Client Errors:%s", fmtInt(r.ClientErr))
	t.Logf("  Server Errors:%s", fmtInt(r.ServerErr))
	t.Logf("  Timeouts:     %s", fmtInt(r.Timeouts))
	t.Logf("  Throughput:   %.1f req/s", throughput)
	if len(r.Latencies) > 0 {
		t.Logf("  Latency p50:  %s", fmtDur(percentile(r.Latencies, 0.50)))
		t.Logf("  Latency p95:  %s", fmtDur(percentile(r.Latencies, 0.95)))
		t.Logf("  Latency p99:  %s", fmtDur(percentile(r.Latencies, 0.99)))
		t.Logf("  Latency max:  %s", fmtDur(r.Latencies[len(r.Latencies)-1]))
	}
}

// percentile returns the p-th percentile from a pre-sorted slice.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// fmtInt formats an int64 with comma separators.
func fmtInt(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// fmtDur formats a duration for display.
func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fus", float64(d.Microseconds()))
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}
