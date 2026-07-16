package redis

import (
	"bufio"
	"errors"
	"testing"
)

// The budget-driven cases in TestWriteCommand_PropagatesWriteErrors never make
// the very first WriteByte fail: with an empty bufio buffer that byte is always
// buffered and a later write is the one that flushes and breaks. A connection
// whose previous command left the buffer full (or the writer already errored)
// fails on the array-header byte itself, and writeCommand must return that
// error rather than encode the rest of the frame onto a dead writer.
func TestWriteCommand_ArrayHeaderByteFailure(t *testing.T) {
	w := bufio.NewWriterSize(&failingWriter{remaining: 0}, 1)
	if err := w.WriteByte('x'); err != nil {
		t.Fatalf("priming byte should buffer, not flush: %v", err)
	}

	err := writeCommand(w, "PING")
	if !errors.Is(err, errWriteFailed) {
		t.Fatalf("writeCommand = %v, want %v", err, errWriteFailed)
	}
}
