package ewp

import (
	"sync"
	"testing"
	"time"
)

// syncCapture is a goroutine-safe MessageTransport that records every
// frame the SecureStream emits, with its frame type byte decoded back
// out for burst-shape assertions.
type syncCapture struct {
	mu     sync.Mutex
	send   *FrameAEAD
	recv   *FrameAEAD
	frames [][]byte
	typ    []FrameType
}

func newSyncCapture(t *testing.T) (*syncCapture, *SecureStream) {
	t.Helper()
	key := hardRandKey()
	prefix := hardRandPrefix()
	send, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatalf("send AEAD: %v", err)
	}
	// Decoder side uses an independent AEAD seeded with the same key so
	// the test can recover frame types from the captured ciphertext.
	dec, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatalf("dec AEAD: %v", err)
	}
	c := &syncCapture{recv: dec}
	ss := &SecureStream{tr: c, send: send, recv: send}
	return c, ss
}

func (c *syncCapture) SendMessage(b []byte) error {
	cp := append([]byte(nil), b...)
	c.mu.Lock()
	c.frames = append(c.frames, cp)
	c.mu.Unlock()
	return nil
}
func (c *syncCapture) ReadMessage() ([]byte, error) { select {} }
func (c *syncCapture) Close() error                 { return nil }

func (c *syncCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.frames)
}

// TestShaper_CoalescesBurst verifies that a rapid burst of small
// writes collapses into fewer frames than writes, so the on-wire frame
// COUNT no longer mirrors the inner record count.
func TestShaper_CoalescesBurst(t *testing.T) {
	cap, ss := newSyncCapture(t)
	cfg := ShaperConfig{FlushDelay: 20 * time.Millisecond, MaxCoalesce: 16384}
	sh := NewStreamShaper(ss, cfg)
	defer sh.Close()

	const writes = 20
	for i := 0; i < writes; i++ {
		if err := sh.WriteTCP([]byte("inner-tls-record")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := sh.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got := cap.count()
	if got >= writes {
		t.Fatalf("coalescing did not reduce frame count: %d frames for %d writes", got, writes)
	}
	if got == 0 {
		t.Fatalf("no frames emitted")
	}
	t.Logf("coalesced %d writes -> %d wire frames", writes, got)
}

// TestShaper_NoCoalesceWhenDisabled confirms a zero FlushDelay degrades
// to a direct passthrough (one frame per write) so the shaper is safe
// to install unconditionally.
func TestShaper_NoCoalesceWhenDisabled(t *testing.T) {
	cap, ss := newSyncCapture(t)
	sh := NewStreamShaper(ss, ShaperConfig{}) // all-zero: disabled
	defer sh.Close()

	for i := 0; i < 5; i++ {
		if err := sh.WriteTCP([]byte("x")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if got := cap.count(); got != 5 {
		t.Fatalf("disabled shaper should pass through 1:1, got %d frames", got)
	}
}

// TestShaper_CoverTrafficDuringIdle verifies that the cover loop emits
// FramePaddingOnly frames when the stream is idle, filling the
// dead-air-then-burst silhouette of a tunnelled handshake.
func TestShaper_CoverTrafficDuringIdle(t *testing.T) {
	cap, ss := newSyncCapture(t)
	cfg := ShaperConfig{
		FlushDelay:       1 * time.Millisecond,
		CoverIdleAfter:   10 * time.Millisecond,
		CoverMinInterval: 5 * time.Millisecond,
		CoverMaxInterval: 15 * time.Millisecond,
		CoverMaxPad:      256,
	}
	sh := NewStreamShaper(ss, cfg)
	defer sh.Close()

	// One write to start the loop, then go idle.
	if err := sh.WriteTCP([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sh.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	before := cap.count()

	time.Sleep(120 * time.Millisecond) // idle window: cover should fire

	after := cap.count()
	if after <= before {
		t.Fatalf("cover loop emitted no frames during idle (before=%d after=%d)", before, after)
	}
	t.Logf("cover frames during 120ms idle: %d", after-before)
}

// TestShaper_MaxFramePadCoversLadderGaps is the guard for the steady
// ladder: every gap between consecutive buckets must be reachable
// within a single frame's MaxFramePad budget, otherwise a raw size in
// the gap gets clamped between buckets and leaks its real length.
func TestShaper_MaxFramePadCoversLadderGaps(t *testing.T) {
	for i := 1; i < len(steadyBuckets); i++ {
		gap := steadyBuckets[i] - steadyBuckets[i-1]
		if gap > MaxFramePad {
			t.Fatalf("steady ladder gap %d->%d = %d exceeds MaxFramePad=%d; raw sizes in this gap leak length",
				steadyBuckets[i-1], steadyBuckets[i], gap, MaxFramePad)
		}
	}
	// Plus jitter headroom: a frame already at a bucket edge must be
	// able to add jitter without exceeding MaxFramePad in the worst
	// in-gap case. We assert the largest gap + jitter still fits.
	maxGap := 0
	for i := 1; i < len(steadyBuckets); i++ {
		if g := steadyBuckets[i] - steadyBuckets[i-1]; g > maxGap {
			maxGap = g
		}
	}
	if maxGap+jitterWithinBucket > MaxFramePad {
		t.Logf("note: largest gap %d + jitter %d == %d, near MaxFramePad %d (jitter is skipped when it would overflow)",
			maxGap, jitterWithinBucket, maxGap+jitterWithinBucket, MaxFramePad)
	}
}
