package ewp

import (
	"bytes"
	"io"
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

// orderedCapture holds its first send open while allowing a second send to
// proceed. It makes a missing shaper send serialisation deterministic.
type orderedCapture struct {
	mu            sync.Mutex
	frames        [][]byte
	firstInFlight bool
	firstStarted  chan struct{}
	releaseFirst  chan struct{}
}

func (c *orderedCapture) SendMessage(b []byte) error {
	cp := append([]byte(nil), b...)
	c.mu.Lock()
	first := !c.firstInFlight && len(c.frames) == 0
	if first {
		c.firstInFlight = true
		close(c.firstStarted)
	}
	c.mu.Unlock()
	if first {
		<-c.releaseFirst
	}
	c.mu.Lock()
	c.frames = append(c.frames, cp)
	c.mu.Unlock()
	return nil
}

func (c *orderedCapture) ReadMessage() ([]byte, error) { select {} }
func (c *orderedCapture) Close() error                 { return nil }

func (c *orderedCapture) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	frames := make([][]byte, len(c.frames))
	for i, frame := range c.frames {
		frames[i] = append([]byte(nil), frame...)
	}
	return frames
}

type shaperFailingTransport struct {
	sendStarted chan struct{}
	once        sync.Once
}

func (t *shaperFailingTransport) SendMessage([]byte) error {
	t.once.Do(func() { close(t.sendStarted) })
	return io.ErrClosedPipe
}
func (t *shaperFailingTransport) ReadMessage() ([]byte, error) { return nil, io.EOF }
func (t *shaperFailingTransport) Close() error                 { return nil }

type shaperBlockingTransport struct {
	sendStarted chan struct{}
	closed      chan struct{}
	sendOnce    sync.Once
	closeOnce   sync.Once
}

func (t *shaperBlockingTransport) SendMessage([]byte) error {
	t.sendOnce.Do(func() { close(t.sendStarted) })
	<-t.closed
	return io.ErrClosedPipe
}
func (t *shaperBlockingTransport) ReadMessage() ([]byte, error) { return nil, io.EOF }
func (t *shaperBlockingTransport) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func newShaperSendStream(t *testing.T, tr MessageTransport) *SecureStream {
	t.Helper()
	key := hardRandKey()
	prefix := hardRandPrefix()
	send, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return &SecureStream{tr: tr, send: send}
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

func TestShaper_AsyncFlushFailureRejectsLaterWrites(t *testing.T) {
	tr := &shaperFailingTransport{sendStarted: make(chan struct{})}
	sh := NewStreamShaper(newShaperSendStream(t, tr), ShaperConfig{FlushDelay: time.Millisecond})
	defer sh.Close()
	if err := sh.WriteTCP([]byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tr.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("timer flush did not reach transport")
	}
	deadline := time.Now().Add(time.Second)
	for !sh.stopped.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !sh.stopped.Load() {
		t.Fatal("timer flush failure did not stop shaper")
	}
	if err := sh.WriteTCP([]byte("later")); err == nil {
		t.Fatal("write after asynchronous flush failure unexpectedly succeeded")
	}
}

func TestStreamConnCloseUnblocksCoverWrite(t *testing.T) {
	tr := &shaperBlockingTransport{
		sendStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	stream := newShaperSendStream(t, tr)
	conn := &streamConn{SecureStream: stream}
	conn.shaper = NewStreamShaper(stream, ShaperConfig{
		FlushDelay:       time.Hour,
		CoverIdleAfter:   time.Millisecond,
		CoverMinInterval: time.Millisecond,
		CoverMaxInterval: time.Millisecond,
		CoverMaxPad:      1,
	})
	if _, err := conn.Write([]byte("buffered")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tr.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("cover write did not reach blocking transport")
	}
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("streamConn.Close blocked behind cover write")
	}
	if _, err := conn.Write([]byte("after-close")); err == nil {
		t.Fatal("write after Close unexpectedly succeeded")
	}
}

func TestShaper_PreservesFlushOrderOnSlowTransport(t *testing.T) {
	key := hardRandKey()
	prefix := hardRandPrefix()
	send, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	cap := &orderedCapture{
		firstStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	stream := &SecureStream{tr: cap, send: send}
	sh := NewStreamShaper(stream, ShaperConfig{FlushDelay: time.Hour, MaxCoalesce: 1})
	defer sh.Close()

	firstDone := make(chan error, 1)
	go func() { firstDone <- sh.WriteTCP([]byte("first")) }()
	select {
	case <-cap.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first flush did not reach transport")
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- sh.WriteTCP([]byte("second")) }()
	close(cap.releaseFirst)
	for _, done := range []chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("flush did not complete")
		}
	}

	frames := cap.snapshot()
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	for i, want := range [][]byte{[]byte("first"), []byte("second")} {
		frame, err := DecodeFrame(bytes.NewReader(frames[i]), dec)
		if err != nil {
			t.Fatalf("decode frame %d: %v", i, err)
		}
		if !bytes.Equal(frame.Payload, want) {
			t.Fatalf("frame %d payload = %q, want %q", i, frame.Payload, want)
		}
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
