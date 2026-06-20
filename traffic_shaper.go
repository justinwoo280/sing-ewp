package ewp

import (
	"sync"
	"time"
)

// Traffic shaping for the SecureStream send side (v0.2.x).
//
// Padding (padding_policy.go) removes the *length* dimension of the
// TLS-in-TLS fingerprint. It does NOT touch the *timing* / *burst*
// dimension: an inner TLS-1.3 flight that emits N records back-to-back
// still produces N EWP frames with the same back-to-back arrival
// pattern, and the up/down packet-count ratio survives untouched.
// Burst-based classifiers key on exactly that.
//
// StreamShaper sits between the application byte stream and
// SecureStream.SendTCPData and reshapes the send timeline so it no
// longer mirrors the inner protocol:
//
//   - Application writes are coalesced inside a short, randomised
//     flush window. A burst of small inner records collapses into
//     fewer, larger EWP frames whose count no longer matches the
//     inner record count.
//   - During idle gaps the shaper emits FramePaddingOnly cover frames
//     drawn from an HTTPS-like inter-arrival distribution, so the
//     observable "silence then burst" shape that betrays a tunnelled
//     handshake is filled in.
//
// Everything the shaper emits still goes through SecureStream.sendFrame
// and is therefore fully padded + AEAD-sealed: there is no plaintext
// path here (Rule 2 holds). The shaper only decides WHEN bytes are
// flushed and WHETHER to inject cover, never how they are encrypted.
type ShaperConfig struct {
	// FlushDelay is the maximum time a write may sit in the coalescing
	// buffer before being flushed. A random delay in [0, FlushDelay]
	// is drawn per pending flush. Zero disables coalescing.
	FlushDelay time.Duration

	// MaxCoalesce caps how many application bytes accumulate before an
	// immediate flush (so latency-sensitive bulk transfer is not held
	// hostage to FlushDelay). Zero uses defaultMaxCoalesce.
	MaxCoalesce int

	// CoverIdleAfter is how long the stream must be idle (no
	// application send) before the cover-traffic loop starts emitting
	// FramePaddingOnly frames. Zero disables cover traffic.
	CoverIdleAfter time.Duration

	// CoverMinInterval / CoverMaxInterval bound the random gap between
	// successive cover frames while idle.
	CoverMinInterval time.Duration
	CoverMaxInterval time.Duration

	// CoverMaxPad bounds the random pad carried by each cover frame.
	// Clamped to MaxFramePad by SecureStream.
	CoverMaxPad int
}

// DefaultShaperConfig returns a configuration tuned to mimic the
// burst / idle rhythm of an HTTPS/1.1-over-TLS browsing session: small
// sub-millisecond coalescing windows, occasional cover frames during
// think-time gaps.
func DefaultShaperConfig() ShaperConfig {
	return ShaperConfig{
		FlushDelay:       2 * time.Millisecond,
		MaxCoalesce:      defaultMaxCoalesce,
		CoverIdleAfter:   400 * time.Millisecond,
		CoverMinInterval: 80 * time.Millisecond,
		CoverMaxInterval: 600 * time.Millisecond,
		CoverMaxPad:      512,
	}
}

const (
	// defaultMaxCoalesce is the byte ceiling for the coalescing buffer.
	// Anchored to the top steady bucket so a full buffer maps onto one
	// max-size frame rather than spilling into a second.
	defaultMaxCoalesce = 16384
)

// StreamShaper wraps a *SecureStream and reshapes its send timeline.
//
// Concurrency: WriteTCP is safe for concurrent callers; it serialises
// on mu. The background flush + cover goroutines are started lazily on
// the first WriteTCP and torn down by Close.
type StreamShaper struct {
	s   *SecureStream
	cfg ShaperConfig

	mu       sync.Mutex
	buf      []byte
	flushTmr *time.Timer

	lastActivity time.Time

	started   bool
	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewStreamShaper builds a shaper around s. A zero-value cfg disables
// all shaping and WriteTCP degenerates to a direct SendTCPData, so the
// shaper is always safe to install unconditionally.
func NewStreamShaper(s *SecureStream, cfg ShaperConfig) *StreamShaper {
	return &StreamShaper{
		s:            s,
		cfg:          cfg,
		stop:         make(chan struct{}),
		lastActivity: time.Now(),
	}
}

// WriteTCP submits application bytes for shaped delivery. The bytes
// are copied; the caller may reuse p immediately on return.
func (h *StreamShaper) WriteTCP(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if h.cfg.FlushDelay <= 0 {
		// Coalescing disabled: send directly but still record activity
		// so the cover loop (if enabled) backs off.
		h.touch()
		return h.s.SendTCPData(p)
	}

	h.mu.Lock()
	h.ensureStartedLocked()
	h.buf = append(h.buf, p...)
	h.lastActivity = time.Now()

	maxCoalesce := h.cfg.MaxCoalesce
	if maxCoalesce <= 0 {
		maxCoalesce = defaultMaxCoalesce
	}
	if len(h.buf) >= maxCoalesce {
		// Buffer full: flush synchronously to keep bulk throughput up.
		return h.flushLocked()
	}
	// Arm a flush timer if one is not already pending.
	if h.flushTmr == nil {
		delay := h.cfg.FlushDelay
		if jit := randDuration(h.cfg.FlushDelay); jit > 0 {
			delay = jit
		}
		h.flushTmr = time.AfterFunc(delay, h.onFlushTimer)
	}
	h.mu.Unlock()
	return nil
}

// onFlushTimer is the time.AfterFunc callback: it flushes whatever has
// accumulated. Errors are swallowed here (the next WriteTCP / Recv will
// observe the closed stream); the goroutine must not panic.
func (h *StreamShaper) onFlushTimer() {
	h.mu.Lock()
	h.flushTmr = nil
	_ = h.flushLocked()
}

// flushLocked drains the coalescing buffer in one or more frames. It is
// called with mu held and RELEASES mu before returning (the actual
// SendTCPData happens off-lock so a slow transport does not block
// concurrent WriteTCP callers from buffering).
func (h *StreamShaper) flushLocked() error {
	if len(h.buf) == 0 {
		h.mu.Unlock()
		return nil
	}
	out := h.buf
	h.buf = nil
	h.lastActivity = time.Now()
	h.mu.Unlock()

	maxPayload := MaxFrameSize - 256
	var err error
	for len(out) > 0 && err == nil {
		chunk := out
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		err = h.s.SendTCPData(chunk)
		out = out[len(chunk):]
	}
	return err
}

// touch records send-side activity without buffering (used on the
// no-coalesce fast path).
func (h *StreamShaper) touch() {
	h.mu.Lock()
	h.lastActivity = time.Now()
	h.ensureStartedLocked()
	h.mu.Unlock()
}

// ensureStartedLocked lazily launches the cover-traffic goroutine. Must
// be called with mu held.
func (h *StreamShaper) ensureStartedLocked() {
	if h.started {
		return
	}
	h.started = true
	if h.cfg.CoverIdleAfter > 0 && h.cfg.CoverMaxInterval > 0 {
		h.wg.Add(1)
		go h.coverLoop()
	}
}

// coverLoop emits FramePaddingOnly frames during idle periods so a
// passive observer sees HTTPS-like keepalive chatter instead of the
// dead-air-then-burst silhouette of a tunnelled inner handshake.
func (h *StreamShaper) coverLoop() {
	defer h.wg.Done()
	for {
		wait := h.cfg.CoverMinInterval + randDuration(h.cfg.CoverMaxInterval-h.cfg.CoverMinInterval)
		if wait <= 0 {
			wait = h.cfg.CoverMinInterval
		}
		t := time.NewTimer(wait)
		select {
		case <-h.stop:
			t.Stop()
			return
		case <-t.C:
		}
		if h.s.closed.Load() {
			return
		}
		h.mu.Lock()
		idle := time.Since(h.lastActivity)
		h.mu.Unlock()
		if idle < h.cfg.CoverIdleAfter {
			continue // recently active; real traffic is the cover
		}
		pad := h.cfg.CoverMaxPad
		if pad > 0 {
			pad = secureRandIntn(pad)
		}
		if err := h.s.SendCoverPad(pad); err != nil {
			return
		}
	}
}

// Flush forces any buffered bytes out immediately.
func (h *StreamShaper) Flush() error {
	h.mu.Lock()
	if h.flushTmr != nil {
		h.flushTmr.Stop()
		h.flushTmr = nil
	}
	return h.flushLocked()
}

// Close stops the background goroutines and flushes residual bytes. It
// does NOT close the underlying SecureStream (the owner does that).
func (h *StreamShaper) Close() error {
	var err error
	h.closeOnce.Do(func() {
		err = h.Flush()
		close(h.stop)
	})
	h.wg.Wait()
	return err
}

// randDuration returns a uniform random duration in [0, d). For d <= 0
// it returns 0.
func randDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(secureRandIntn(int(d)))
}
