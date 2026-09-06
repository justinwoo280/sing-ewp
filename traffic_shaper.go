package ewp

import (
	"io"
	"sync"
	"sync/atomic"
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

	// shaperCloseFlushTimeout bounds graceful delivery during Close before the
	// underlying transport is interrupted to release an in-flight cover send.
	shaperCloseFlushTimeout = 100 * time.Millisecond
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
	sendMu   sync.Mutex
	buf      []byte
	flushTmr *time.Timer

	lastActivity time.Time

	started     bool
	stopped     atomic.Bool
	closing     atomic.Bool
	terminalErr error
	stop        chan struct{}
	stopOnce    sync.Once
	closeOnce   sync.Once
	closeErr    error
	wg          sync.WaitGroup
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
	if h.closing.Load() || h.stopped.Load() {
		return h.terminalError()
	}
	if len(p) == 0 {
		return nil
	}
	h.mu.Lock()
	if h.closing.Load() {
		h.mu.Unlock()
		return io.ErrClosedPipe
	}
	if err := h.stateErrorLocked(); err != nil {
		h.mu.Unlock()
		return err
	}
	if h.cfg.FlushDelay <= 0 {
		// Coalescing disabled: send directly but still record activity
		// so the cover loop (if enabled) backs off.
		h.lastActivity = time.Now()
		h.ensureStartedLocked()
		h.mu.Unlock()
		h.sendMu.Lock()
		err := h.s.SendTCPData(p)
		if err != nil {
			h.signalStop()
		}
		h.sendMu.Unlock()
		if err != nil {
			h.finishStop(err)
		}
		return err
	}

	h.ensureStartedLocked()
	h.buf = append(h.buf, p...)
	h.lastActivity = time.Now()

	maxCoalesce := h.cfg.MaxCoalesce
	if maxCoalesce <= 0 {
		maxCoalesce = defaultMaxCoalesce
	}
	if len(h.buf) >= maxCoalesce {
		// Buffer full: flush synchronously to keep bulk throughput up.
		err := h.flushLocked()
		if err != nil {
			h.finishStop(err)
		}
		return err
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
// accumulated and records a terminal error so later writes cannot report
// success for data that will never reach the peer.
func (h *StreamShaper) onFlushTimer() {
	if h.closing.Load() {
		return
	}
	h.mu.Lock()
	h.flushTmr = nil
	if h.closing.Load() {
		h.mu.Unlock()
		return
	}
	if err := h.stateErrorLocked(); err != nil {
		h.mu.Unlock()
		return
	}
	err := h.flushLocked()
	if err != nil {
		h.finishStop(err)
	}
}

// flushLocked drains the coalescing buffer in one or more frames. It is
// called with mu held and releases mu before the actual sends. sendMu is
// acquired while mu is still held so flushes are emitted in buffer order.
func (h *StreamShaper) flushLocked() error {
	if err := h.stateErrorLocked(); err != nil {
		h.mu.Unlock()
		return err
	}
	if len(h.buf) == 0 {
		h.mu.Unlock()
		return nil
	}
	h.sendMu.Lock()
	out := h.buf
	h.buf = nil
	h.lastActivity = time.Now()
	h.mu.Unlock()
	defer h.sendMu.Unlock()

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
	if err != nil {
		h.signalStop()
	}
	return err
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
		if h.closing.Load() {
			return
		}
		if h.s.closed.Load() {
			h.recordTerminal(io.ErrClosedPipe)
			return
		}
		h.mu.Lock()
		if h.closing.Load() || h.stopped.Load() {
			h.mu.Unlock()
			return
		}
		idle := time.Since(h.lastActivity)
		h.mu.Unlock()
		if idle < h.cfg.CoverIdleAfter {
			continue // recently active; real traffic is the cover
		}
		pad := h.cfg.CoverMaxPad
		if pad > 0 {
			pad = secureRandIntn(pad)
		}
		h.sendMu.Lock()
		err := h.s.SendCoverPad(pad)
		if err != nil {
			h.signalStop()
		}
		h.sendMu.Unlock()
		if err != nil {
			h.finishStop(err)
			return
		}
	}
}

// Flush forces any buffered bytes out immediately.
func (h *StreamShaper) Flush() error {
	h.mu.Lock()
	if err := h.stateErrorLocked(); err != nil {
		h.mu.Unlock()
		return err
	}
	if h.flushTmr != nil {
		h.flushTmr.Stop()
		h.flushTmr = nil
	}
	err := h.flushLocked()
	if err != nil {
		h.finishStop(err)
	}
	return err
}

// Close rejects new writes, gives an already-buffered flush a short bounded
// chance to finish, then closes the underlying SecureStream before waiting for
// a blocked cover or flush send. A net.Conn Close cannot guarantee delivery of
// buffered bytes; prioritising teardown prevents a non-reading peer from
// hanging shutdown.
func (h *StreamShaper) Close() error {
	h.closeOnce.Do(func() {
		h.closeErr = h.close()
	})
	return h.closeErr
}

func (h *StreamShaper) close() error {
	h.closing.Store(true)
	flushDone := make(chan error, 1)
	go func() { flushDone <- h.Flush() }()

	timer := time.NewTimer(shaperCloseFlushTimeout)
	var (
		flushErr error
		timedOut bool
	)
	select {
	case flushErr = <-flushDone:
		timer.Stop()
	case <-timer.C:
		timedOut = true
	}

	h.signalStop()
	streamErr := h.s.Close()
	if timedOut {
		flushErr = <-flushDone
	}
	h.finishStop(nil)
	h.wg.Wait()
	h.mu.Lock()
	terminalErr := h.terminalErr
	h.mu.Unlock()
	if terminalErr != nil {
		return terminalErr
	}
	if !timedOut && flushErr != nil {
		return flushErr
	}
	return streamErr
}

func (h *StreamShaper) stateErrorLocked() error {
	if h.terminalErr != nil {
		return h.terminalErr
	}
	if h.stopped.Load() {
		return io.ErrClosedPipe
	}
	return nil
}

func (h *StreamShaper) terminalError() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.terminalErr != nil {
		return h.terminalErr
	}
	return io.ErrClosedPipe
}

func (h *StreamShaper) recordTerminal(err error) {
	h.signalStop()
	h.finishStop(err)
}

func (h *StreamShaper) signalStop() {
	h.stopped.Store(true)
	h.stopOnce.Do(func() { close(h.stop) })
}

func (h *StreamShaper) finishStop(err error) {
	h.mu.Lock()
	if err != nil && h.terminalErr == nil && !h.closing.Load() {
		h.terminalErr = err
	}
	if h.flushTmr != nil {
		h.flushTmr.Stop()
		h.flushTmr = nil
	}
	h.buf = nil
	h.mu.Unlock()
}

// randDuration returns a uniform random duration in [0, d). For d <= 0
// it returns 0.
func randDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(secureRandIntn(int(d)))
}
