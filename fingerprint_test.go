package ewp

// Strict length / timing fingerprint tests for EWP v2.
//
// These tests intentionally measure observable wire properties.
// They do not exercise correctness (other tests do); they exercise
// whether an on-path observer can recover internal payload structure
// from the SecureStream's output bytes alone.
//
// All tests use the in-memory transport from v2_test.go (memTransport).
// We snapshot every wire message sent from one side, then post-process.

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// capturingTransport is a blocking, lossless paired transport built
// specifically for these tests. It also records every outbound
// message so the test can observe wire sizes without racing the
// reader goroutine.
type capturingTransport struct {
	name   string
	in     chan []byte // receive side (delivered FROM peer)
	out    chan []byte // send side (delivered TO peer)

	recMu      sync.Mutex
	record     [][]byte // copies of bytes we sent
	closedFlag bool

	closeOnce sync.Once
	done      chan struct{}
}

func newCapturingPair() (*capturingTransport, *capturingTransport) {
	a2b := make(chan []byte, 1024)
	b2a := make(chan []byte, 1024)
	a := &capturingTransport{name: "A", in: b2a, out: a2b, done: make(chan struct{})}
	b := &capturingTransport{name: "B", in: a2b, out: b2a, done: make(chan struct{})}
	return a, b
}

func (c *capturingTransport) SendMessage(b []byte) error {
	cp := append([]byte(nil), b...)
	c.recMu.Lock()
	if c.closedFlag {
		c.recMu.Unlock()
		return io.ErrClosedPipe
	}
	c.record = append(c.record, cp)
	// Send while still holding the lock so Close cannot run between
	// the closedFlag check and the send (which would race against
	// close(c.out)).
	select {
	case c.out <- cp:
		c.recMu.Unlock()
		return nil
	case <-c.done:
		c.recMu.Unlock()
		return io.ErrClosedPipe
	}
}

func (c *capturingTransport) ReadMessage() ([]byte, error) {
	select {
	case b, ok := <-c.in:
		if !ok {
			return nil, io.EOF
		}
		return b, nil
	case <-c.done:
		return nil, io.EOF
	}
}

func (c *capturingTransport) Close() error {
	c.closeOnce.Do(func() {
		c.recMu.Lock()
		c.closedFlag = true
		close(c.done)
		close(c.out)
		c.recMu.Unlock()
	})
	return nil
}

func (c *capturingTransport) sizes() []int {
	c.recMu.Lock()
	defer c.recMu.Unlock()
	out := make([]int, len(c.record))
	for i, b := range c.record {
		out[i] = len(b)
	}
	return out
}

func (c *capturingTransport) snapshot() [][]byte {
	c.recMu.Lock()
	defer c.recMu.Unlock()
	out := make([][]byte, len(c.record))
	for i, b := range c.record {
		cp := append([]byte(nil), b...)
		out[i] = cp
	}
	return out
}

// makePair returns a connected pair of SecureStreams.
// We fully bypass the handshake by minting deterministic keys.
func makePair(t *testing.T) (client *SecureStream, server *SecureStream, clientTr *capturingTransport) {
	t.Helper()
	a, b := newCapturingPair()

	var keys SessionKeys
	_, _ = rand.Read(keys.C2SKey[:])
	_, _ = rand.Read(keys.S2CKey[:])
	_, _ = rand.Read(keys.C2SNonce[:])
	_, _ = rand.Read(keys.S2CNonce[:])

	cs, err := NewClientSecureStream(a, keys)
	if err != nil {
		t.Fatalf("NewClientSecureStream: %v", err)
	}
	ss, err := NewServerSecureStream(b, keys)
	if err != nil {
		t.Fatalf("NewServerSecureStream: %v", err)
	}
	return cs, ss, a
}

// drainRecv keeps server.Recv running until the client closes, so the
// in-memory buffered channel doesn't stall sends. Returns when EOF.
func drainRecv(t *testing.T, s *SecureStream) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, err := s.Recv()
			if err != nil {
				return
			}
		}
	}()
	return done
}

// (capturingTransport records sizes itself; no separate goroutine needed.)

// spearman computes the Spearman rank correlation between two equal-
// length sequences. Returns NaN if either is constant.
func spearman(x, y []float64) float64 {
	if len(x) != len(y) || len(x) < 2 {
		return math.NaN()
	}
	rx := ranks(x)
	ry := ranks(y)
	var n = float64(len(x))
	var sumDD float64
	for i := range rx {
		d := rx[i] - ry[i]
		sumDD += d * d
	}
	return 1.0 - (6.0*sumDD)/(n*(n*n-1.0))
}

func ranks(v []float64) []float64 {
	type iv struct {
		i int
		v float64
	}
	s := make([]iv, len(v))
	for i, x := range v {
		s[i] = iv{i, x}
	}
	sort.Slice(s, func(i, j int) bool { return s[i].v < s[j].v })
	r := make([]float64, len(v))
	i := 0
	for i < len(s) {
		j := i
		for j+1 < len(s) && s[j+1].v == s[i].v {
			j++
		}
		// average rank for the tied group (1-based)
		avg := float64(i+j+2) / 2.0
		for k := i; k <= j; k++ {
			r[s[k].i] = avg
		}
		i = j + 1
	}
	return r
}

// unique counts distinct values.
func unique(xs []int) int {
	m := map[int]struct{}{}
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return len(m)
}

// shannonEntropy of an empirical distribution over int values, in bits.
func shannonEntropy(xs []int) float64 {
	if len(xs) == 0 {
		return 0
	}
	count := map[int]int{}
	for _, x := range xs {
		count[x]++
	}
	n := float64(len(xs))
	var h float64
	for _, c := range count {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// ---------------------------------------------------------------------
// FP1: input length ↔ output length correlation
//
// THREAT: observer can predict input payload size from wire size.
// IDEAL : Spearman correlation should be small (< 0.3) once padding
//         buckets dominate.
// REALITY EXPECTED: extremely high correlation (>0.99), because the
// current padding is uniform[0..64) which is a small additive noise.
// ---------------------------------------------------------------------

func TestFingerprint_LengthCorrelation(t *testing.T) {
	cs, ss, ctr := makePair(t)
	defer cs.Close()
	defer ss.Close()
	done := drainRecv(t, ss)


	// Mix of payload sizes spanning the realistic TCP-data spectrum.
	sizes := []int{40, 80, 200, 517, 800, 1200, 1500, 2200, 3000, 4500, 6000, 9000, 14000, 16000, 24000, 32000, 48000, 60000}
	// Replicate the schedule a few times so statistics are meaningful.
	var input []int
	for rep := 0; rep < 50; rep++ {
		input = append(input, sizes...)
	}

	for _, n := range input {
		buf := make([]byte, n)
		_, _ = rand.Read(buf)
		if err := cs.SendTCPData(buf); err != nil {
			t.Fatalf("SendTCPData(%d): %v", n, err)
		}
	}

	// (capturingTransport records inside SendMessage.)
	_ = cs.Close()
	<-done
	

	// SendTCPData may chunk; but for sizes <= MaxFrameSize-256 each call
	// produces a single frame. We sent 18 sizes; chunking only kicks in
	// near MaxFrameSize. Filter to non-chunked calls only to keep the
	// 1:1 mapping clean.
	if len(ctr.sizes()) < len(input) {
		t.Fatalf("wire frames %d < input frames %d (transport lost data?)", len(ctr.sizes()), len(input))
	}

	// Take the first len(input) frames (the chunked tail is benign).
	wire := ctr.sizes()[:len(input)]
	inX := make([]float64, len(input))
	inY := make([]float64, len(input))
	for i := range input {
		inX[i] = float64(input[i])
		inY[i] = float64(wire[i])
	}
	rho := spearman(inX, inY)

	// Average overhead per frame.
	var overheadSum int
	for i := range input {
		overheadSum += wire[i] - input[i]
	}
	avgOverhead := float64(overheadSum) / float64(len(input))

	t.Logf("Spearman(payload_len, wire_len) = %.4f over %d frames", rho, len(input))
	t.Logf("avg per-frame overhead = %.1f B (header+AEAD+pad)", avgOverhead)

	// Threshold: a good padding policy should drive this below 0.30 by
	// bucketing. We assert <0.30 -- this test SHOULD FAIL on the
	// current implementation, exposing the leak.
	if rho > 0.30 {
		t.Errorf("FAIL: wire length is strongly determined by payload length (Spearman %.4f > 0.30). TLS-in-TLS length fingerprint survives EWP framing.", rho)
	}
}

// ---------------------------------------------------------------------
// FP2: bucket count for a fixed-size payload
//
// THREAT: padding adds entropy; we want the wire-size distribution to
// have low correlation with payload size AND to NOT be a delta around
// payload+const. A useful padder maps a given payload to MANY distinct
// wire sizes (the random component fills a wide span) OR to a small
// number of fixed buckets that are shared with OTHER payload sizes.
//
// We check the easier property here: for one fixed payload size, how
// many distinct wire lengths appear over many sends.
// ---------------------------------------------------------------------

func TestFingerprint_FixedPayloadDistribution(t *testing.T) {
	cs, ss, ctr := makePair(t)
	defer cs.Close()
	defer ss.Close()
	done := drainRecv(t, ss)


	const N = 2000
	const payloadLen = 1024
	payload := make([]byte, payloadLen)
	_, _ = rand.Read(payload)

	for i := 0; i < N; i++ {
		if err := cs.SendTCPData(payload); err != nil {
			t.Fatalf("SendTCPData: %v", err)
		}
	}

	_ = cs.Close()
	<-done
	

	wire := ctr.sizes()[:N]

	minL, maxL := wire[0], wire[0]
	for _, x := range wire {
		if x < minL {
			minL = x
		}
		if x > maxL {
			maxL = x
		}
	}
	t.Logf("fixed payload=%d: wire size range = [%d, %d] (span %d), distinct values = %d, H = %.2f bits",
		payloadLen, minL, maxL, maxL-minL, unique(wire), shannonEntropy(wire))

	// We expect the current implementation to produce a span of ~64
	// (the uniform[0..64) pad). That is far too small to mask anything.
	// A reasonable padder would either map everything to ONE bucket
	// (e.g. always 1500 B) OR span >= 512 with high entropy.
	span := maxL - minL
	distinct := unique(wire)
	if span < 256 && distinct > 1 {
		t.Errorf("FAIL: padding span is %d B (<256) and not single-bucket; this is the worst of both worlds: leaks payload length AND wastes entropy on tiny jitter.", span)
	}
}

// ---------------------------------------------------------------------
// FP3: TLS-1.3 handshake replay shape
//
// We replay representative TLS-1.3 record sizes observed for a typical
// HTTPS GET to a CDN:
//
//   CH  ~  517
//   SH+EE+Cert+CV+Fin ~ 3800  (often split into 2 records, sum ~4200)
//   Fin (client) ~ 80
//   app_data (request) ~ 600
//   app_data (response chunks) ~ 16384 .. 1500
//
// A successful unmasking attack only needs to recognise this LENGTH
// SEQUENCE -- it doesn't decrypt. So we send these sizes through the
// SecureStream and check whether the output sequence is still uniquely
// identifiable.
//
// Metric: edit-distance-free comparison -- if you sort the input sizes
// and the output sizes and compute correlation, very high correlation
// means the SHAPE survived. We also report the raw sequence so a
// human can eyeball it.
// ---------------------------------------------------------------------

func TestFingerprint_TLSHandshakeShapeSurvives(t *testing.T) {
	cs, ss, ctr := makePair(t)
	defer cs.Close()
	defer ss.Close()
	done := drainRecv(t, ss)


	// Synthetic but realistic TLS 1.3 record-size sequence. The first
	// 16 records (handshake phase) are heavily padded, so we focus
	// the statistical test on the STEADY-STATE behaviour after that
	// budget is spent. Inner-TLS handshakes are 6-12 records, so they
	// are covered separately by FP6 (PaddingNotPhaseAware). Here we
	// check that even after the handshake budget runs out, repeated
	// TLS-record sequences cannot be recovered by rank correlation.
	baseSeq := []int{517, 2800, 1600, 80, 600, 14000, 14000, 9000, 1500, 80}
	const reps = 30 // 300 frames total — well past handshakePhaseFrames=16.
	var seq []int
	for i := 0; i < reps; i++ {
		seq = append(seq, baseSeq...)
	}
	for _, n := range seq {
		buf := make([]byte, n)
		_, _ = rand.Read(buf)
		if err := cs.SendTCPData(buf); err != nil {
			t.Fatalf("SendTCPData(%d): %v", n, err)
		}
	}

	_ = cs.Close()
	<-done

	wireAll := ctr.sizes()
	if len(wireAll) < len(seq) {
		t.Fatalf("got %d wire frames, expected >= %d", len(wireAll), len(seq))
	}
	// Drop the first len(baseSeq) frames (handshake phase) and look at
	// the steady-state tail.
	drop := len(baseSeq) + handshakePhaseFrames
	if drop >= len(seq) {
		drop = 0
	}
	seqTail := seq[drop:]
	wireTail := wireAll[drop:len(seq)]

	x := make([]float64, len(seqTail))
	y := make([]float64, len(seqTail))
	for i := range seqTail {
		x[i] = float64(seqTail[i])
		y[i] = float64(wireTail[i])
	}
	rho := spearman(x, y)
	t.Logf("Spearman over steady-state TLS-shape replay (%d frames) = %.4f", len(seqTail), rho)

	if rho > 0.5 {
		t.Errorf("FAIL: the TLS-record length silhouette survives bucketing (Spearman %.4f > 0.5). Inner-TLS record sequence is recoverable.", rho)
	}
}

// ---------------------------------------------------------------------
// FP4: large-frame reshape is MISSING
//
// XTLS/Vision splits oversized records to disrupt the "16KB ceiling"
// fingerprint. EWP currently never reshapes. We send N payloads at
// exactly MaxFrameSize-256 and count how many distinct wire lengths
// appear. A reshape policy would produce >1 cluster; a no-reshape
// policy will produce ~1 (plus the small pad jitter).
// ---------------------------------------------------------------------

func TestFingerprint_NoLargeFrameReshape(t *testing.T) {
	cs, ss, ctr := makePair(t)
	defer cs.Close()
	defer ss.Close()
	done := drainRecv(t, ss)


	const N = 500
	big := make([]byte, MaxFrameSize-256)
	_, _ = rand.Read(big)
	for i := 0; i < N; i++ {
		if err := cs.SendTCPData(big); err != nil {
			t.Fatalf("SendTCPData: %v", err)
		}
	}

	_ = cs.Close()
	<-done
	

	wire := ctr.sizes()
	minL, maxL := wire[0], wire[0]
	for _, x := range wire {
		if x < minL {
			minL = x
		}
		if x > maxL {
			maxL = x
		}
	}
	t.Logf("large payload (MaxFrameSize-256) -> wire range [%d, %d], distinct=%d, frames=%d (no chunking happened)",
		minL, maxL, unique(wire), len(wire))

	// Without reshape we expect EXACTLY N frames (no split) and all
	// roughly the same size, an unmistakable signature.
	if len(wire) != N {
		t.Logf("NOTE: large frames produced %d wire messages for %d sends -- reshape exists", len(wire), N)
	} else if maxL-minL < 256 {
		t.Errorf("FAIL: %d consecutive near-MaxFrameSize frames all within %d B of each other -> 'streaming download' length signature.", N, maxL-minL)
	}
}

// ---------------------------------------------------------------------
// FP5: idle / cover-traffic absence
//
// THREAT: timing+packet-count fingerprint. A real client that just
// connected to Cloudflare keeps emitting keep-alives / cover. EWP
// has FramePaddingOnly defined but nothing automatically emits it.
// We assert: after handshake, with no application sends, the wire is
// silent for at least 2 seconds. (Currently this WILL pass, because
// the silence IS the fingerprint -- so we flip the assertion: silence
// is bad.)
// ---------------------------------------------------------------------

func TestFingerprint_IdleSilenceIsAFingerprint(t *testing.T) {
	cs, ss, ctr := makePair(t)
	defer cs.Close()
	defer ss.Close()
	done := drainRecv(t, ss)

	cs.StartCoverTraffic(CoverConfig{
		Interval:   200 * time.Millisecond,
		IdleAfter:  200 * time.Millisecond,
		JitterFrac: 0.5,
	})

	// Send ONE small data frame, then idle.
	if err := cs.SendTCPData([]byte("hello")); err != nil {
		t.Fatalf("SendTCPData: %v", err)
	}

	time.Sleep(2 * time.Second)

	observedBeforeClose := len(ctr.sizes())
	_ = cs.Close()
	<-done

	t.Logf("frames emitted in 2s of application-idle: %d (expected several due to cover traffic)", observedBeforeClose)

	if observedBeforeClose <= 1 {
		t.Errorf("FAIL: SecureStream emits no cover traffic during application idle. An observer can fingerprint the connection by its silence: real HTTPS sessions to a CDN typically exchange keep-alive / TLS application_data every few hundred ms.")
	}
	if observedBeforeClose < 3 {
		t.Errorf("FAIL: cover traffic too sparse: only %d frames in 2s with 200ms cadence", observedBeforeClose)
	}
}// ---------------------------------------------------------------------
// FP6: FrameType byte is plaintext-leaking via predictable distribution
//
// The wire header has FrameType at a fixed offset and is part of AAD,
// not encrypted. We do not check ciphertext bytes (that would assume
// the outer transport is plaintext) -- this is just a structural
// observation about the wire spec, surfaced as a documented test so
// it cannot regress silently.
// ---------------------------------------------------------------------

func TestFingerprint_FrameTypeIsPlaintext(t *testing.T) {
	cs, ss, ctr := makePair(t)
	defer cs.Close()
	defer ss.Close()
	done := drainRecv(t, ss)

	_ = cs.SendTCPData([]byte("a"))
	_ = cs.SendTCPData([]byte("b"))
	_ = cs.Close()
	<-done
	wireBufs := ctr.snapshot()

	if len(wireBufs) < 2 {
		t.Fatalf("got %d frames", len(wireBufs))
	}

	// FrameType offset = 4 (FrameLen) + 8 (Counter) = 12.
	const frameTypeOff = 4 + 8
	for i, w := range wireBufs[:2] {
		if len(w) < frameTypeOff+1 {
			t.Fatalf("frame %d too short: %d", i, len(w))
		}
		ft := w[frameTypeOff]
		if ft != byte(FrameTCPData) {
			t.Errorf("frame %d: type byte %#x, expected %#x -- header is plaintext, exact match required", i, ft, byte(FrameTCPData))
		}
		t.Logf("frame %d wire[12] = %#x (FrameType, plaintext, readable by any observer)", i, ft)
	}

	t.Log("INFO: FrameType is in the AAD, not encrypted. If an outer transport is ever 'less secret' than TLS (e.g. a future plaintext transport for debugging, or a downgrade), this byte alone leaks the protocol type taxonomy of every frame.")
}

// ---------------------------------------------------------------------
// FP7: handshake-phase padding strength vs steady-state
//
// Vision/XTLS pads the first ~8 inner records aggressively because
// that's where the inner-TLS handshake fingerprint lives. EWP applies
// the same uniform[0..64) pad to frame #1 and frame #1000 alike.
// We measure: do early frames have larger pads than late frames?
// ---------------------------------------------------------------------

func TestFingerprint_PaddingNotPhaseAware(t *testing.T) {
	cs, ss, ctr := makePair(t)
	defer cs.Close()
	defer ss.Close()
	done := drainRecv(t, ss)


	const N = 200
	payload := make([]byte, 100)
	_, _ = rand.Read(payload)
	for i := 0; i < N; i++ {
		if err := cs.SendTCPData(payload); err != nil {
			t.Fatalf("SendTCPData: %v", err)
		}
	}
	_ = cs.Close()
	<-done
	

	wire := ctr.sizes()[:N]
	early := wire[:16]
	late := wire[N-16:]

	avg := func(xs []int) float64 {
		s := 0
		for _, x := range xs {
			s += x
		}
		return float64(s) / float64(len(xs))
	}
	ea, la := avg(early), avg(late)
	t.Logf("avg wire size: first 16 frames = %.1f B, last 16 frames = %.1f B (ratio %.3f)", ea, la, ea/la)

	if math.Abs(ea-la) < 32 {
		t.Errorf("FAIL: padding policy is phase-agnostic. Early frames (where inner-TLS handshake fingerprints live) get the same %v B vs %v B treatment as steady-state frames. Vision/XTLS pads handshake-phase records ~10x more aggressively.", ea, la)
	}
}

// ---------------------------------------------------------------------
// FP8: end-to-end fingerprint summary (informational)
//
// Aggregates the metrics into one log so reviewers see the picture
// at a glance.
// ---------------------------------------------------------------------

func TestFingerprint_Summary(t *testing.T) {
	cs, ss, ctr := makePair(t)
	defer cs.Close()
	defer ss.Close()
	done := drainRecv(t, ss)


	// Replay a synthetic "first 30s of a browser session":
	// TLS handshake -> HTTP request -> response (mix of small/large).
	profile := []int{
		517, 122, 3800, 1500, 80, // CH, SH, EE+Cert+CV+Fin, more cert, Fin
		40, 600, // app_data: GET request
		14000, 14000, 8000, 1500, 200, // response stream
		60, 60, 60, // some pings
		14000, 5000, 1500, // more data
	}
	var input []int
	for rep := 0; rep < 30; rep++ {
		input = append(input, profile...)
	}

	for _, n := range input {
		buf := make([]byte, n)
		_, _ = rand.Read(buf)
		if err := cs.SendTCPData(buf); err != nil {
			t.Fatalf("SendTCPData(%d): %v", n, err)
		}
	}
	_ = cs.Close()
	<-done
	

	wire := ctr.sizes()
	if len(wire) > len(input) {
		wire = wire[:len(input)]
	}
	if len(wire) < len(input) {
		input = input[:len(wire)]
	}
	x := make([]float64, len(input))
	y := make([]float64, len(input))
	for i := range input {
		x[i] = float64(input[i])
		y[i] = float64(wire[i])
	}
	rho := spearman(x, y)

	t.Log("==== EWP v2 length-fingerprint summary ====")
	t.Logf("frames           : %d", len(input))
	t.Logf("unique payload Ls: %d", unique(input))
	t.Logf("unique wire    Ls: %d", unique(wire))
	t.Logf("Spearman(in,out) : %.4f", rho)
	t.Logf("payload H        : %.2f bits", shannonEntropy(input))
	t.Logf("wire    H        : %.2f bits", shannonEntropy(wire))
	t.Logf("H_diff           : %+.2f bits  (positive = padding ADDED entropy; negative = padding COLLAPSED structure)", shannonEntropy(wire)-shannonEntropy(input))

	// Total bandwidth overhead.
	var in, out int
	for i := range input {
		in += input[i]
		out += wire[i]
	}
	overhead := float64(out-in) / float64(in) * 100
	t.Logf("wire bandwidth   : %d B in, %d B out, overhead = %.2f%%", in, out, overhead)

	fmt.Println("[Summary captured in test log; run with -v to see numbers]")
}
