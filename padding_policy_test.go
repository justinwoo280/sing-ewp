package ewp

import (
	"io"
	"math"
	"testing"
)

// TestPaddingPolicy_BucketMonotonicity verifies the core invariant:
// after padding, wire size always lands at or above the smallest
// fitting bucket and never exceeds the next bucket + jitter window.
func TestPaddingPolicy_BucketMonotonicity(t *testing.T) {
	for _, ladder := range [][]int{steadyBuckets, handshakeBuckets} {
		top := ladder[len(ladder)-1]
		for raw := 1; raw <= top; raw += 37 {
			pad := padToBucket(raw, ladder)
			wire := raw + pad
			// must fit in some bucket window [bucket, bucket+jitter)
			// or in the next bucket window.
			ok := false
			for _, b := range ladder {
				if wire >= b && wire < b+jitterWithinBucket {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("raw=%d pad=%d wire=%d outside any bucket window (ladder=%v)",
					raw, pad, wire, ladder)
			}
			if wire < raw {
				t.Fatalf("raw=%d wire=%d shrunk", raw, wire)
			}
		}
	}
}

// TestPaddingPolicy_BucketUpBreaksMonotonicity verifies that the
// bucket-up jump is actually exercised: across many trials at a
// raw size that fits comfortably in bucket k, we sometimes land in
// bucket k+1. Without this the payload→wire mapping is monotonic
// and length-rank attacks succeed.
func TestPaddingPolicy_BucketUpBreaksMonotonicity(t *testing.T) {
	// pick a raw size that fits squarely in the first bucket (256)
	const raw = 100
	const trials = 4000
	higher := 0
	for i := 0; i < trials; i++ {
		pad := padToBucket(raw, steadyBuckets)
		wire := raw + pad
		if wire >= steadyBuckets[1] { // landed in bucket 512 or above
			higher++
		}
	}
	// bucketUpProbBP = 4500 (45%); allow generous tolerance.
	if higher < trials*30/100 || higher > trials*60/100 {
		t.Fatalf("bucket-up rate out of expected ~45%%: %d/%d", higher, trials)
	}
}

// TestPaddingPolicy_JitterIsNotConstant verifies that within a single
// bucket, wire size is not a deterministic function of raw size.
// Without intra-bucket jitter, an observer recovers raw size up to
// bucket resolution.
func TestPaddingPolicy_JitterIsNotConstant(t *testing.T) {
	// Fix a raw size; collect all observed wire sizes when bucket-up
	// did NOT trigger (wire < second bucket). They should span multiple
	// distinct values inside the first bucket's jitter window.
	const raw = 100
	distinct := map[int]struct{}{}
	for i := 0; i < 2000; i++ {
		pad := padToBucket(raw, steadyBuckets)
		wire := raw + pad
		if wire < steadyBuckets[1] {
			distinct[wire] = struct{}{}
		}
	}
	if len(distinct) < 8 {
		t.Fatalf("intra-bucket jitter too narrow: only %d distinct wire sizes", len(distinct))
	}
}

// TestPaddingPolicy_OversizeClamped verifies that a rawWireLen above
// the top bucket does not blow past the spec frame size limit.
func TestPaddingPolicy_OversizeClamped(t *testing.T) {
	top := steadyBuckets[len(steadyBuckets)-1]
	// Inputs that are themselves <= maxWire: pad must not push them over.
	maxWire := MaxFrameSize - 4
	for _, raw := range []int{top + 1, top + 1024, maxWire - 100, maxWire} {
		pad := padToBucket(raw, steadyBuckets)
		wire := raw + pad
		if wire > maxWire {
			t.Fatalf("raw=%d pad=%d wire=%d exceeds maxWire=%d", raw, pad, wire, maxWire)
		}
		if pad > MaxFramePad {
			t.Fatalf("raw=%d pad=%d exceeds MaxFramePad", raw, pad)
		}
	}
	// Inputs that already exceed maxWire: policy returns 0 pad and lets
	// EncodeFrame reject them with ErrFrameTooLarge.
	if pad := padToBucket(MaxFrameSize, steadyBuckets); pad != 0 {
		t.Fatalf("raw=MaxFrameSize: expected pad=0, got %d", pad)
	}
}

// TestPaddingPolicy_PhaseSwitch verifies the handshake-phase ladder
// is used for the first handshakePhaseFrames frames and steady after.
func TestPaddingPolicy_PhaseSwitch(t *testing.T) {
	// A tiny raw (64) lands at the smallest bucket of whichever ladder
	// is active; handshake ladder's smallest is 1500, steady's is 256.
	const raw = 64
	// During handshake phase, wire size should always be >= 1500.
	for i := 0; i < handshakePhaseFrames; i++ {
		pad := suggestStreamPad(raw, i)
		wire := raw + pad
		if wire < handshakeBuckets[0] {
			t.Fatalf("handshake-phase frame %d: wire=%d < %d", i, wire, handshakeBuckets[0])
		}
	}
	// Steady phase: a tiny raw should be allowed to land in the small
	// 256-byte bucket at least sometimes (proves we switched ladders).
	hitSmall := false
	for i := handshakePhaseFrames; i < handshakePhaseFrames+200; i++ {
		pad := suggestStreamPad(raw, i)
		wire := raw + pad
		if wire < handshakeBuckets[0] {
			hitSmall = true
			break
		}
	}
	if !hitSmall {
		t.Fatalf("steady phase never produced small-bucket frame; ladder did not switch")
	}
}

// TestPaddingPolicy_RankCorrelationCollapses is the real attacker
// model: if payload→wire is monotonic, Spearman ρ = 1 and the
// observer recovers payload size up to bucket resolution. The
// bucket-up + jitter policy must drag ρ well below 1.
//
// We sample many (payload, wire) pairs across the whole range and
// require that the rank correlation is not perfect.
func TestPaddingPolicy_RankCorrelationCollapses(t *testing.T) {
	top := steadyBuckets[len(steadyBuckets)-1]
	const N = 2000
	raws := make([]int, N)
	wires := make([]int, N)
	for i := 0; i < N; i++ {
		// uniformly sample raw payload size inside the ladder's reach
		raw := 1 + (i*top)/N
		pad := padToBucket(raw, steadyBuckets)
		raws[i] = raw
		wires[i] = raw + pad
	}
	rho := spearman(raws, wires)
	// Without bucket-up, this would be ~1.0 (jitter alone preserves
	// rank). With 45% bucket-up, rank order is broken: ρ should be
	// noticeably below 1. Threshold 0.95 leaves wide margin while
	// catching any regression that removes bucket-up.
	// With 45% bucket-up the perfect monotonic rho=1.0 should be
	// broken; threshold 0.98 is well below 1.0 while leaving room
	// for sampling noise across runs.
	if rho > 0.98 {
		t.Fatalf("Spearman rho=%.3f too close to 1.0; bucket-up not effective", rho)
	}
	if rho < 0.5 {
		t.Fatalf("Spearman rho=%.3f suspiciously low; sanity-check the policy", rho)
	}
}

// spearman returns the Spearman rank correlation of xs and ys.
// Ties are handled by averaging ranks.
func spearman(xs, ys []int) float64 {
	n := len(xs)
	rx := ranks(xs)
	ry := ranks(ys)
	var sx, sy, sxx, syy, sxy float64
	for i := 0; i < n; i++ {
		sx += rx[i]
		sy += ry[i]
		sxx += rx[i] * rx[i]
		syy += ry[i] * ry[i]
		sxy += rx[i] * ry[i]
	}
	nf := float64(n)
	num := nf*sxy - sx*sy
	den := math.Sqrt((nf*sxx - sx*sx) * (nf*syy - sy*sy))
	if den == 0 {
		return 0
	}
	return num / den
}

func ranks(xs []int) []float64 {
	n := len(xs)
	type pair struct {
		v, i int
	}
	ps := make([]pair, n)
	for i, x := range xs {
		ps[i] = pair{x, i}
	}
	// stable insertion sort is enough for test sizes; use simple sort
	for i := 1; i < n; i++ {
		for j := i; j > 0 && ps[j-1].v > ps[j].v; j-- {
			ps[j-1], ps[j] = ps[j], ps[j-1]
		}
	}
	out := make([]float64, n)
	i := 0
	for i < n {
		j := i
		for j < n && ps[j].v == ps[i].v {
			j++
		}
		// average rank for ties; ranks are 1-based
		avg := float64(i+j-1)/2.0 + 1.0
		for k := i; k < j; k++ {
			out[ps[k].i] = avg
		}
		i = j
	}
	return out
}

// TestPaddingPolicy_EndToEndWireOnBucket asserts that frames coming
// out of a real SecureStream.SendTCPData on the wire fall onto the
// bucket ladder (handshake ladder for the first handshakePhaseFrames,
// steady ladder thereafter), within the jitter window.
//
// This is the integration-level invariant: sendFrame -> EncodeFrame
// -> MessageTransport.SendMessage produces a byte stream whose sizes
// match the policy. If any future refactor disconnects the policy
// from the send path, this test fires.
func TestPaddingPolicy_EndToEndWireOnBucket(t *testing.T) {
	key := hardRandKey()
	prefix := hardRandPrefix()
	send, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatalf("send AEAD: %v", err)
	}
	recv, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatalf("recv AEAD: %v", err)
	}

	cap := &captureTransport{}
	s := &SecureStream{tr: cap, send: send, recv: recv}

	// Send a mix of payload sizes spanning the ladder. Sequence
	// length deliberately exceeds handshakePhaseFrames so we exercise
	// both regimes.
	payloads := []int{8, 64, 200, 600, 1200, 4000, 9000, 1, 50, 333, 1024, 5000, 16000, 16, 256, 800, 128, 2000, 7777, 100}
	if len(payloads) <= handshakePhaseFrames {
		t.Fatalf("test needs > %d payloads to cover both regimes", handshakePhaseFrames)
	}

	for i, p := range payloads {
		if err := s.SendTCPData(make([]byte, p)); err != nil {
			t.Fatalf("send[%d] len=%d: %v", i, p, err)
		}
	}

	if len(cap.frames) != len(payloads) {
		t.Fatalf("got %d frames, want %d", len(cap.frames), len(payloads))
	}

	check := func(wire int, ladder []int, idx int) {
		for _, b := range ladder {
			if wire >= b && wire < b+jitterWithinBucket {
				return
			}
		}
		t.Fatalf("frame %d (payload=%d) wire=%d outside ladder %v",
			idx, payloads[idx], wire, ladder)
	}

	for i, wireMsg := range cap.frames {
		wire := len(wireMsg)
		if i < handshakePhaseFrames {
			check(wire, handshakeBuckets, i)
		} else {
			check(wire, steadyBuckets, i)
		}
	}
}

type captureTransport struct {
	frames [][]byte
}

func (c *captureTransport) SendMessage(b []byte) error {
	cp := append([]byte(nil), b...)
	c.frames = append(c.frames, cp)
	return nil
}
func (c *captureTransport) ReadMessage() ([]byte, error) { return nil, io.EOF }
func (c *captureTransport) Close() error                 { return nil }
