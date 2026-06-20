package ewp

import (
	mrand "math/rand/v2"
)

// Padding policy for SecureStream-level frames (v0.2.x).
//
// Goal: make the on-wire frame size weakly correlated with the
// underlying plaintext length, so an observer cannot trivially
// recover the inner-TLS record-size silhouette (the TLS-in-TLS
// length fingerprint).
//
// Strategy: every wire frame is padded so its total size lands in a
// fixed bucket drawn from a ladder that mimics realistic HTTPS /
// TLS-over-TCP record-size distribution. Within each bucket we add
// a small uniform jitter (via SuggestPadLen) so the wire size is
// not a deterministic function of the bucket choice either.
//
// Two regimes:
//
//   - HANDSHAKE phase (the first handshakePhaseFrames frames of the
//     SecureStream): aggressive bucketing. Even tiny payloads are
//     padded up to at least handshakeMinBucket bytes so the inner
//     TLS-handshake record-size sequence is destroyed.
//   - STEADY phase: the standard bucket ladder. Small payloads still
//     get padded but only up to the next realistic bucket, so the
//     bandwidth overhead in long-lived streams stays modest.
//
// The ladder is anchored to TLS record sizes (TLS 1.2/1.3 caps a
// single record's plaintext at 2^14 = 16384 B per RFC 5246 §6.2.2.1
// and RFC 8446 §5.1). Real HTTPS endpoints rarely emit a single
// record above this, so the top bucket is 16384 — anything larger
// from the application layer is naturally split across frames, which
// is exactly what TLS-over-TCP does in practice.
var (
	steadyBuckets = []int{
		256,
		512,
		1024,
		1500,
		2048,
		4096,
		8192,
		12288,
		16384,
	}

	// handshakeFloorProfile gives a per-position minimum target size
	// (in wire bytes) for the opening frames of a SecureStream. It is
	// shaped like a real TLS-1.3 handshake record silhouette as seen
	// on the wire:
	//
	//   pos 0      small ClientHello-ish record   (~512)
	//   pos 1      ServerHello / EncryptedExt      (~1500)
	//   pos 2..4   Certificate flight (the big one) (~8-12 KiB)
	//   pos 5..6   CertVerify / Finished pair      (~1500)
	//   pos 7+     settling toward steady traffic   (~1024)
	//
	// Padding only ever raises a frame to its floor (never shrinks a
	// genuinely larger frame), and the per-position floor is then run
	// through the steady ladder + jitter so the result is still a
	// bucketised, non-monotonic wire size. The point is that the
	// OPENING SEQUENCE of frame sizes resembles a TLS handshake
	// instead of the old "16 uniformly medium frames" shape that no
	// real endpoint emits.
	handshakeFloorProfile = []int{
		512,   // 0: ClientHello
		1500,  // 1: ServerHello + EncryptedExtensions
		8192,  // 2: Certificate (start of cert flight)
		12288, // 3: Certificate (continued)
		8192,  // 4: Certificate (tail)
		1500,  // 5: CertificateVerify
		1500,  // 6: Finished
		1024,  // 7
		1024,  // 8
	}
)

const (
	// handshakePhaseFrames is the number of frames per direction that
	// are padded with the handshake-phase ladder. After this many
	// frames the SecureStream transitions to the steady ladder.
	//
	// Inner TLS-1.3 needs at most ~6 records to complete its full
	// handshake (CH, SH, EE, Cert, CV, Fin pair); a budget of 16
	// covers handshake + a handful of early-data records with margin.
	handshakePhaseFrames = 16

	// bucketUpProbBP is the probability (in basis points, out of 10000)
	// that a frame is padded to the NEXT bucket rather than the
	// smallest fitting one. This is what actually destroys the rank
	// correlation between payload size and wire size: without it,
	// payload → bucket is monotonic and an observer can recover
	// payload size up to bucket resolution. With ~45% bucket-up the
	// mapping is no longer monotonic and Spearman collapses.
	bucketUpProbBP = 4500

	// jitterWithinBucket is the maximum extra random bytes added on
	// top of the bucket target. Keeps wire size off the exact bucket
	// boundary so the wire-size histogram is not a discrete set of
	// spikes.
	jitterWithinBucket = 64
)

// padToBucket returns a pad length such that
//
//	rawWireLen + pad  ∈  bucket + [0, jitterWithinBucket)
//
// where bucket is the smallest entry in the ladder that is
// >= rawWireLen. If no bucket fits (rawWireLen exceeds the largest
// bucket), pad is clamped so that the wire length stays under
// MaxFrameSize / MaxFramePad limits.
//
// rawWireLen here means the wire size BEFORE pad bytes are added,
// i.e. frameHeaderSize + len(meta) + cipherLen.
func padToBucket(rawWireLen int, ladder []int) int {
	const maxWire = MaxFrameSize - 4 // FrameLen field itself is outside frameLen.

	// Find smallest bucket >= rawWireLen whose distance is reachable
	// within one frame's MaxFramePad budget. (Without this guard, a
	// raw size that falls into a ladder gap wider than MaxFramePad
	// gets pad-clamped and lands between buckets, leaking its real
	// size as a distinct wire-size value.)
	idx := -1
	for i, b := range ladder {
		if b >= rawWireLen && b-rawWireLen <= MaxFramePad {
			idx = i
			break
		}
	}

	var target int
	switch {
	case idx == -1:
		// Larger than top bucket: pad to nearest 1024-multiple ceiling
		// up to maxWire. (This branch is rare; SecureStream callers
		// pre-chunk large writes to <= top bucket where reasonable.)
		t := ((rawWireLen + 1023) / 1024) * 1024
		if t > maxWire {
			return 0
		}
		target = t
	case idx+1 < len(ladder) &&
		ladder[idx+1]-rawWireLen <= MaxFramePad &&
		secureRandIntn(10000) < bucketUpProbBP:
		// Bucket-up: pick the NEXT bucket. This breaks the monotonic
		// payload → wire mapping that makes rank correlation high.
		// Skip when the jump would exceed MaxFramePad, otherwise the
		// clamp would leave wire size orphaned between two buckets.
		target = ladder[idx+1]
	default:
		target = ladder[idx]
	}

	// Add jitter inside the bucket so the wire size is not a discrete
	// spike at the bucket edge. Skip when adding jitter would push us
	// past MaxFramePad.
	if target-rawWireLen+jitterWithinBucket <= MaxFramePad {
		target += secureRandIntn(jitterWithinBucket)
	}

	pad := target - rawWireLen
	if pad < 0 {
		pad = 0
	}
	if pad > MaxFramePad {
		pad = MaxFramePad
	}
	if rawWireLen+pad > maxWire {
		pad = maxWire - rawWireLen
		if pad < 0 {
			pad = 0
		}
	}
	return pad
}

// suggestStreamPad picks a pad length for a frame about to be sent on
// a SecureStream.
//
// phaseFrameIndex is the zero-based send-side frame index since the
// SecureStream started. Frames < handshakePhaseFrames use the more
// aggressive handshake ladder.
//
// rawWireLen is the frame size BEFORE pad bytes are added:
//
//	frameHeaderSize + len(meta) + len(payload) + chacha20poly1305.Overhead
func suggestStreamPad(rawWireLen, phaseFrameIndex int) int {
	if phaseFrameIndex < handshakePhaseFrames {
		return suggestHandshakePad(rawWireLen, phaseFrameIndex)
	}
	return padToBucket(rawWireLen, steadyBuckets)
}

// suggestHandshakePad shapes an opening-phase frame toward a per-
// position floor drawn from a TLS-1.3 record silhouette, then runs the
// result through the steady ladder + jitter. The total pad is clamped
// to MaxFramePad: a single EWP frame can lift a small payload by at
// most MaxFramePad bytes, so a floor above (rawWireLen + MaxFramePad)
// is approached as closely as one frame allows. The big Certificate-
// flight positions therefore reach their full silhouette only when the
// inner record is itself large (the common case for a real cert
// flight); a tiny inner record is lifted as far as one frame permits
// and the rest of the silhouette is carried by the following frames.
func suggestHandshakePad(rawWireLen, phaseFrameIndex int) int {
	floor := handshakeFloor(phaseFrameIndex)

	raw := rawWireLen
	if floor > raw {
		raw = floor
		// Cap the floor lift so the frame stays paddable in one shot.
		if raw-rawWireLen > MaxFramePad {
			raw = rawWireLen + MaxFramePad
		}
	}

	// Bucketise the (possibly lifted) size on the steady ladder, then
	// express the answer as pad relative to the ORIGINAL rawWireLen and
	// clamp to MaxFramePad so EncodeFrame never rejects it.
	pad := padToBucket(raw, steadyBuckets) + (raw - rawWireLen)
	if pad > MaxFramePad {
		pad = MaxFramePad
	}
	if pad < 0 {
		pad = 0
	}
	return pad
}

// handshakeFloor returns the per-position minimum wire size for the
// opening frames. Positions past the end of the explicit profile use
// the last entry (a modest 1 KiB floor) so the tail of the handshake
// window settles smoothly into steady traffic.
func handshakeFloor(pos int) int {
	if pos < 0 {
		return 0
	}
	if pos >= len(handshakeFloorProfile) {
		return handshakeFloorProfile[len(handshakeFloorProfile)-1]
	}
	return handshakeFloorProfile[pos]
}

// secureRandIntn returns a value in [0, n).
//
// We use math/rand/v2's global generator, which is seeded once from
// the operating system entropy and backed by ChaCha8 (cryptographic
// strength). It is goroutine-safe, lock-free, and allocation-free —
// the right tradeoff for a per-frame jitter / bucket-up coin flip
// that runs on the data-plane hot path. The previous crypto/rand
// path cost ~43 ns and 1 allocation per call; this is ~3 ns and 0
// allocations, and is called up to twice per frame.
//
// SECURITY NOTE: the output of this function is NEVER a key, nonce,
// or anything an adversary can directly observe in cleartext. It
// only chooses (a) whether to bucket-up, and (b) how many random pad
// bytes to insert. The pad bytes themselves are still drawn from
// crypto/rand inside EncodeFrame.
func secureRandIntn(n int) int {
	if n <= 1 {
		return 0
	}
	return int(mrand.Uint32N(uint32(n)))
}
