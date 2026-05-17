package ewp

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
)

// Padding policy for SecureStream-level frames.
//
// Goal: make the on-wire frame size weakly correlated with the
// underlying plaintext length, so an observer cannot trivially
// recover the inner-TLS record-size silhouette (the TLS-in-TLS
// length fingerprint).
//
// Strategy: every wire frame is padded so its total size lands in
// a fixed bucket. Buckets are chosen to cover the realistic record
// distribution of HTTPS / QUIC / SSH-like traffic. Within each
// bucket we add a small uniform jitter so the wire size is not a
// deterministic function of the bucket choice either.
//
// We have two regimes:
//
//   - HANDSHAKE phase (the first handshakePhaseFrames frames of the
//     SecureStream): aggressive bucketing. Even tiny payloads are
//     padded up to at least handshakeMinBucket bytes so the inner
//     TLS-handshake record-size sequence is destroyed.
//   - STEADY phase: the standard bucket ladder. Small payloads still
//     get padded but only up to the next realistic bucket, so the
//     bandwidth overhead in long-lived streams stays modest.
//
// The bucket ladder is anchored to common MTU / TLS-record sizes so
// EWP traffic does not introduce its own oddball histogram.
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

	// Note on the top bucket:
	//
	// TLS 1.2/1.3 caps a single record's plaintext at 2^14 = 16384 B
	// (RFC 5246 §6.2.2.1, RFC 8446 §5.1). With TLS framing + AEAD
	// overhead a real on-wire record tops out around ~16.4 KiB; a
	// single HTTPS record at 24K/32K/49K does not occur in the wild.
	//
	// Earlier revisions of this ladder reached 49152 to absorb large
	// bursts in one frame, but on any path with MTU=1500 (MSS≈1460)
	// such a frame visibly fragments into ~34 segments — a burst
	// shape that no real HTTPS endpoint produces. Capping the ladder
	// at 16384 keeps EWP's wire-size histogram inside the realistic
	// HTTPS envelope; larger inner payloads simply span multiple
	// frames, which is exactly what TLS-over-TCP does in practice.

	handshakeBuckets = []int{
		1500,
		4096,
		8192,
		16384,
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
	// payload size up to bucket resolution. With ~50% bucket-up the
	// mapping is no longer monotonic and Spearman collapses.
	//
	// 4500 bp = 45% of frames are bumped one bucket higher.
	bucketUpProbBP = 4500
)

// padToBucket returns a pad length such that
//
//	rawWireLen + pad  ∈  bucket + [0, jitterMax)
//
// where bucket is the smallest entry in the ladder that is >= rawWireLen.
// If no bucket fits (rawWireLen exceeds the largest bucket), pad is
// clamped so that the wire length stays under MaxFrameSize.
//
// rawWireLen here means the wire size BEFORE pad bytes are added,
// i.e. header + ciphertext (= header + len(meta)+len(payload)+AEAD).
func padToBucket(rawWireLen int, ladder []int) int {
	// Budget inside one frame.
	const maxWire = MaxFrameSize - 4 // FrameLen field itself is outside frameLen.

	// Find smallest bucket >= rawWireLen.
	idx := -1
	for i, b := range ladder {
		if b >= rawWireLen {
			idx = i
			break
		}
	}

	var target int
	switch {
	case idx == -1:
		// Larger than top bucket: pad to nearest 1024-multiple ceiling
		// up to maxWire.
		t := ((rawWireLen + 1023) / 1024) * 1024
		if t > maxWire {
			return 0
		}
		target = t
	case idx+1 < len(ladder) && secureRandIntn(10000) < bucketUpProbBP:
		// Bucket-up: pick the NEXT bucket. This breaks the monotonic
		// payload → wire mapping that makes rank correlation high.
		target = ladder[idx+1]
	default:
		target = ladder[idx]
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
// a SecureStream. phaseFrameIndex is the zero-based frame index since
// the SecureStream started (across all frame types, both directions
// counted separately by SecureStream itself).
//
// rawWireLen = frameHeaderSize + len(meta) + len(payload) + chacha20poly1305.Overhead
func suggestStreamPad(rawWireLen, phaseFrameIndex int) int {
	ladder := steadyBuckets
	if phaseFrameIndex < handshakePhaseFrames {
		ladder = handshakeBuckets
	}
	return padToBucket(rawWireLen, ladder)
}

// secureRandIntn returns a value in [0, n) drawn from crypto/rand.
// Uses the same one-shot 32-bit rejection-free pattern as
// SuggestPadLen (good enough for jitter, not for keys).
func secureRandIntn(n int) int {
	if n <= 1 {
		return 0
	}
	var b [4]byte
	if _, err := io.ReadFull(crand.Reader, b[:]); err != nil {
		return 0
	}
	r := int(binary.BigEndian.Uint32(b[:])) & 0x7fffffff
	return r % n
}
