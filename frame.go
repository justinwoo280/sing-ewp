package ewp

import (
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// FrameType is the 1-byte frame discriminator from the v2 spec.
type FrameType byte

const (
	FrameTCPData      FrameType = 0x01
	FrameUDPData      FrameType = 0x02
	FrameUDPNew       FrameType = 0x03
	FrameUDPEnd       FrameType = 0x04
	FrameUDPProbeReq  FrameType = 0x05
	FrameUDPProbeResp FrameType = 0x06
	FramePing         FrameType = 0x10
	FramePong         FrameType = 0x11
	FrameRekeyReq     FrameType = 0x12
	FrameRekeyResp    FrameType = 0x13
	FramePaddingOnly  FrameType = 0x20
)

func (t FrameType) Valid() bool {
	switch t {
	case FrameTCPData, FrameUDPData, FrameUDPNew, FrameUDPEnd,
		FrameUDPProbeReq, FrameUDPProbeResp,
		FramePing, FramePong,
		FrameRekeyReq, FrameRekeyResp,
		FramePaddingOnly:
		return true
	}
	return false
}

// Wire layout offsets, for clarity.
//
// Header (everything before the AEAD body):
//
//	FrameLen(4) || Counter(8) || FrameType(1) || MetaLen(2) || PadLen(2)
//
// PadLen is part of the header (and of the AAD) so that the AEAD body
// length is unambiguous from the receiver's point of view: cipher bytes
// = FrameLen - (Counter + FrameType + MetaLen + PadLen + Pad).
const (
	frameHdrFrameLen = 4 // big-endian uint32
	frameHdrCounter  = 8 // big-endian uint64
	frameHdrType     = 1
	frameHdrMetaLen  = 2 // big-endian uint16
	frameHdrPadLen   = 2 // big-endian uint16
	frameHeaderSize  = frameHdrFrameLen + frameHdrCounter + frameHdrType + frameHdrMetaLen + frameHdrPadLen

	// aeadTagLen is exposed so callers (SecureStream, padding policy,
	// transports) can size buffers without importing chacha20poly1305.
	aeadTagLen = chacha20poly1305.Overhead
)

// Errors surfaced by frame encode/decode.
var (
	ErrFrameTooLarge   = errors.New("ewp/v2: frame exceeds MaxFrameSize")
	ErrFrameTooShort   = errors.New("ewp/v2: frame body shorter than declared length")
	ErrFrameType       = errors.New("ewp/v2: unknown frame type")
	ErrMetaTooLarge    = errors.New("ewp/v2: meta exceeds MaxMetaLen")
	ErrPadTooLarge     = errors.New("ewp/v2: pad exceeds MaxFramePad")
	ErrAEADOpen        = errors.New("ewp/v2: AEAD open failed")
	ErrCounterMismatch = errors.New("ewp/v2: counter mismatch (replay or reorder)")
)

// FrameAEAD wraps a directional ChaCha20-Poly1305 cipher together with
// its 4-byte nonce prefix and the running counter for that direction.
//
// FrameAEAD is NOT goroutine-safe. SecureStream serialises access from
// the appropriate side.
type FrameAEAD struct {
	aead    cipher.AEAD
	prefix  [NoncePrefixLen]byte
	counter uint64
}

// NewFrameAEAD constructs a per-direction AEAD context.
func NewFrameAEAD(key [AEADKeyLen]byte, prefix [NoncePrefixLen]byte) (*FrameAEAD, error) {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("ewp/v2: chacha20poly1305.New: %w", err)
	}
	return &FrameAEAD{aead: a, prefix: prefix}, nil
}

// Counter returns the current counter (next-to-use for sender,
// next-expected for receiver).
func (f *FrameAEAD) Counter() uint64 { return f.counter }

// composeNonce builds the 12-byte AEAD nonce = prefix(4) || counter(8).
func (f *FrameAEAD) composeNonce(counter uint64) [AEADNonceLen]byte {
	var n [AEADNonceLen]byte
	copy(n[:NoncePrefixLen], f.prefix[:])
	binary.BigEndian.PutUint64(n[NoncePrefixLen:], counter)
	return n
}

// EncodeFrame writes one frame to w.
//
// The encoded layout matches §3 of doc/EWP_V2.md:
//
//	FrameLen(4) || Counter(8) || FrameType(1) || MetaLen(2)
//	  || AEAD(meta||payload)  || PadLen(2) || Pad(PadLen)
//
// padLen is clamped to [0, MaxFramePad]. Callers SHOULD pass a
// pseudo-random padLen drawn from a sane distribution; this function
// fills the pad bytes with crypto/rand.
//
// EncodeFrame increments the AEAD counter on success.
func EncodeFrame(w io.Writer, f *FrameAEAD, t FrameType, meta, payload []byte, padLen int) error {
	wire, err := EncodeFrameAppend(nil, f, t, meta, payload, padLen)
	if err != nil {
		return err
	}
	_, err = w.Write(wire)
	return err
}

// EncodeFrameAppend appends one encoded frame to dst and returns the
// extended slice. If dst has enough capacity the whole frame is built
// without any allocation:
//
//   - The 17-byte plaintext header is written in place.
//   - The AEAD seal runs in-place (dst=plaintext[:0]) so the ciphertext
//     reuses the plaintext storage; no separate ciphertext buffer.
//   - The padding bytes are drawn from crypto/rand directly into the
//     dst buffer.
//
// Callers that want zero-alloc steady-state I/O should pre-grow dst to
// (frameHeaderSize + len(meta) + len(payload) + chacha20poly1305.Overhead
// + padLen) before calling.
//
// On success the AEAD counter advances by 1.
func EncodeFrameAppend(dst []byte, f *FrameAEAD, t FrameType, meta, payload []byte, padLen int) ([]byte, error) {
	if !t.Valid() {
		return dst, ErrFrameType
	}
	if len(meta) > MaxMetaLen {
		return dst, ErrMetaTooLarge
	}
	if padLen < 0 {
		padLen = 0
	}
	if padLen > MaxFramePad {
		return dst, ErrPadTooLarge
	}

	plainLen := len(meta) + len(payload)
	cipherLen := plainLen + chacha20poly1305.Overhead

	frameLen := frameHdrCounter + frameHdrType + frameHdrMetaLen + frameHdrPadLen +
		cipherLen + padLen
	if frameLen > MaxFrameSize {
		return dst, ErrFrameTooLarge
	}

	totalWire := frameHeaderSize + cipherLen + padLen
	base := len(dst)

	// Grow dst in one shot if needed. If the caller pre-sized dst,
	// this is a no-op append.
	if cap(dst)-base < totalWire {
		grown := make([]byte, base+totalWire)
		copy(grown, dst)
		dst = grown
	} else {
		dst = dst[:base+totalWire]
	}
	wire := dst[base:]

	counter := f.counter

	// Header (also serves as AAD).
	binary.BigEndian.PutUint32(wire[0:4], uint32(frameLen))
	binary.BigEndian.PutUint64(wire[4:12], counter)
	wire[12] = byte(t)
	binary.BigEndian.PutUint16(wire[13:15], uint16(len(meta)))
	binary.BigEndian.PutUint16(wire[15:17], uint16(padLen))
	hdr := wire[:frameHeaderSize]

	// Lay plaintext (meta || payload) into the wire region where the
	// ciphertext will end up.
	plainStart := frameHeaderSize
	if plainLen > 0 {
		copy(wire[plainStart:], meta)
		copy(wire[plainStart+len(meta):], payload)
	}

	// In-place AEAD seal. The crypto/cipher.AEAD contract allows
	// dst=plaintext[:0] (reuse plaintext storage). After Seal,
	// wire[plainStart : plainStart+cipherLen] holds cipher||tag.
	nonce := f.composeNonce(counter)
	plainSlice := wire[plainStart : plainStart+plainLen]
	_ = f.aead.Seal(plainSlice[:0], nonce[:], plainSlice, hdr)

	// Random pad bytes go directly into the wire buffer; no temporary.
	if padLen > 0 {
		if _, err := io.ReadFull(crand.Reader, wire[plainStart+cipherLen:]); err != nil {
			// Roll back dst since we promised "on error counter does not
			// advance and frame is not emitted".
			return dst[:base], fmt.Errorf("ewp/v2: pad rand: %w", err)
		}
	}

	f.counter = counter + 1
	return dst, nil
}

// DecodedFrame is the result of DecodeFrame. The Meta and Payload
// slices are freshly allocated and may be retained by the caller.
type DecodedFrame struct {
	Counter uint64
	Type    FrameType
	Meta    []byte
	Payload []byte
}

// DecodeFrame reads one frame from r and decrypts it.
//
// On success the AEAD counter advances by 1.
//
// Errors:
//   - ErrCounterMismatch: the wire counter is not equal to the next
//     expected counter on f. The connection MUST be torn down.
//   - ErrAEADOpen: AEAD authentication failed. Same.
//   - any io error from r.
//
// The function reads exactly one frame and never partially consumes the
// next; on any error after the FrameLen has been consumed it still
// drains the rest of the frame to keep the byte stream synchronized in
// principle, but callers MUST treat any error as fatal for the
// SecureStream and stop reading.
func DecodeFrame(r io.Reader, f *FrameAEAD) (*DecodedFrame, error) {
	var hdr [frameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint32(hdr[0:4])
	if frameLen > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	counter := binary.BigEndian.Uint64(hdr[4:12])
	t := FrameType(hdr[12])
	metaLen := binary.BigEndian.Uint16(hdr[13:15])
	padLen := binary.BigEndian.Uint16(hdr[15:17])
	if metaLen > MaxMetaLen {
		return nil, ErrMetaTooLarge
	}
	if padLen > MaxFramePad {
		return nil, ErrPadTooLarge
	}

	// Bytes remaining to read = frameLen - (Counter+Type+MetaLen+PadLen).
	bodyLen := int(frameLen) - (frameHdrCounter + frameHdrType + frameHdrMetaLen + frameHdrPadLen)
	if bodyLen < int(padLen)+chacha20poly1305.Overhead+int(metaLen) {
		return nil, ErrFrameTooShort
	}
	cipherLen := bodyLen - int(padLen)

	cipherBuf := make([]byte, cipherLen)
	if _, err := io.ReadFull(r, cipherBuf); err != nil {
		return nil, err
	}
	// Drain the pad region to keep the byte stream synchronized; the
	// content is not used.
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return nil, err
		}
	}

	// Counter discipline: receiver MUST see the next-expected counter
	// exactly. No reordering tolerance.
	if counter != f.counter {
		return nil, ErrCounterMismatch
	}
	if !t.Valid() {
		return nil, ErrFrameType
	}

	nonce := f.composeNonce(counter)
	plain, err := f.aead.Open(nil, nonce[:], cipherBuf, hdr[:])
	if err != nil {
		return nil, ErrAEADOpen
	}
	if len(plain) < int(metaLen) {
		return nil, ErrFrameTooShort
	}

	meta := append([]byte(nil), plain[:metaLen]...)
	payload := append([]byte(nil), plain[metaLen:]...)

	f.counter = counter + 1
	return &DecodedFrame{
		Counter: counter,
		Type:    t,
		Meta:    meta,
		Payload: payload,
	}, nil
}

// SuggestPadLen returns a pseudo-random pad length in
// [minPad, maxPad]. Both bounds are clamped to the spec maximum.
//
// This helper exists so callers don't reinvent it differently in five
// places. It uses crypto/rand because the cost is dominated by the
// AEAD; we don't need a math/rand fast path here.
func SuggestPadLen(minPad, maxPad int) int {
	if minPad < 0 {
		minPad = 0
	}
	if maxPad > MaxFramePad {
		maxPad = MaxFramePad
	}
	if minPad >= maxPad {
		return minPad
	}
	span := maxPad - minPad + 1
	var b [4]byte
	if _, err := io.ReadFull(crand.Reader, b[:]); err != nil {
		return minPad
	}
	r := int(binary.BigEndian.Uint32(b[:])) & 0x7fffffff
	return minPad + (r % span)
}

// NewGlobalID returns a fresh 8-byte UDP sub-session identifier from
// crypto/rand.
//
// Replaces the v1 NewGlobalID in protocol/ewp/udp.go (deleted).
func NewGlobalID() [8]byte {
	var id [8]byte
	if _, err := io.ReadFull(crand.Reader, id[:]); err != nil {
		panic("ewp/v2: crypto/rand failed for GlobalID: " + err.Error())
	}
	return id
}
