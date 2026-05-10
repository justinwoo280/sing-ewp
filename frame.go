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
	// key is the raw symmetric material used to construct aead. It is
	// retained so Rekey can derive a successor key without requiring
	// the caller to re-supply it. Storing the key here is no worse
	// than the cipher.AEAD itself (which retains the expanded round
	// keys); both are wiped when the SecureStream is closed.
	key [AEADKeyLen]byte
}

// NewFrameAEAD constructs a per-direction AEAD context.
func NewFrameAEAD(key [AEADKeyLen]byte, prefix [NoncePrefixLen]byte) (*FrameAEAD, error) {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("ewp/v2: chacha20poly1305.New: %w", err)
	}
	return &FrameAEAD{aead: a, prefix: prefix, key: key}, nil
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
	if !t.Valid() {
		return ErrFrameType
	}
	if len(meta) > MaxMetaLen {
		return ErrMetaTooLarge
	}
	if padLen < 0 {
		padLen = 0
	}
	if padLen > MaxFramePad {
		return ErrPadTooLarge
	}

	cipherLen := len(meta) + len(payload) + chacha20poly1305.Overhead

	// FrameLen counts everything after the FrameLen field itself.
	// = Counter + FrameType + MetaLen + PadLen + cipher + pad.
	frameLen := frameHdrCounter + frameHdrType + frameHdrMetaLen + frameHdrPadLen +
		cipherLen + padLen
	if frameLen > MaxFrameSize {
		return ErrFrameTooLarge
	}

	counter := f.counter
	nonce := f.composeNonce(counter)

	// Build header in one allocation; the entire header is AAD.
	hdr := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(frameLen))
	binary.BigEndian.PutUint64(hdr[4:12], counter)
	hdr[12] = byte(t)
	binary.BigEndian.PutUint16(hdr[13:15], uint16(len(meta)))
	binary.BigEndian.PutUint16(hdr[15:17], uint16(padLen))

	// Plaintext = meta || payload, sealed with AAD = header.
	plain := make([]byte, 0, len(meta)+len(payload))
	plain = append(plain, meta...)
	plain = append(plain, payload...)
	cipherBuf := f.aead.Seal(nil, nonce[:], plain, hdr)

	pad := make([]byte, padLen)
	if padLen > 0 {
		if _, err := io.ReadFull(crand.Reader, pad); err != nil {
			return fmt.Errorf("ewp/v2: pad rand: %w", err)
		}
	}

	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(cipherBuf); err != nil {
		return err
	}
	if padLen > 0 {
		if _, err := w.Write(pad); err != nil {
			return err
		}
	}

	f.counter = counter + 1
	return nil
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
