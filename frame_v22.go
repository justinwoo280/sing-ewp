package ewp

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// EWP/v2.2 record layout:
//
//	RecordLen(4) || AEAD(
//	    Counter(8) || FrameType(1) || MetaLen(2) || PayloadLen(4) ||
//	    Meta || Payload || RandomPadding
//	)
//
// RecordLen is the ciphertext length, is authenticated as AAD, and is the
// only cleartext data-plane field. Senders bucketize the complete record size
// before encoding, so observers see only a coarse padded record length.
const (
	v22OuterLengthSize = 4
	v22InnerCounterLen = 8
	v22InnerTypeLen    = 1
	v22InnerMetaLen    = 2
	v22InnerPayloadLen = 4
	v22InnerHeaderSize = v22InnerCounterLen + v22InnerTypeLen + v22InnerMetaLen + v22InnerPayloadLen

	// MaxV22RecordSize bounds the complete transmitted record, including its
	// cleartext length prefix. This avoids the legacy ambiguity where
	// MaxFrameSize excluded its own prefix.
	MaxV22RecordSize = MaxFrameSize
)

// EncodeFrameV22 writes a single opaque v2.2 record. padLen is a minimum
// encrypted padding request; the encoder adds bucket padding so direct users
// cannot accidentally expose an exact payload length. SecureStream supplies a
// phase-aware final padding plan through its private encoder path.
func EncodeFrameV22(w io.Writer, f *FrameAEAD, t FrameType, meta, payload []byte, padLen int) error {
	return encodeFrameV22WithPad(w, f, t, meta, payload, selectV22DirectPad(meta, payload, padLen))
}

func selectV22DirectPad(meta, payload []byte, requested int) int {
	if requested < 0 {
		requested = 0
	}
	if requested > MaxFramePad {
		return requested
	}
	rawWireLen := v22OuterLengthSize + v22InnerHeaderSize + len(meta) + len(payload) + chacha20poly1305.Overhead
	// Direct codec users have no stream phase, so use the steady-state ladder.
	extra := suggestStreamPadV22(rawWireLen+requested, handshakePhaseFrames)
	if extra > MaxFramePad-requested {
		extra = MaxFramePad - requested
	}
	return requested + extra
}

func encodeFrameV22WithPad(w io.Writer, f *FrameAEAD, t FrameType, meta, payload []byte, padLen int) error {
	if f == nil || f.aead == nil {
		return io.ErrClosedPipe
	}
	if f.counter == ^uint64(0) {
		return ErrCounterExhausted
	}
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
	if len(payload) > MaxV22RecordSize {
		return ErrFrameTooLarge
	}

	plainLen := v22InnerHeaderSize + len(meta) + len(payload) + padLen
	recordLen := plainLen + chacha20poly1305.Overhead
	if recordLen+v22OuterLengthSize > MaxV22RecordSize {
		return ErrFrameTooLarge
	}

	counter := f.counter
	var outer [v22OuterLengthSize]byte
	binary.BigEndian.PutUint32(outer[:], uint32(recordLen))

	plain := f.scratchBuf(plainLen)
	binary.BigEndian.PutUint64(plain[0:v22InnerCounterLen], counter)
	plain[v22InnerCounterLen] = byte(t)
	binary.BigEndian.PutUint16(plain[v22InnerCounterLen+v22InnerTypeLen:v22InnerCounterLen+v22InnerTypeLen+v22InnerMetaLen], uint16(len(meta)))
	payloadLenOffset := v22InnerCounterLen + v22InnerTypeLen + v22InnerMetaLen
	binary.BigEndian.PutUint32(plain[payloadLenOffset:payloadLenOffset+v22InnerPayloadLen], uint32(len(payload)))
	dataOffset := v22InnerHeaderSize
	copy(plain[dataOffset:], meta)
	dataOffset += len(meta)
	copy(plain[dataOffset:], payload)
	dataOffset += len(payload)
	if padLen > 0 {
		if _, err := io.ReadFull(crand.Reader, plain[dataOffset:]); err != nil {
			return err
		}
	}

	nonce := f.composeNonce(counter)
	// When the sink is a *bytes.Buffer (the SecureStream send path),
	// seal directly into its spare capacity so the ciphertext never
	// touches a separate heap allocation. Generic writers fall back to
	// a sealed temporary slice.
	if buf, ok := w.(*bytes.Buffer); ok {
		buf.Grow(v22OuterLengthSize + recordLen)
		if _, err := buf.Write(outer[:]); err != nil {
			return err
		}
		avail := buf.Bytes()
		avail = avail[len(avail):cap(avail)]
		ciphertext := f.aead.Seal(avail[:0], nonce[:], plain, outer[:])
		if _, err := buf.Write(ciphertext); err != nil {
			return err
		}
		f.counter = counter + 1
		return nil
	}
	ciphertext := f.aead.Seal(nil, nonce[:], plain, outer[:])
	if _, err := w.Write(outer[:]); err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}
	f.counter = counter + 1
	return nil
}

// DecodeFrameV22 reads and authenticates one opaque v2.2 record. It derives
// the nonce from the local expected counter before opening the ciphertext, and
// then validates every encrypted length before advancing the counter.
func DecodeFrameV22(r io.Reader, f *FrameAEAD) (*DecodedFrame, error) {
	if f == nil || f.aead == nil {
		return nil, io.ErrClosedPipe
	}
	if f.counter == ^uint64(0) {
		return nil, ErrCounterExhausted
	}

	var outer [v22OuterLengthSize]byte
	if _, err := io.ReadFull(r, outer[:]); err != nil {
		return nil, err
	}
	recordLen := binary.BigEndian.Uint32(outer[:])
	minRecordLen := v22InnerHeaderSize + chacha20poly1305.Overhead
	if recordLen < uint32(minRecordLen) {
		return nil, ErrFrameTooShort
	}
	if recordLen > uint32(MaxV22RecordSize-v22OuterLengthSize) {
		return nil, ErrFrameTooLarge
	}

	ciphertext := f.scratchBuf(int(recordLen))
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}
	counter := f.counter
	nonce := f.composeNonce(counter)
	plain, err := f.aead.Open(ciphertext[:0], nonce[:], ciphertext, outer[:])
	if err != nil {
		return nil, ErrAEADOpen
	}
	if len(plain) < v22InnerHeaderSize {
		return nil, ErrFrameTooShort
	}

	wireCounter := binary.BigEndian.Uint64(plain[0:v22InnerCounterLen])
	if wireCounter != counter {
		return nil, ErrCounterMismatch
	}
	t := FrameType(plain[v22InnerCounterLen])
	if !t.Valid() {
		return nil, ErrFrameType
	}
	metaLenOffset := v22InnerCounterLen + v22InnerTypeLen
	metaLen := int(binary.BigEndian.Uint16(plain[metaLenOffset : metaLenOffset+v22InnerMetaLen]))
	if metaLen > MaxMetaLen {
		return nil, ErrMetaTooLarge
	}
	payloadLenOffset := metaLenOffset + v22InnerMetaLen
	payloadLen := uint64(binary.BigEndian.Uint32(plain[payloadLenOffset : payloadLenOffset+v22InnerPayloadLen]))
	dataLen := len(plain) - v22InnerHeaderSize
	if uint64(metaLen)+payloadLen > uint64(dataLen) {
		return nil, ErrFrameTooShort
	}
	paddingLen := dataLen - metaLen - int(payloadLen)
	if paddingLen > MaxFramePad {
		return nil, ErrPadTooLarge
	}

	data := plain[v22InnerHeaderSize:]
	meta := append([]byte(nil), data[:metaLen]...)
	payload := append([]byte(nil), data[metaLen:metaLen+int(payloadLen)]...)
	f.counter = counter + 1
	return &DecodedFrame{
		Counter: counter,
		Type:    t,
		Meta:    meta,
		Payload: payload,
	}, nil
}
