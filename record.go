package ewp

import (
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	AEADKeyLen     = chacha20poly1305.KeySize
	AEADNonceLen   = chacha20poly1305.NonceSize
	NoncePrefixLen = AEADNonceLen - CounterLen
	CounterLen     = 8

	X25519PubLen    = 32
	MLKEM768PubLen  = 1184
	MLKEM768CipherL = 1088

	MaxFramePad  = 4096
	MaxFrameSize = 65536
	MaxMetaLen   = 1024
)

type Command byte

const (
	CommandTCP Command = 0x01
	CommandUDP Command = 0x02
)

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
		FrameUDPProbeReq, FrameUDPProbeResp, FramePing, FramePong,
		FrameRekeyReq, FrameRekeyResp, FramePaddingOnly:
		return true
	default:
		return false
	}
}

var (
	ErrFrameTooLarge    = errors.New("ewp/v3: record exceeds limit")
	ErrFrameTooShort    = errors.New("ewp/v3: record is truncated")
	ErrFrameType        = errors.New("ewp/v3: unknown record type")
	ErrMetaTooLarge     = errors.New("ewp/v3: metadata exceeds limit")
	ErrPadTooLarge      = errors.New("ewp/v3: padding exceeds limit")
	ErrAEADOpen         = errors.New("ewp/v3: record authentication failed")
	ErrCounterMismatch  = errors.New("ewp/v3: record counter mismatch")
	ErrCounterExhausted = errors.New("ewp/v3: record counter exhausted")
	ErrCommand          = errors.New("ewp/v3: unsupported command")
)

// FrameAEAD is one directional record cipher and its next expected counter.
// SecureStream serializes access to each direction.
type FrameAEAD struct {
	aead         cipher.AEAD
	prefix       [NoncePrefixLen]byte
	nonce        [AEADNonceLen]byte
	counter      uint64
	key          [AEADKeyLen]byte
	updateSecret [32]byte
	epoch        uint64
	context      v3RecordContext
}

type v3RecordContext struct {
	listener   V3ListenerContext
	transcript [32]byte
	sender     string
	receiver   string
	direction  string
}

func NewFrameAEAD(key [AEADKeyLen]byte, prefix [NoncePrefixLen]byte) (*FrameAEAD, error) {
	secret := v3Hash("ewp/v3/record-update-root", key[:], prefix[:])
	return newFrameAEAD(key, prefix, secret, v3RecordContext{})
}

func newFrameAEAD(key [AEADKeyLen]byte, prefix [NoncePrefixLen]byte, updateSecret [32]byte, context v3RecordContext) (*FrameAEAD, error) {
	if updateSecret == ([32]byte{}) {
		updateSecret = v3Hash("ewp/v3/record-update-root", key[:], prefix[:])
	}
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("ewp/v3: create record cipher: %w", err)
	}
	return &FrameAEAD{aead: a, prefix: prefix, key: key, updateSecret: updateSecret, context: context}, nil
}

func (f *FrameAEAD) wipe() {
	if f == nil {
		return
	}
	zero(f.key[:])
	zero(f.prefix[:])
	zero(f.nonce[:])
	zero(f.updateSecret[:])
	f.aead = nil
	f.counter = 0
	f.epoch = 0
}

func (f *FrameAEAD) Counter() uint64 {
	if f == nil {
		return 0
	}
	return f.counter
}

func (f *FrameAEAD) composeNonce(counter uint64) []byte {
	copy(f.nonce[:NoncePrefixLen], f.prefix[:])
	binary.BigEndian.PutUint64(f.nonce[NoncePrefixLen:], counter)
	return f.nonce[:]
}

func deriveFrameRekey(f *FrameAEAD) ([32]byte, [AEADKeyLen]byte, [NoncePrefixLen]byte, error) {
	if f == nil || f.aead == nil {
		return [32]byte{}, [AEADKeyLen]byte{}, [NoncePrefixLen]byte{}, io.ErrClosedPipe
	}
	if f.epoch == ^uint64(0) {
		return [32]byte{}, [AEADKeyLen]byte{}, [NoncePrefixLen]byte{}, ErrCounterExhausted
	}
	epoch := f.epoch + 1
	var secretBytes, keyBytes, prefixBytes []byte
	var err error
	if f.context.listener.validate() == nil {
		secretBytes, err = v3Expand(f.updateSecret[:], "traffic/update-secret", f.context.listener, f.context.transcript[:], f.context.sender, f.context.receiver, f.context.direction, epoch, 32)
		if err == nil {
			var nextSecret [32]byte
			defer zero(nextSecret[:])
			copy(nextSecret[:], secretBytes)
			keyBytes, err = v3Expand(nextSecret[:], "traffic/key", f.context.listener, f.context.transcript[:], f.context.sender, f.context.receiver, f.context.direction, epoch, AEADKeyLen)
			if err == nil {
				prefixBytes, err = v3Expand(nextSecret[:], "traffic/nonce-prefix", f.context.listener, f.context.transcript[:], f.context.sender, f.context.receiver, f.context.direction, epoch, NoncePrefixLen)
			}
		}
	} else {
		context := v3Domain(recordRekeyLabel, []byte(f.context.sender), []byte(f.context.receiver), []byte(f.context.direction), f.context.transcript[:], v3Uint64Bytes(epoch))
		expand := func(suffix string, length int) ([]byte, error) {
			info := append(append([]byte(nil), context...), suffix...)
			return v3ExpandRaw(f.updateSecret[:], string(info), length)
		}
		secretBytes, err = expand("/secret", 32)
		if err == nil {
			keyBytes, err = expand("/key", AEADKeyLen)
		}
		if err == nil {
			prefixBytes, err = expand("/nonce-prefix", NoncePrefixLen)
		}
	}
	if err != nil {
		zero(secretBytes)
		zero(keyBytes)
		zero(prefixBytes)
		return [32]byte{}, [AEADKeyLen]byte{}, [NoncePrefixLen]byte{}, err
	}
	var secret [32]byte
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	copy(secret[:], secretBytes)
	copy(key[:], keyBytes)
	copy(prefix[:], prefixBytes)
	zero(secretBytes)
	zero(keyBytes)
	zero(prefixBytes)
	return secret, key, prefix, nil
}

const (
	recordOuterLengthSize = 4
	recordCounterLen      = 8
	recordTypeLen         = 1
	recordMetaLen         = 2
	recordPayloadLen      = 4
	recordInnerHeaderSize = recordCounterLen + recordTypeLen + recordMetaLen + recordPayloadLen
)

// EncodeRecord writes the opaque v3 application record. The clear prefix only
// announces the authenticated ciphertext length; type, metadata and payload
// are all encrypted together.
func EncodeRecord(w io.Writer, f *FrameAEAD, t FrameType, meta, payload []byte, padLen int) error {
	return encodeRecordWithReader(w, f, t, meta, payload, padLen, crand.Reader)
}

func recordLayout(f *FrameAEAD, t FrameType, meta, payload []byte, padLen int) (counter uint64, normalizedPad, plainLen, recordLen int, err error) {
	if f == nil || f.aead == nil {
		err = io.ErrClosedPipe
		return
	}
	if f.counter == ^uint64(0) {
		err = ErrCounterExhausted
		return
	}
	if !t.Valid() {
		err = ErrFrameType
		return
	}
	if len(meta) > MaxMetaLen {
		err = ErrMetaTooLarge
		return
	}
	if padLen < 0 {
		padLen = 0
	}
	if padLen > MaxFramePad {
		err = ErrPadTooLarge
		return
	}
	plainLen = recordInnerHeaderSize + len(meta) + len(payload) + padLen
	recordLen = plainLen + chacha20poly1305.Overhead
	if recordLen+recordOuterLengthSize > MaxFrameSize {
		err = ErrFrameTooLarge
		return
	}
	return f.counter, padLen, plainLen, recordLen, nil
}

func encodeRecordBytesWithReader(f *FrameAEAD, t FrameType, meta, payload []byte, padLen int, random io.Reader) ([]byte, error) {
	if random == nil {
		random = crand.Reader
	}
	counter, padLen, plainLen, recordLen, err := recordLayout(f, t, meta, payload, padLen)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, plainLen)
	defer zero(plain)
	binary.BigEndian.PutUint64(plain[:recordCounterLen], counter)
	plain[recordCounterLen] = byte(t)
	binary.BigEndian.PutUint16(plain[recordCounterLen+recordTypeLen:recordCounterLen+recordTypeLen+recordMetaLen], uint16(len(meta)))
	payloadOffset := recordCounterLen + recordTypeLen + recordMetaLen
	binary.BigEndian.PutUint32(plain[payloadOffset:payloadOffset+recordPayloadLen], uint32(len(payload)))
	dataOffset := recordInnerHeaderSize
	copy(plain[dataOffset:], meta)
	dataOffset += len(meta)
	copy(plain[dataOffset:], payload)
	dataOffset += len(payload)
	if padLen > 0 {
		if _, err := io.ReadFull(random, plain[dataOffset:]); err != nil {
			return nil, err
		}
	}

	wire := make([]byte, recordOuterLengthSize+recordLen)
	binary.BigEndian.PutUint32(wire[:recordOuterLengthSize], uint32(recordLen))
	nonce := f.composeNonce(counter)
	f.aead.Seal(wire[recordOuterLengthSize:recordOuterLengthSize], nonce[:], plain, wire[:recordOuterLengthSize])
	f.counter = counter + 1
	return wire, nil
}

func encodeRecordWithReader(w io.Writer, f *FrameAEAD, t FrameType, meta, payload []byte, padLen int, random io.Reader) error {
	if random == nil {
		random = crand.Reader
	}
	counter, padLen, plainLen, recordLen, err := recordLayout(f, t, meta, payload, padLen)
	if err != nil {
		return err
	}

	var outer [recordOuterLengthSize]byte
	binary.BigEndian.PutUint32(outer[:], uint32(recordLen))
	plain := make([]byte, plainLen)
	defer zero(plain)
	binary.BigEndian.PutUint64(plain[:recordCounterLen], counter)
	plain[recordCounterLen] = byte(t)
	binary.BigEndian.PutUint16(plain[recordCounterLen+recordTypeLen:recordCounterLen+recordTypeLen+recordMetaLen], uint16(len(meta)))
	payloadOffset := recordCounterLen + recordTypeLen + recordMetaLen
	binary.BigEndian.PutUint32(plain[payloadOffset:payloadOffset+recordPayloadLen], uint32(len(payload)))
	dataOffset := recordInnerHeaderSize
	copy(plain[dataOffset:], meta)
	dataOffset += len(meta)
	copy(plain[dataOffset:], payload)
	dataOffset += len(payload)
	if padLen > 0 {
		if _, err := io.ReadFull(random, plain[dataOffset:]); err != nil {
			return err
		}
	}

	nonce := f.composeNonce(counter)
	if buffer, ok := w.(*bytes.Buffer); ok {
		buffer.Grow(recordOuterLengthSize + recordLen)
		if err := writeFull(buffer, outer[:]); err != nil {
			return err
		}
		available := buffer.Bytes()
		available = available[len(available):cap(available)]
		ciphertext := f.aead.Seal(available[:0], nonce, plain, outer[:])
		if err := writeFull(buffer, ciphertext); err != nil {
			return err
		}
		f.counter = counter + 1
		return nil
	}
	ciphertext := f.aead.Seal(nil, nonce, plain, outer[:])
	if err := writeFull(w, outer[:]); err != nil {
		return err
	}
	if err := writeFull(w, ciphertext); err != nil {
		return err
	}
	f.counter = counter + 1
	return nil
}

type DecodedFrame struct {
	Counter uint64
	Type    FrameType
	Meta    []byte
	Payload []byte
}

func decodeRecordBytes(data []byte, f *FrameAEAD) (*DecodedFrame, int, error) {
	if f == nil || f.aead == nil {
		return nil, 0, io.ErrClosedPipe
	}
	if f.counter == ^uint64(0) {
		return nil, 0, ErrCounterExhausted
	}
	if len(data) < recordOuterLengthSize {
		return nil, 0, ErrFrameTooShort
	}
	recordLen := binary.BigEndian.Uint32(data[:recordOuterLengthSize])
	if recordLen < recordInnerHeaderSize+chacha20poly1305.Overhead {
		return nil, 0, ErrFrameTooShort
	}
	if recordLen > MaxFrameSize-recordOuterLengthSize {
		return nil, 0, ErrFrameTooLarge
	}
	total := recordOuterLengthSize + int(recordLen)
	if total > len(data) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	frame, err := decodeRecordCiphertext(data[:recordOuterLengthSize], data[recordOuterLengthSize:total], f)
	return frame, total, err
}

func DecodeRecord(r io.Reader, f *FrameAEAD) (*DecodedFrame, error) {
	if f == nil || f.aead == nil {
		return nil, io.ErrClosedPipe
	}
	if f.counter == ^uint64(0) {
		return nil, ErrCounterExhausted
	}
	var outer [recordOuterLengthSize]byte
	if _, err := io.ReadFull(r, outer[:]); err != nil {
		return nil, err
	}
	recordLen := binary.BigEndian.Uint32(outer[:])
	if recordLen < recordInnerHeaderSize+chacha20poly1305.Overhead {
		return nil, ErrFrameTooShort
	}
	if recordLen > MaxFrameSize-recordOuterLengthSize {
		return nil, ErrFrameTooLarge
	}
	ciphertext := make([]byte, int(recordLen))
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}
	return decodeRecordCiphertext(outer[:], ciphertext, f)
}

func decodeRecordCiphertext(outer, ciphertext []byte, f *FrameAEAD) (*DecodedFrame, error) {
	if f == nil || f.aead == nil {
		return nil, io.ErrClosedPipe
	}
	if f.counter == ^uint64(0) {
		return nil, ErrCounterExhausted
	}
	counter := f.counter
	nonce := f.composeNonce(counter)
	plain, err := f.aead.Open(nil, nonce, ciphertext, outer)
	if err != nil {
		return nil, ErrAEADOpen
	}
	defer zero(plain)
	if len(plain) < recordInnerHeaderSize {
		return nil, ErrFrameTooShort
	}
	wireCounter := binary.BigEndian.Uint64(plain[:recordCounterLen])
	if wireCounter != counter {
		return nil, ErrCounterMismatch
	}
	t := FrameType(plain[recordCounterLen])
	if !t.Valid() {
		return nil, ErrFrameType
	}
	metaOffset := recordCounterLen + recordTypeLen
	metaLen := int(binary.BigEndian.Uint16(plain[metaOffset : metaOffset+recordMetaLen]))
	if metaLen > MaxMetaLen {
		return nil, ErrMetaTooLarge
	}
	payloadOffset := metaOffset + recordMetaLen
	payloadLen := uint64(binary.BigEndian.Uint32(plain[payloadOffset : payloadOffset+recordPayloadLen]))
	dataLen := len(plain) - recordInnerHeaderSize
	if uint64(metaLen)+payloadLen > uint64(dataLen) {
		return nil, ErrFrameTooShort
	}
	paddingLen := dataLen - metaLen - int(payloadLen)
	if paddingLen > MaxFramePad {
		return nil, ErrPadTooLarge
	}
	data := plain[recordInnerHeaderSize:]
	payloadSize := int(payloadLen)
	output := make([]byte, metaLen+payloadSize)
	copy(output, data[:metaLen])
	copy(output[metaLen:], data[metaLen:metaLen+payloadSize])
	f.counter = counter + 1
	return &DecodedFrame{
		Counter: counter,
		Type:    t,
		Meta:    output[:metaLen:metaLen],
		Payload: output[metaLen : metaLen+payloadSize : metaLen+payloadSize],
	}, nil
}

func NewGlobalID() [8]byte {
	return newGlobalIDWithReader(crand.Reader)
}

func newGlobalIDWithReader(random io.Reader) [8]byte {
	if random == nil {
		random = crand.Reader
	}
	var id [8]byte
	for {
		if _, err := io.ReadFull(random, id[:]); err != nil {
			panic("ewp/v3: random global id: " + err.Error())
		}
		if id != ([8]byte{}) {
			return id
		}
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
