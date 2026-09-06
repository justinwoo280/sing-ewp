package ewp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func newV3RecordPair(t *testing.T) (*FrameAEAD, *FrameAEAD) {
	t.Helper()
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range prefix {
		prefix[i] = byte(0xa0 + i)
	}
	encoder, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return encoder, decoder
}

func TestV3RecordRejectsLengthCounterAndTrailingMutations(t *testing.T) {
	encoder, decoder := newV3RecordPair(t)
	var wire bytes.Buffer
	if err := encodeRecordWithReader(&wire, encoder, FrameTCPData, []byte("meta"), []byte("payload"), 0, v3RepeatingReader{value: 1}); err != nil {
		t.Fatal(err)
	}
	mutatedLength := append([]byte(nil), wire.Bytes()...)
	mutatedLength[3]++
	if _, err := DecodeRecord(bytes.NewReader(mutatedLength), decoder); !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, ErrAEADOpen) {
		t.Fatalf("length mutation error = %v", err)
	}

	encoder, decoder = newV3RecordPair(t)
	wire.Reset()
	if err := encodeRecordWithReader(&wire, encoder, FrameTCPData, nil, []byte("payload"), 0, v3RepeatingReader{value: 1}); err != nil {
		t.Fatal(err)
	}
	mutatedCounter := append([]byte(nil), wire.Bytes()...)
	// The counter is encrypted; change the authenticated ciphertext instead of
	// assuming a visible offset.
	mutatedCounter[len(mutatedCounter)-1] ^= 1
	if _, err := DecodeRecord(bytes.NewReader(mutatedCounter), decoder); !errors.Is(err, ErrAEADOpen) {
		t.Fatalf("ciphertext mutation error = %v", err)
	}

	encoder, decoder = newV3RecordPair(t)
	wire.Reset()
	if err := encodeRecordWithReader(&wire, encoder, FrameTCPData, nil, []byte("payload"), 0, v3RepeatingReader{value: 1}); err != nil {
		t.Fatal(err)
	}
	trailing := append(append([]byte(nil), wire.Bytes()...), 0)
	if _, err := DecodeRecord(bytes.NewReader(trailing), decoder); err != nil {
		t.Fatal("record decoder should consume one record only", err)
	}
	reader := bytes.NewReader(trailing)
	if _, err := DecodeRecord(reader, decoder); err == nil {
		t.Fatal("second decode unexpectedly accepted trailing byte")
	}
	if int(binary.BigEndian.Uint32(trailing[:4]))+4 != len(wire.Bytes()) {
		t.Fatal("record vector length changed unexpectedly")
	}
}
