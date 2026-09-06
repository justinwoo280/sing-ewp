package ewp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func testHelloRetry() V3HelloRetry {
	var initNonce, retryNonce V3Nonce
	for i := range initNonce {
		initNonce[i] = byte(i + 1)
		retryNonce[i] = byte(0x40 + i)
	}
	var cookie [V3CookieLen]byte
	for i := range cookie {
		cookie[i] = byte(0x80 + i)
	}
	return V3HelloRetry{
		Version:     V3ProtocolVersion,
		Suite:       V3SuiteX25519MLKEM768ChaCha20Poly1305,
		InitNonce:   initNonce,
		RetryNonce:  retryNonce,
		CookieKeyID: 3,
		ExpiresAt:   1_900_000_000,
		Cookie:      cookie,
	}
}

func TestV3CanonicalHelloRetryRoundTrip(t *testing.T) {
	want := testHelloRetry()
	encoded, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseV3HelloRetry(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !sameV3HelloRetry(got, want) {
		t.Fatalf("parsed retry differs: %#v != %#v", got, want)
	}
	reencoded, err := got.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("retry encoding is not stable")
	}
}

func TestV3CanonicalRejectsOrderingDuplicatesAndCriticalFields(t *testing.T) {
	valid := testHelloRetry()
	base, err := valid.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(append([]byte(nil), base...), 0)
	if _, err := ParseV3HelloRetry(trailing); !errors.Is(err, ErrV3Malformed) {
		t.Fatalf("trailing bytes error = %v", err)
	}

	first, err := encodeV3Fields(v3U16(v3TagSuite, uint16(valid.Suite)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeV3Fields(v3U16(v3TagVersion, valid.Version))
	if err != nil {
		t.Fatal(err)
	}
	wrongOrder := append(first, second...)
	if _, err := ParseV3HelloRetry(wrongOrder); !errors.Is(err, ErrV3NonCanonical) {
		t.Fatalf("wrong order error = %v", err)
	}

	critical := append(append([]byte(nil), base...), 0x80, 0x00, 0x00, 0x00, 0x00, 0x00)
	if _, err := ParseV3HelloRetry(critical); !errors.Is(err, ErrV3UnknownField) {
		t.Fatalf("unknown critical error = %v", err)
	}

	duplicate := make([]byte, 0, len(base)+len(base))
	duplicate = append(duplicate, base...)
	// A second version field is placed after the canonical fields; the strict
	// ordering check must reject it before any semantic field handling.
	var field [v3FieldHeaderLen]byte
	binary.BigEndian.PutUint16(field[:2], v3TagVersion)
	binary.BigEndian.PutUint32(field[2:], 2)
	duplicate = append(duplicate, field[:]...)
	duplicate = append(duplicate, 0, 3)
	if _, err := ParseV3HelloRetry(duplicate); !errors.Is(err, ErrV3NonCanonical) {
		t.Fatalf("duplicate field error = %v", err)
	}
}

func TestV3CanonicalAcceptsUnknownNonCriticalField(t *testing.T) {
	valid := testHelloRetry()
	base, err := valid.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	extra, err := encodeV3Fields(v3Bytes(100, []byte("extension")))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV3HelloRetry(append(base, extra...))
	if err != nil {
		t.Fatal(err)
	}
	if !sameV3HelloRetry(parsed, valid) {
		t.Fatal("non-critical extension changed known fields")
	}
}

func TestV3CanonicalRejectsDuplicateUnknownNonCriticalField(t *testing.T) {
	first, err := encodeV3Fields(v3Bytes(100, []byte("extension")))
	if err != nil {
		t.Fatal(err)
	}
	data := append(append([]byte(nil), first...), first...)
	if _, err := ParseV3HelloRetry(data); !errors.Is(err, ErrV3DuplicateField) && !errors.Is(err, ErrV3NonCanonical) {
		t.Fatalf("duplicate unknown field error = %v", err)
	}
}

func TestV3CanonicalBoundsBeforeAllocation(t *testing.T) {
	var oversized [6]byte
	binary.BigEndian.PutUint16(oversized[:2], v3TagVersion)
	binary.BigEndian.PutUint32(oversized[2:], ^uint32(0))
	if _, err := ParseV3HelloRetry(oversized[:]); !errors.Is(err, ErrV3Malformed) {
		t.Fatalf("oversized field error = %v", err)
	}

	tooLarge := bytes.Repeat([]byte{0}, MaxV3MessageSize+1)
	if _, err := ParseV3HelloRetry(tooLarge); !errors.Is(err, ErrV3MessageTooLarge) {
		t.Fatalf("oversized message error = %v", err)
	}
}

func TestV3ParsedVariableFieldsOwnInput(t *testing.T) {
	initValue := V3ClientInit{
		Version:          V3ProtocolVersion,
		Suite:            V3SuiteX25519MLKEM768ChaCha20Poly1305,
		ServerID:         "ownership-server",
		DeploymentScope:  "ownership-scope",
		RouteTag:         RouteTag{1},
		RouteEpoch:       7,
		PreKeyID:         PreKeyID{2},
		BundleGeneration: 3,
		BundleDigest:     BundleDigest{4},
		InitNonce:        V3Nonce{5},
		ClientNonce:      V3Nonce{6},
		CoreDigest:       [32]byte{7},
		Padding:          []byte("init-padding"),
	}
	initWire, err := initValue.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsedInit, err := ParseV3ClientInit(initWire)
	if err != nil {
		t.Fatal(err)
	}
	for i := range initWire {
		initWire[i] ^= 0xff
	}
	if parsedInit.ServerID != initValue.ServerID || parsedInit.DeploymentScope != initValue.DeploymentScope || !bytes.Equal(parsedInit.Padding, initValue.Padding) {
		t.Fatal("ClientInit parser retained mutable input data")
	}

	coreHeader := V3ClientHelloCoreHeader{
		PreKeyID:             PreKeyID{8},
		BundleGeneration:     9,
		BundleDigest:         BundleDigest{10},
		ClientNonce:          V3Nonce{11},
		OuterX25519Public:    [X25519PubLen]byte{12},
		OuterMLKEMCiphertext: bytes.Repeat([]byte{0x13}, MLKEM768CipherL),
	}
	coreValue := V3ClientHelloCore{Header: coreHeader, Ciphertext: bytes.Repeat([]byte{0x14}, 32)}
	coreWire, err := coreValue.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsedCore, err := ParseV3ClientHelloCore(coreWire)
	if err != nil {
		t.Fatal(err)
	}
	for i := range coreWire {
		coreWire[i] ^= 0xff
	}
	if !bytes.Equal(parsedCore.Header.OuterMLKEMCiphertext, coreHeader.OuterMLKEMCiphertext) || !bytes.Equal(parsedCore.Ciphertext, coreValue.Ciphertext) {
		t.Fatal("ClientHelloCore parser retained mutable input data")
	}

	finishedValue := V3ClientFinished{
		Version:     V3ProtocolVersion,
		Suite:       V3SuiteX25519MLKEM768ChaCha20Poly1305,
		HandshakeID: HandshakeID{15},
		Ciphertext:  bytes.Repeat([]byte{0x16}, 32),
	}
	finishedWire, err := finishedValue.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsedFinished, err := ParseV3ClientFinished(finishedWire)
	if err != nil {
		t.Fatal(err)
	}
	for i := range finishedWire {
		finishedWire[i] ^= 0xff
	}
	if !bytes.Equal(parsedFinished.Ciphertext, finishedValue.Ciphertext) {
		t.Fatal("Finished parser retained mutable input data")
	}
}
