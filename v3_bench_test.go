package ewp

import (
	"bytes"
	"testing"
	"time"
)

func BenchmarkV3CanonicalHelloRetryEncode(b *testing.B) {
	retry := testHelloRetry()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := retry.MarshalBinary(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkV3CanonicalHelloRetryDecode(b *testing.B) {
	retry := testHelloRetry()
	data, err := retry.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseV3HelloRetry(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkV3ClientInitDecode(b *testing.B) {
	data, err := (V3ClientInit{
		Version:          V3ProtocolVersion,
		Suite:            V3SuiteX25519MLKEM768ChaCha20Poly1305,
		ServerID:         "bench-server",
		DeploymentScope:  "bench-scope",
		RouteTag:         RouteTag{1},
		RouteEpoch:       7,
		PreKeyID:         PreKeyID{2},
		BundleGeneration: 3,
		BundleDigest:     BundleDigest{4},
		InitNonce:        V3Nonce{5},
		ClientNonce:      V3Nonce{6},
		CoreDigest:       [32]byte{7},
		Padding:          []byte("bench-padding"),
	}).MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseV3ClientInit(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkV3FinishedDecode(b *testing.B) {
	data, err := (V3ClientFinished{
		Version:     V3ProtocolVersion,
		Suite:       V3SuiteX25519MLKEM768ChaCha20Poly1305,
		HandshakeID: HandshakeID{1},
		Ciphertext:  bytes.Repeat([]byte{0x5a}, 32),
	}).MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseV3ClientFinished(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkV3CookieReject(b *testing.B) {
	listener := V3ListenerContext{
		Version: V3ProtocolVersion, Suite: V3SuiteX25519MLKEM768ChaCha20Poly1305,
		ServerID: "bench-server", DeploymentScope: "bench-scope",
	}
	keys := V3CookieKeys{Current: V3CookieKey{ID: 1, Key: [32]byte{1}}}
	init := V3ClientInit{
		Version: listener.Version, Suite: listener.Suite, ServerID: listener.ServerID,
		DeploymentScope: listener.DeploymentScope, PreKeyID: PreKeyID{1},
		BundleDigest: BundleDigest{2}, InitNonce: V3Nonce{3}, ClientNonce: V3Nonce{4},
		CoreDigest: [32]byte{5},
	}
	retry := V3HelloRetry{Version: listener.Version, Suite: listener.Suite, InitNonce: init.InitNonce, ExpiresAt: uint64(time.Now().Add(time.Minute).Unix())}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := keys.Verify(listener, init, retry, SourceBinding("bench-source")); err == nil {
			b.Fatal("invalid cookie unexpectedly accepted")
		}
	}
}

func BenchmarkV3RecordSeal(b *testing.B) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	frame, err := NewFrameAEAD(key, prefix)
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	random := v3RepeatingReader{value: 0x11}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame.counter = 0
		if _, err := encodeRecordBytesWithReader(frame, FrameTCPData, nil, payload, 64, random); err != nil {
			b.Fatal(err)
		}
	}
}

type v3RepeatingReader struct {
	value byte
}

func (r v3RepeatingReader) Read(data []byte) (int, error) {
	for i := range data {
		data[i] = r.value
	}
	return len(data), nil
}

func BenchmarkV3RecordOpen(b *testing.B) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	encoder, err := NewFrameAEAD(key, prefix)
	if err != nil {
		b.Fatal(err)
	}
	var wire bytes.Buffer
	if err := encodeRecordWithReader(&wire, encoder, FrameTCPData, nil, bytes.Repeat([]byte{0x5a}, 1024), 64, bytes.NewReader(bytes.Repeat([]byte{0x11}, 128))); err != nil {
		b.Fatal(err)
	}
	data := append([]byte(nil), wire.Bytes()...)
	decoder, err := NewFrameAEAD(key, prefix)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reuse the cipher so this measures one record open, not cipher setup.
		decoder.counter = 0
		if _, consumed, err := decodeRecordBytes(data, decoder); err != nil || consumed != len(data) {
			b.Fatal(err)
		}
	}
}
