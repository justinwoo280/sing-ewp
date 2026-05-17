package ewp

import (
	"io"
	"net/netip"
	"testing"
)

// BenchmarkHandshake_FullRoundTrip measures one complete client-side
// + server-side handshake (X25519 + ML-KEM-768 + HKDF + AEAD seal/open
// of the inner plaintext + outer HMAC verify).
//
// This is the cost the client pays per new tunnel; the server pays
// roughly the same per accepted tunnel.
func BenchmarkHandshake_FullRoundTrip(b *testing.B) {
	addr := Address{Addr: netip.MustParseAddrPort("8.8.8.8:443")}
	lookup := MakeUUIDLookup([][UUIDLen]byte{testUUID})
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var captured []byte
		state, err := WriteClientHello(func(b []byte) error {
			captured = append([]byte(nil), b...)
			return nil
		}, testUUID, CommandTCP, addr)
		if err != nil {
			b.Fatal(err)
		}
		shOut, _, err := AcceptClientHello(captured, lookup)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := state.ReadServerHello(shOut); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHandshake_ClientOnly isolates the client-side cost (this
// is the latency the user feels on every new tunnel).
func BenchmarkHandshake_ClientOnly(b *testing.B) {
	addr := Address{Addr: netip.MustParseAddrPort("1.1.1.1:443")}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := WriteClientHello(func(b []byte) error { return nil }, testUUID, CommandTCP, addr)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFrameEncode_1KiB measures frame send throughput for a
// typical small-payload frame (1 KiB), including AEAD seal + write to
// io.Discard.
func BenchmarkFrameEncode_1KiB(b *testing.B) {
	enc, _ := newPairBench(b)
	payload := make([]byte, 1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := EncodeFrame(io.Discard, enc, FrameTCPData, nil, payload, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFrameEncode_16KiB measures large-frame throughput (close to
// MaxFrameSize budget for TCP-style bulk).
func BenchmarkFrameEncode_16KiB(b *testing.B) {
	enc, _ := newPairBench(b)
	payload := make([]byte, 16*1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := EncodeFrame(io.Discard, enc, FrameTCPData, nil, payload, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func newPairBench(b *testing.B) (*FrameAEAD, *FrameAEAD) {
	b.Helper()
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range prefix {
		prefix[i] = byte(0xa0 + i)
	}
	a, err := NewFrameAEAD(key, prefix)
	if err != nil {
		b.Fatal(err)
	}
	c, err := NewFrameAEAD(key, prefix)
	if err != nil {
		b.Fatal(err)
	}
	return a, c
}

// nullTransport is a MessageTransport that discards every Send.
type nullTransport struct{}

func (nullTransport) SendMessage(b []byte) error  { return nil }
func (nullTransport) ReadMessage() ([]byte, error) { return nil, io.EOF }
func (nullTransport) Close() error                 { return nil }

// BenchmarkSecureStream_SendTCPData_1KiB measures the hot path on the
// SecureStream itself, including bucket-aware padding lookup and
// reuse of the per-stream send buffer.
func BenchmarkSecureStream_SendTCPData_1KiB(b *testing.B) {
	var keys SessionKeys
	for i := range keys.C2SKey {
		keys.C2SKey[i] = byte(i)
	}
	for i := range keys.S2CKey {
		keys.S2CKey[i] = byte(i ^ 0xff)
	}
	ss, err := NewClientSecureStream(nullTransport{}, keys)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := ss.SendTCPData(payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSecureStream_SendTCPData_16KiB exercises the reshape path
// (16KiB > reshapeThreshold so the payload is split).
func BenchmarkSecureStream_SendTCPData_16KiB(b *testing.B) {
	var keys SessionKeys
	for i := range keys.C2SKey {
		keys.C2SKey[i] = byte(i)
	}
	ss, err := NewClientSecureStream(nullTransport{}, keys)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 16*1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := ss.SendTCPData(payload); err != nil {
			b.Fatal(err)
		}
	}
}
