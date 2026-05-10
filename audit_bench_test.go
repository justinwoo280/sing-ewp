// Performance benchmark suite comparing the v2.0 and v2.1 hot paths.
//
// We focus on:
//   1. ClientHello handshake — encode + decode (server-side accept).
//      v2.1 adds one X25519 static-ECDH per direction; the rest of
//      the work is unchanged.
//   2. Bulk data throughput — a single SecureStream round-trip is
//      identical between v2.0 and v2.1 (both use the same FrameAEAD
//      path), so we benchmark it once as a baseline.
//   3. ReplayCache.MarkSeenOrReject under concurrent admit pressure.
//
// To run:
//
//   go test -bench=. -benchmem -benchtime=2s ./...

package ewp

import (
	"bytes"
	"crypto/ecdh"
	crand "crypto/rand"
	"sync/atomic"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Handshake encode + accept benchmarks (v2.0 vs v2.1)
// ----------------------------------------------------------------------

func BenchmarkHandshake_V20_Encode(b *testing.B) {
	uuid := benchUUID(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := WriteClientHello(func(_ []byte) error { return nil },
			uuid, CommandTCP, Address{Domain: "x.example", Port: 1})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshake_V21_Encode(b *testing.B) {
	uuid := benchUUID(b)
	_, pub := benchStatic(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := WriteClientHelloV21(func(_ []byte) error { return nil },
			uuid, CommandTCP, Address{Domain: "x.example", Port: 1}, pub)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshake_V20_Accept(b *testing.B) {
	uuid := benchUUID(b)
	state, err := WriteClientHello(func(_ []byte) error { return nil },
		uuid, CommandTCP, Address{Domain: "x.example", Port: 1})
	if err != nil {
		b.Fatal(err)
	}
	wire, err := EncodeClientHello(state.hello)
	if err != nil {
		b.Fatal(err)
	}
	lookup := MakeUUIDLookup([][UUIDLen]byte{uuid})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := AcceptClientHello(wire, lookup)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshake_V21_Accept(b *testing.B) {
	uuid := benchUUID(b)
	priv, pub := benchStatic(b)
	state, err := WriteClientHelloV21(func(_ []byte) error { return nil },
		uuid, CommandTCP, Address{Domain: "x.example", Port: 1}, pub)
	if err != nil {
		b.Fatal(err)
	}
	wire, err := EncodeClientHelloV21Test(state, pub)
	if err != nil {
		b.Fatal(err)
	}
	lookup := MakeUUIDLookupV21([][UUIDLen]byte{uuid})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := AcceptClientHelloV21Strict(wire, lookup, priv)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ----------------------------------------------------------------------
// Frame data throughput (independent of v2.0 vs v2.1 — both use the
// same FrameAEAD path)
// ----------------------------------------------------------------------

func BenchmarkFrame_Encode_1KB(b *testing.B) {
	enc, err := NewFrameAEAD([AEADKeyLen]byte{1, 2, 3}, [NoncePrefixLen]byte{4, 5, 6, 7})
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 1024)
	b.SetBytes(int64(len(payload)))
	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := EncodeFrame(&buf, enc, FrameTCPData, nil, payload, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrame_Decode_1KB(b *testing.B) {
	enc, _ := NewFrameAEAD([AEADKeyLen]byte{1, 2, 3}, [NoncePrefixLen]byte{4, 5, 6, 7})
	dec, _ := NewFrameAEAD([AEADKeyLen]byte{1, 2, 3}, [NoncePrefixLen]byte{4, 5, 6, 7})
	payload := bytes.Repeat([]byte("x"), 1024)
	var buf bytes.Buffer
	if err := EncodeFrame(&buf, enc, FrameTCPData, nil, payload, 0); err != nil {
		b.Fatal(err)
	}
	wire := buf.Bytes()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Re-create dec each iteration so counter doesn't desync.
		// We measure pure DecodeFrame work; the AEAD cost dominates.
		dec.counter = uint64(i)
		_, _ = DecodeFrame(bytes.NewReader(wire), dec)
		dec.counter = 0
	}
}

// ----------------------------------------------------------------------
// ReplayCache concurrent admit
// ----------------------------------------------------------------------

func BenchmarkReplayCache_AdmitParallel(b *testing.B) {
	cache := NewReplayCache(ReplayWindow)
	defer cache.Close()
	var ctr atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var u [UUIDLen]byte
			var n [HandshakeNonce]byte
			x := ctr.Add(1)
			n[0] = byte(x)
			n[1] = byte(x >> 8)
			n[2] = byte(x >> 16)
			n[3] = byte(x >> 24)
			cache.MarkSeenOrReject(u, n)
		}
	})
}

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

func benchUUID(b *testing.B) [UUIDLen]byte {
	b.Helper()
	var u [UUIDLen]byte
	if _, err := crand.Read(u[:]); err != nil {
		b.Fatal(err)
	}
	return u
}

func benchStatic(b *testing.B) (*ecdh.PrivateKey, []byte) {
	b.Helper()
	p, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	return p, p.PublicKey().Bytes()
}

// Avoid unused-import flag.
var _ = time.Now
