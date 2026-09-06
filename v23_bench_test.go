package ewp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// BenchmarkV23Handshake measures one complete v2.3 six-stage handshake
// over net.Pipe (no data transfer): client ClientInit → server
// HelloRetry → client ClientHello → server ServerHello → client
// ClientFinished → server ServerFinished, including the hybrid
// X25519+ML-KEM-768 key agreement, Ed25519 signatures, transcript
// hashing and HKDF.
//
// This is the cost the client pays per new tunnel; the server pays
// roughly the same per accepted tunnel.
func BenchmarkV23Handshake(b *testing.B) {
	priv, pub, err := GenerateSigningIdentity()
	if err != nil {
		b.Fatal(err)
	}
	const serverID = "bench"
	service, err := NewServiceV23(&v23BenchDiscardHandler{}, priv, serverID, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer service.Close()
	if err := service.AddUser(v23TestUUID); err != nil {
		b.Fatal(err)
	}
	client, err := NewClientV23(v23TestUUID, serverID, pub, 0)
	if err != nil {
		b.Fatal(err)
	}
	dst := Address{Addr: netip.MustParseAddrPort("8.8.8.8:443")}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		clientConn, serverConn := net.Pipe()
		serverDone := make(chan error, 1)
		go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := client.DialConn(ctx, clientConn, dst)
		cancel()
		if err != nil {
			b.Fatalf("DialConn: %v", err)
		}
		conn.Close()
		<-serverDone
	}
}

// v23BenchDiscardHandler completes the handshake then discards the conn.
type v23BenchDiscardHandler struct{}

func (v23BenchDiscardHandler) NewConnection(_ context.Context, conn net.Conn, _ Metadata) error {
	return conn.Close()
}

func (v23BenchDiscardHandler) NewPacketConnection(_ context.Context, pc net.PacketConn, _ Metadata) error {
	return pc.Close()
}

// BenchmarkV23RecordEncode_1KiB measures the data-plane cost per 1 KiB
// record on the v2.3 path: AEAD seal + v2.2 opaque header encode, into
// io.Discard. Uses the same FrameAEAD primitive the live v2.3 stream
// uses, so this tracks the hot loop exactly.
func BenchmarkV23RecordEncode_1KiB(b *testing.B) {
	benchmarkV23RecordEncode(b, 1024)
}

func BenchmarkV23RecordEncode_16KiB(b *testing.B) {
	benchmarkV23RecordEncode(b, 16*1024)
}

func benchmarkV23RecordEncode(b *testing.B, size int) {
	b.Helper()
	enc, _ := newPairBench(b)
	payload := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := EncodeFrameV22(io.Discard, enc, FrameTCPData, nil, payload, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkV23RecordDecode_1KiB measures the receive-side cost per
// 1 KiB record: opaque header parse + AEAD open. Pre-encodes one wire
// record and replays it, resetting the decoder counter each iteration so
// the measurement isolates pure decode work (AEAD open dominates).
func BenchmarkV23RecordDecode_1KiB(b *testing.B) {
	enc, dec := newPairBench(b)
	payload := make([]byte, 1024)
	var buf bytes.Buffer
	if err := EncodeFrameV22(&buf, enc, FrameTCPData, nil, payload, 0); err != nil {
		b.Fatal(err)
	}
	wire := buf.Bytes()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// The pre-encoded wire record carries counter 0; reset the
		// decoder to expect it each iteration so only decode work is
		// measured.
		dec.counter = 0
		if _, err := DecodeFrameV22(bytes.NewReader(wire), dec); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkV23EndToEndThroughput measures a full v2.3 stream
// (handshake once, then steady-state 16 KiB record echo over net.Pipe)
// to gauge data-plane throughput including the SecureStream wrapper.
func BenchmarkV23EndToEndThroughput(b *testing.B) {
	priv, pub, err := GenerateSigningIdentity()
	if err != nil {
		b.Fatal(err)
	}
	service, err := NewServiceV23(&v23BenchEchoHandler{}, priv, "bench", 0)
	if err != nil {
		b.Fatal(err)
	}
	defer service.Close()
	if err := service.AddUser(v23TestUUID); err != nil {
		b.Fatal(err)
	}
	client, err := NewClientV23(v23TestUUID, "bench", pub, 0)
	if err != nil {
		b.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	go func() { _ = service.HandleConn(context.Background(), serverConn) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, clientConn, Address{Addr: netip.MustParseAddrPort("8.8.8.8:443")})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	payload := make([]byte, 16*1024)
	buf := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			b.Fatal(err)
		}
	}
}

type v23BenchEchoHandler struct{}

func (v23BenchEchoHandler) NewConnection(_ context.Context, conn net.Conn, _ Metadata) error {
	_, _ = io.Copy(conn, conn)
	return conn.Close()
}

func (v23BenchEchoHandler) NewPacketConnection(_ context.Context, pc net.PacketConn, _ Metadata) error {
	return pc.Close()
}
