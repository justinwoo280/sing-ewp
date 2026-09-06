package ewp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func newV22FramePair(t *testing.T) (*FrameAEAD, *FrameAEAD) {
	t.Helper()
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range prefix {
		prefix[i] = byte(0xa0 + i)
	}
	enc, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return enc, dec
}

func v22SealForTest(t *testing.T, f *FrameAEAD, nonceCounter uint64, plain []byte) []byte {
	t.Helper()
	var outer [v22OuterLengthSize]byte
	binary.BigEndian.PutUint32(outer[:], uint32(len(plain)+chacha20poly1305.Overhead))
	nonce := f.composeNonce(nonceCounter)
	ciphertext := f.aead.Seal(nil, nonce[:], plain, outer[:])
	return append(outer[:], ciphertext...)
}

func TestFrameV22_EqualBucketsHideDifferentPayloadLengths(t *testing.T) {
	encA, decA := newV22FramePair(t)
	encB, decB := newV22FramePair(t)
	payloadA := bytes.Repeat([]byte("a"), 32)
	payloadB := bytes.Repeat([]byte("b"), 200)
	const targetWireLen = 1024

	encode := func(enc *FrameAEAD, payload []byte) []byte {
		t.Helper()
		raw := v22OuterLengthSize + v22InnerHeaderSize + len(payload) + chacha20poly1305.Overhead
		padLen := targetWireLen - raw
		if padLen < 0 || padLen > MaxFramePad {
			t.Fatalf("invalid test padding %d", padLen)
		}
		var wire bytes.Buffer
		if err := encodeFrameV22WithPad(&wire, enc, FrameTCPData, nil, payload, padLen); err != nil {
			t.Fatal(err)
		}
		return wire.Bytes()
	}

	wireA := encode(encA, payloadA)
	wireB := encode(encB, payloadB)
	if len(wireA) != targetWireLen || len(wireB) != targetWireLen {
		t.Fatalf("wire lengths = %d, %d; want equal bucket %d", len(wireA), len(wireB), targetWireLen)
	}
	for _, wire := range [][]byte{wireA, wireB} {
		if got := int(binary.BigEndian.Uint32(wire[:v22OuterLengthSize])) + v22OuterLengthSize; got != targetWireLen {
			t.Fatalf("outer length announces %d, want %d", got, targetWireLen)
		}
	}
	if bytes.Contains(wireA, payloadA) || bytes.Contains(wireB, payloadB) {
		t.Fatal("payload leaked outside the v2.2 ciphertext")
	}
	frameA, err := DecodeFrameV22(bytes.NewReader(wireA), decA)
	if err != nil || !bytes.Equal(frameA.Payload, payloadA) {
		t.Fatalf("decode A = %#v, %v", frameA, err)
	}
	frameB, err := DecodeFrameV22(bytes.NewReader(wireB), decB)
	if err != nil || !bytes.Equal(frameB.Payload, payloadB) {
		t.Fatalf("decode B = %#v, %v", frameB, err)
	}
}

func TestFrameV22_AuthenticatesOuterLengthAndInnerLengths(t *testing.T) {
	enc, dec := newV22FramePair(t)
	var wire bytes.Buffer
	if err := EncodeFrameV22(&wire, enc, FrameTCPData, nil, []byte("payload"), 0); err != nil {
		t.Fatal(err)
	}
	tamperedOuter := append([]byte(nil), wire.Bytes()...)
	tamperedOuter[3]--
	if _, err := DecodeFrameV22(bytes.NewReader(tamperedOuter), dec); err == nil {
		t.Fatal("outer record length tampering must fail")
	}

	enc, dec = newV22FramePair(t)
	plain := make([]byte, v22InnerHeaderSize)
	binary.BigEndian.PutUint64(plain[:v22InnerCounterLen], 0)
	plain[v22InnerCounterLen] = byte(FrameTCPData)
	payloadLenOffset := v22InnerCounterLen + v22InnerTypeLen + v22InnerMetaLen
	binary.BigEndian.PutUint32(plain[payloadLenOffset:payloadLenOffset+v22InnerPayloadLen], 1)
	malformed := v22SealForTest(t, enc, 0, plain)
	if _, err := DecodeFrameV22(bytes.NewReader(malformed), dec); !errors.Is(err, ErrFrameTooShort) {
		t.Fatalf("want encrypted length validation failure, got %v", err)
	}
}

func TestFrameV22_DefaultEncoderPadsVisibleRecordLength(t *testing.T) {
	for _, payloadLen := range []int{1, 100, 300} {
		enc, dec := newV22FramePair(t)
		payload := bytes.Repeat([]byte{0x42}, payloadLen)
		var wire bytes.Buffer
		if err := EncodeFrameV22(&wire, enc, FrameTCPData, nil, payload, 0); err != nil {
			t.Fatal(err)
		}
		rawWireLen := v22OuterLengthSize + v22InnerHeaderSize + len(payload) + chacha20poly1305.Overhead
		if wire.Len() <= rawWireLen {
			t.Fatalf("payload %d: record length %d exposes raw length %d", payloadLen, wire.Len(), rawWireLen)
		}
		frame, err := DecodeFrameV22(bytes.NewReader(wire.Bytes()), dec)
		if err != nil || !bytes.Equal(frame.Payload, payload) {
			t.Fatalf("payload %d: decode = %#v, %v", payloadLen, frame, err)
		}
	}
}

func TestFrameV22_BindsExpectedCounterBeforeDispatch(t *testing.T) {
	enc, dec := newV22FramePair(t)
	dec.counter = 1
	plain := make([]byte, v22InnerHeaderSize)
	binary.BigEndian.PutUint64(plain[:v22InnerCounterLen], 0)
	plain[v22InnerCounterLen] = byte(FrameTCPData)
	wire := v22SealForTest(t, enc, 1, plain)
	if _, err := DecodeFrameV22(bytes.NewReader(wire), dec); !errors.Is(err, ErrCounterMismatch) {
		t.Fatalf("want counter mismatch, got %v", err)
	}
}

func TestV22SessionKeysUseDistinctDomainLabels(t *testing.T) {
	var classical [X25519PubLen]byte
	var clientNonce, serverNonce [HandshakeNonce]byte
	for i := range classical {
		classical[i] = byte(i + 1)
	}
	for i := range clientNonce {
		clientNonce[i] = byte(0x20 + i)
		serverNonce[i] = byte(0x40 + i)
	}
	pqShared := bytes.Repeat([]byte{0x5a}, 32)
	v21Keys := DeriveSessionKeys(classical, pqShared, clientNonce, serverNonce)
	v22Keys := DeriveSessionKeysV22(classical, pqShared, clientNonce, serverNonce)
	if v21Keys.C2SKey == v22Keys.C2SKey || v21Keys.S2CKey == v22Keys.S2CKey {
		t.Fatal("v2.2 session keys alias v2.1 keys under identical inputs")
	}
	if _, err := NewClientSecureStreamV22(noopTransport{}, v21Keys); !errors.Is(err, ErrProtocolVersion) {
		t.Fatalf("v2.2 stream accepted v2.1 keys: %v", err)
	}
}

func TestSecureStreamV22_AutoPadsAndRejectsTrailingRecordBytes(t *testing.T) {
	var classical [X25519PubLen]byte
	var nonce [HandshakeNonce]byte
	keys := DeriveSessionKeysV22(classical, []byte("v22-test-pq-shared"), nonce, nonce)
	capture := &securityCaptureTransport{}
	stream, err := NewClientSecureStreamV22(capture, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendTCPData([]byte("x")); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	// The opening scheme forces the first two records: one data record at
	// scheme.sizes[0] and one chaff record completing scheme.sizes[1], so
	// frame count does not leak the write size.
	if len(capture.msgs) != 2 {
		capture.mu.Unlock()
		t.Fatalf("got %d records, want 2 (data + forced chaff)", len(capture.msgs))
	}
	wire := append([]byte(nil), capture.msgs[0]...)
	capture.mu.Unlock()
	// The opening phase is now shaped by the per-connection scheme
	// (opening_scheme.go): the first record must land exactly on the
	// scheme's first target wire size — a strictly stronger check than the
	// old handshake-floor minimum.
	if len(wire) != stream.scheme.sizes[0] {
		t.Fatalf("first v2.2 record wire=%d, want exact scheme target %d",
			len(wire), stream.scheme.sizes[0])
	}
	if int(binary.BigEndian.Uint32(wire[:v22OuterLengthSize]))+v22OuterLengthSize != len(wire) {
		t.Fatal("v2.2 outer length does not cover exactly one ciphertext record")
	}

	dec, err := NewFrameAEAD(keys.C2SKey, keys.C2SNonce)
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(wire, 0x7f)
	recv := &SecureStream{tr: &singleMessageTransport{msg: trailing}, version: protocolVersionV22, recv: dec}
	if _, err := recv.Recv(); err == nil {
		t.Fatal("v2.2 stream accepted trailing record bytes")
	}
}

func TestSecureStreamV22_NeverFallsBackToLegacyFrameCodec(t *testing.T) {
	var classical [X25519PubLen]byte
	var nonce [HandshakeNonce]byte
	keys := DeriveSessionKeysV22(classical, []byte("v22-test-pq-shared"), nonce, nonce)
	legacyEncoder, err := NewFrameAEAD(keys.C2SKey, keys.C2SNonce)
	if err != nil {
		t.Fatal(err)
	}
	var legacyWire bytes.Buffer
	if err := EncodeFrame(&legacyWire, legacyEncoder, FrameTCPData, nil, []byte("legacy-shape"), 0); err != nil {
		t.Fatal(err)
	}
	stream, err := NewServerSecureStreamV22(&singleMessageTransport{msg: legacyWire.Bytes()}, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("v2.2 stream accepted a legacy clear-header record")
	}
}

func TestV22HandshakePaddingNeverProducesAnOrphanLength(t *testing.T) {
	rawWireLen := v22OuterLengthSize + v22InnerHeaderSize + 1 + chacha20poly1305.Overhead
	for phase := 0; phase < handshakePhaseFrames; phase++ {
		wireLen := rawWireLen + suggestStreamPadV22(rawWireLen, phase)
		bucketed := false
		for _, bucket := range steadyBuckets {
			if wireLen >= bucket && wireLen < bucket+jitterWithinBucket {
				bucketed = true
				break
			}
		}
		if !bucketed {
			t.Fatalf("phase %d produced non-bucketed v2.2 length %d", phase, wireLen)
		}
	}
}

func TestV22DomainLabelsAreVersioned(t *testing.T) {
	for _, label := range []string{
		v22LabelOuterAEAD,
		v22LabelOuterMAC,
		v22LabelOuterAEADSalt,
		v22LabelOuterMACSalt,
		v22LabelSessionSalt,
		v22LabelC2SKey,
		v22LabelS2CKey,
		v22LabelC2SNonce,
		v22LabelS2CNonce,
		v22LabelSessionID,
		v22LabelRekey,
	} {
		if !bytes.Contains([]byte(label), []byte("ewp/v2.2")) {
			t.Fatalf("label %q is not v2.2 domain separated", label)
		}
	}
}

func v22SecurePair(t *testing.T) (*SecureStream, *SecureStream, SessionKeys) {
	t.Helper()
	uuid := fixesMustUUID(t)
	staticPriv, staticPub := genStaticIdentity(t)
	clientTr, serverTr := newMemPair()
	state, err := WriteClientHelloV22(clientTr.SendMessage, uuid, CommandTCP, Address{Domain: "v22.example", Port: 443}, staticPub)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := serverTr.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	serverHello, serverResult, err := AcceptClientHelloV22Strict(hello, MakeUUIDLookupV21([][UUIDLen]byte{uuid}), staticPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverTr.SendMessage(serverHello); err != nil {
		t.Fatal(err)
	}
	clientHello, err := clientTr.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	clientResult, err := state.ReadServerHelloV22(clientHello, staticPub)
	if err != nil {
		t.Fatal(err)
	}
	if clientResult.Keys != serverResult.Keys {
		t.Fatal("v2.2 peers derived different session keys")
	}
	client, err := NewClientSecureStreamV22(clientTr, clientResult.Keys)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV22(serverTr, serverResult.Keys)
	if err != nil {
		t.Fatal(err)
	}
	return client, server, clientResult.Keys
}

func TestSecureStreamV22_RoundTripAndRekey(t *testing.T) {
	client, server, keys := v22SecurePair(t)
	defer client.Close()
	defer server.Close()
	if _, err := NewClientSecureStream(new(noopTransport), keys); !errors.Is(err, ErrProtocolVersion) {
		t.Fatalf("legacy stream constructor must reject v2.2 keys, got %v", err)
	}
	// recvTCP skips cover/chaff frames (FramePaddingOnly) which the opening
	// scheme emits to complete its forced head; application data is what
	// this test cares about.
	recvTCP := func() *Event {
		for {
			ev, err := server.Recv()
			if err != nil {
				t.Fatalf("recv: %v", err)
			}
			if ev.Type == FramePaddingOnly {
				continue
			}
			return ev
		}
	}
	if err := client.SendTCPData([]byte("before-rekey")); err != nil {
		t.Fatal(err)
	}
	if ev := recvTCP(); string(ev.Payload) != "before-rekey" {
		t.Fatalf("before rekey = %#v", ev)
	}
	if err := client.Rekey(); err != nil {
		t.Fatal(err)
	}
	if err := client.SendTCPData([]byte("after-rekey")); err != nil {
		t.Fatal(err)
	}
	if ev := recvTCP(); string(ev.Payload) != "after-rekey" {
		t.Fatalf("after rekey = %#v", ev)
	}
}

func TestHandshakeV22_RejectsV21WithoutFallback(t *testing.T) {
	uuid := fixesMustUUID(t)
	staticPriv, staticPub := genStaticIdentity(t)
	lookup := MakeUUIDLookupV21([][UUIDLen]byte{uuid})

	v22State, err := WriteClientHelloV22(func([]byte) error { return nil }, uuid, CommandTCP, Address{Domain: "v22.example", Port: 443}, staticPub)
	if err != nil {
		t.Fatal(err)
	}
	v22Wire, err := EncodeClientHelloV22Test(v22State, staticPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcceptClientHelloV21Strict(v22Wire, lookup, staticPriv); err == nil {
		t.Fatal("v2.1 server accepted v2.2 ClientHello")
	}

	v21State, err := WriteClientHelloV21(func([]byte) error { return nil }, uuid, CommandTCP, Address{Domain: "v21.example", Port: 443}, staticPub)
	if err != nil {
		t.Fatal(err)
	}
	v21Wire, err := EncodeClientHelloV21Test(v21State, staticPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcceptClientHelloV22Strict(v21Wire, lookup, staticPriv); err == nil {
		t.Fatal("v2.2 server accepted v2.1 ClientHello")
	}
}

type v22CountingHandler struct {
	calls atomic.Int32
}

func (h *v22CountingHandler) NewConnection(context.Context, net.Conn, Metadata) error {
	h.calls.Add(1)
	return errors.New("unexpected handler invocation")
}

func (h *v22CountingHandler) NewPacketConnection(context.Context, net.PacketConn, Metadata) error {
	h.calls.Add(1)
	return errors.New("unexpected handler invocation")
}

type v22EchoHandler struct{}

func (v22EchoHandler) NewConnection(_ context.Context, conn net.Conn, _ Metadata) error {
	defer conn.Close()
	buf := make([]byte, 64)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf[:n])
	return err
}

func (v22EchoHandler) NewPacketConnection(_ context.Context, conn net.PacketConn, _ Metadata) error {
	defer conn.Close()
	buf := make([]byte, 64)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	n, source, err := conn.ReadFrom(buf)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(buf[:n], source)
	return err
}

func TestHighLevelV22_TCPAndUDPRoundTrip(t *testing.T) {
	uuid := "11112222-3333-4444-5555-666677778899"
	staticPriv, staticPub := genStaticIdentity(t)
	staticPrivB64 := base64.StdEncoding.EncodeToString(staticPriv.Bytes())
	staticPubB64 := base64.StdEncoding.EncodeToString(staticPub)

	t.Run("tcp", func(t *testing.T) {
		service, err := NewServiceV22(v22EchoHandler{}, staticPrivB64)
		if err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		if err := service.AddUser(uuid); err != nil {
			t.Fatal(err)
		}
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		go func() { _ = service.HandleConn(context.Background(), serverConn) }()
		client, err := NewClientV22(uuid, staticPubB64)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := client.DialConn(context.Background(), clientConn, Address{Domain: "tcp.v22.example", Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("v22-tcp")); err != nil {
			t.Fatal(err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "v22-tcp" {
			t.Fatalf("got %q", buf[:n])
		}
	})

	t.Run("udp", func(t *testing.T) {
		service, err := NewServiceV22(v22EchoHandler{}, staticPrivB64)
		if err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		if err := service.AddUser(uuid); err != nil {
			t.Fatal(err)
		}
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		go func() { _ = service.HandleConn(context.Background(), serverConn) }()
		client, err := NewClientV22(uuid, staticPubB64)
		if err != nil {
			t.Fatal(err)
		}
		dst := Address{Domain: "udp.v22.example", Port: 53}
		conn, err := client.DialPacketConn(context.Background(), clientConn, dst)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.(*packetConn).WriteToAddress([]byte("v22-udp"), dst); err != nil {
			t.Fatal(err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "v22-udp" {
			t.Fatalf("got %q", buf[:n])
		}
	})
}

type v22Service interface {
	AddUser(string) error
	Close() error
	HandleConn(context.Context, net.Conn) error
}

func TestHighLevelV22_VersionMismatchNeverDispatches(t *testing.T) {
	uuid := "11112222-3333-4444-5555-666677778899"
	staticPriv, staticPub := genStaticIdentity(t)
	staticPrivB64 := base64.StdEncoding.EncodeToString(staticPriv.Bytes())
	staticPubB64 := base64.StdEncoding.EncodeToString(staticPub)

	for _, tc := range []struct {
		name      string
		serverV22 bool
		newClient func() (func(context.Context, net.Conn, Address) (net.Conn, error), error)
	}{
		{
			name:      "v21-server-v22-client",
			serverV22: false,
			newClient: func() (func(context.Context, net.Conn, Address) (net.Conn, error), error) {
				client, err := NewClientV22(uuid, staticPubB64)
				if err != nil {
					return nil, err
				}
				return client.DialConn, nil
			},
		},
		{
			name:      "v22-server-v21-client",
			serverV22: true,
			newClient: func() (func(context.Context, net.Conn, Address) (net.Conn, error), error) {
				client, err := NewClientV21(uuid, staticPubB64)
				if err != nil {
					return nil, err
				}
				return client.DialConn, nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := &v22CountingHandler{}
			var service v22Service
			var err error
			if tc.serverV22 {
				service, err = NewServiceV22(handler, staticPrivB64)
			} else {
				service, err = NewServiceV21(handler, staticPrivB64)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			if err := service.AddUser(uuid); err != nil {
				t.Fatal(err)
			}
			dial, err := tc.newClient()
			if err != nil {
				t.Fatal(err)
			}
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			serverDone := make(chan error, 1)
			go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := dial(ctx, clientConn, Address{Domain: "mismatch.example", Port: 443}); err == nil {
				t.Fatal("cross-version dial unexpectedly succeeded")
			}
			select {
			case err := <-serverDone:
				if err == nil {
					t.Fatal("cross-version server unexpectedly succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("cross-version server did not terminate")
			}
			if handler.calls.Load() != 0 {
				t.Fatal("version mismatch reached application handler")
			}
		})
	}
}
