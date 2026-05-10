package ewp

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Address codec
// ----------------------------------------------------------------------

func TestAddress_RoundTrip(t *testing.T) {
	cases := []Address{
		{Addr: netip.MustParseAddrPort("1.2.3.4:443")},
		{Addr: netip.MustParseAddrPort("[2001:db8::1]:53")},
		{Domain: "example.com", Port: 443},
		{Domain: "a.very-long-subdomain.example.test", Port: 8080},
	}
	for _, in := range cases {
		buf, err := in.Append(nil)
		if err != nil {
			t.Fatalf("Append(%v): %v", in, err)
		}
		got, n, err := DecodeAddress(buf)
		if err != nil {
			t.Fatalf("Decode(%x): %v", buf, err)
		}
		if n != len(buf) {
			t.Fatalf("Decode consumed %d, want %d (%x)", n, len(buf), buf)
		}
		if got.IsDomain() != in.IsDomain() ||
			got.Domain != in.Domain ||
			got.Port != in.Port ||
			got.Addr != in.Addr {
			t.Fatalf("round trip mismatch: in=%+v out=%+v", in, got)
		}
	}
}

func TestAddress_RejectsBadType(t *testing.T) {
	_, _, err := DecodeAddress([]byte{0xff, 0, 0, 0})
	if !errors.Is(err, ErrAddrType) {
		t.Fatalf("want ErrAddrType, got %v", err)
	}
}

// ----------------------------------------------------------------------
// Handshake round trip
// ----------------------------------------------------------------------

var testUUID = [UUIDLen]byte{
	0x55, 0x53, 0x45, 0x52, 0x55, 0x55, 0x49, 0x44,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
}

func TestHandshake_RoundTrip(t *testing.T) {
	addr := Address{Addr: netip.MustParseAddrPort("8.8.8.8:443")}

	var sentToServer []byte
	clientSend := func(b []byte) error {
		sentToServer = append([]byte(nil), b...)
		return nil
	}

	state, err := WriteClientHello(clientSend, testUUID, CommandTCP, addr)
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}

	helloOut, srvResult, err := AcceptClientHello(sentToServer, MakeUUIDLookup([][UUIDLen]byte{testUUID}))
	if err != nil {
		t.Fatalf("AcceptClientHello: %v", err)
	}
	if srvResult.ClientHello.UUID != testUUID {
		t.Fatalf("server saw wrong UUID")
	}
	if srvResult.ClientHello.Command != CommandTCP {
		t.Fatalf("server saw wrong command")
	}
	if !srvResult.ClientHello.Address.Addr.IsValid() ||
		srvResult.ClientHello.Address.Addr != addr.Addr {
		t.Fatalf("server saw wrong addr: %+v", srvResult.ClientHello.Address)
	}

	clientResult, err := state.ReadServerHello(helloOut)
	if err != nil {
		t.Fatalf("ReadServerHello: %v", err)
	}

	// Both sides must end up with the same key material.
	if clientResult.Keys.C2SKey != srvResult.Keys.C2SKey {
		t.Fatal("C2S key mismatch")
	}
	if clientResult.Keys.S2CKey != srvResult.Keys.S2CKey {
		t.Fatal("S2C key mismatch")
	}
	if clientResult.Keys.C2SNonce != srvResult.Keys.C2SNonce {
		t.Fatal("C2S nonce prefix mismatch")
	}
	if clientResult.Keys.S2CNonce != srvResult.Keys.S2CNonce {
		t.Fatal("S2C nonce prefix mismatch")
	}
}

// TestHandshake_TamperedLeadingBytesRejected replaces the legacy
// "bad magic" test: v2 has no plaintext magic, so flipping the very
// first byte now corrupts the nonce field. The outer MAC is computed
// over the entire on-wire message, so any single-bit flip at any
// position MUST cause the server to reject the ClientHello.
func TestHandshake_TamperedLeadingBytesRejected(t *testing.T) {
	addr := Address{Addr: netip.MustParseAddrPort("1.1.1.1:443")}
	var captured []byte
	if _, err := WriteClientHello(func(b []byte) error {
		captured = append([]byte(nil), b...)
		return nil
	}, testUUID, CommandTCP, addr); err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	captured[0] ^= 0xff // corrupt the very first byte of the nonce

	_, _, err := AcceptClientHello(captured, MakeUUIDLookup([][UUIDLen]byte{testUUID}))
	if err == nil {
		t.Fatal("server accepted tampered ClientHello")
	}
}

func TestHandshake_UnknownUUIDRejected(t *testing.T) {
	addr := Address{Addr: netip.MustParseAddrPort("1.1.1.1:443")}
	var captured []byte
	if _, err := WriteClientHello(func(b []byte) error {
		captured = append([]byte(nil), b...)
		return nil
	}, testUUID, CommandTCP, addr); err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	other := [UUIDLen]byte{0x99}
	_, _, err := AcceptClientHello(captured, MakeUUIDLookup([][UUIDLen]byte{other}))
	if !errors.Is(err, ErrUnknownUUID) {
		t.Fatalf("want ErrUnknownUUID, got %v", err)
	}
}

func TestHandshake_TimestampWindow(t *testing.T) {
	// Build a hello whose timestamp is far in the past, then confirm the
	// server rejects it. We do this by intercepting WriteClientHello's
	// internal state and re-encoding with a back-dated timestamp.
	addr := Address{Addr: netip.MustParseAddrPort("1.1.1.1:443")}
	state, err := WriteClientHello(func(b []byte) error { return nil }, testUUID, CommandTCP, addr)
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	state.hello.Timestamp = uint32(time.Now().Add(-1 * time.Hour).Unix())
	patched, err := EncodeClientHello(state.hello)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	_, _, err = AcceptClientHello(patched, MakeUUIDLookup([][UUIDLen]byte{testUUID}))
	// Post-fix: timestamp-out-of-window is unified onto ErrReplay so
	// network observers cannot distinguish "your clock is wrong" from
	// "I have already seen this exact ClientHello". Either failure is
	// equally fatal to the handshake; merging removes a side-channel
	// oracle. See audit_fixes_test.go::TestFix_M4_ReplayAndSkew_Indistinguishable.
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("want ErrReplay (unified skew/replay error), got %v", err)
	}
}

// ----------------------------------------------------------------------
// Frame round trip and counter discipline
// ----------------------------------------------------------------------

func newPair(t *testing.T) (*FrameAEAD, *FrameAEAD) {
	t.Helper()
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
		t.Fatalf("NewFrameAEAD a: %v", err)
	}
	// Same key/prefix on both sides — this is intentional for the
	// frame-only test (the SecureStream test below uses a real
	// handshake).
	b, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatalf("NewFrameAEAD b: %v", err)
	}
	return a, b
}

func TestFrame_RoundTrip(t *testing.T) {
	enc, dec := newPair(t)
	var buf bytes.Buffer

	for i := 0; i < 5; i++ {
		payload := []byte("hello-frame-")
		payload = append(payload, byte('0'+i))
		if err := EncodeFrame(&buf, enc, FrameTCPData, nil, payload, 16); err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
	}

	for i := 0; i < 5; i++ {
		df, err := DecodeFrame(&buf, dec)
		if err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		want := append([]byte("hello-frame-"), byte('0'+i))
		if !bytes.Equal(df.Payload, want) {
			t.Fatalf("decode %d: payload=%q want=%q", i, df.Payload, want)
		}
		if df.Counter != uint64(i) {
			t.Fatalf("decode %d: counter=%d want=%d", i, df.Counter, i)
		}
	}
}

func TestFrame_RejectsReplay(t *testing.T) {
	enc, dec := newPair(t)
	var buf bytes.Buffer

	if err := EncodeFrame(&buf, enc, FrameTCPData, nil, []byte("hello"), 0); err != nil {
		t.Fatalf("encode: %v", err)
	}
	wire := append([]byte(nil), buf.Bytes()...)

	if _, err := DecodeFrame(bytes.NewReader(wire), dec); err != nil {
		t.Fatalf("first decode: %v", err)
	}
	// Feed the same bytes again — receiver expects counter 1, sees 0.
	_, err := DecodeFrame(bytes.NewReader(wire), dec)
	if !errors.Is(err, ErrCounterMismatch) {
		t.Fatalf("want ErrCounterMismatch on replay, got %v", err)
	}
}

func TestFrame_RejectsTampering(t *testing.T) {
	enc, dec := newPair(t)
	var buf bytes.Buffer
	if err := EncodeFrame(&buf, enc, FrameTCPData, nil, []byte("payload-here"), 8); err != nil {
		t.Fatalf("encode: %v", err)
	}
	wire := buf.Bytes()
	// Flip a byte inside the ciphertext region (skip the first 15B
	// header, then we know the AEAD body sits before the trailing pad).
	wire[20] ^= 0x01
	_, err := DecodeFrame(bytes.NewReader(wire), dec)
	if !errors.Is(err, ErrAEADOpen) {
		t.Fatalf("want ErrAEADOpen on tampered byte, got %v", err)
	}
}

// ----------------------------------------------------------------------
// SecureStream end-to-end (in-memory transport)
// ----------------------------------------------------------------------

// memTransport pairs two sides via two channels and implements
// MessageTransport for both.
type memTransport struct {
	in  chan []byte
	out chan []byte

	mu     sync.Mutex
	closed bool
}

func newMemPair() (*memTransport, *memTransport) {
	a2b := make(chan []byte, 64)
	b2a := make(chan []byte, 64)
	return &memTransport{in: b2a, out: a2b}, &memTransport{in: a2b, out: b2a}
}

func (m *memTransport) SendMessage(b []byte) error {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return errors.New("memTransport closed")
	}
	cp := append([]byte(nil), b...)
	select {
	case m.out <- cp:
		return nil
	default:
		return errors.New("memTransport buffer full")
	}
}

func (m *memTransport) ReadMessage() ([]byte, error) {
	b, ok := <-m.in
	if !ok {
		return nil, errors.New("memTransport closed")
	}
	return b, nil
}

func (m *memTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	close(m.out)
	return nil
}

func TestSecureStream_TCPDataRoundTrip(t *testing.T) {
	clientTr, serverTr := newMemPair()

	// Client writes ClientHello.
	state, err := WriteClientHello(clientTr.SendMessage, testUUID, CommandTCP,
		Address{Addr: netip.MustParseAddrPort("1.2.3.4:443")})
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	helloIn, err := serverTr.ReadMessage()
	if err != nil {
		t.Fatalf("server ReadMessage: %v", err)
	}
	srvHelloOut, srvRes, err := AcceptClientHello(helloIn, MakeUUIDLookup([][UUIDLen]byte{testUUID}))
	if err != nil {
		t.Fatalf("AcceptClientHello: %v", err)
	}
	if err := serverTr.SendMessage(srvHelloOut); err != nil {
		t.Fatalf("server SendMessage(SH): %v", err)
	}
	shBytes, err := clientTr.ReadMessage()
	if err != nil {
		t.Fatalf("client ReadMessage(SH): %v", err)
	}
	cliRes, err := state.ReadServerHello(shBytes)
	if err != nil {
		t.Fatalf("ReadServerHello: %v", err)
	}

	// Build SecureStreams.
	cli, err := NewClientSecureStream(clientTr, cliRes.Keys)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServerSecureStream(serverTr, srvRes.Keys)
	if err != nil {
		t.Fatal(err)
	}

	// Client → server.
	if err := cli.SendTCPData([]byte("hello v2")); err != nil {
		t.Fatalf("cli send: %v", err)
	}
	ev, err := srv.Recv()
	if err != nil {
		t.Fatalf("srv recv: %v", err)
	}
	if ev.Type != FrameTCPData || string(ev.Payload) != "hello v2" {
		t.Fatalf("server got %+v", ev)
	}

	// Server → client.
	if err := srv.SendTCPData([]byte("hi back")); err != nil {
		t.Fatalf("srv send: %v", err)
	}
	ev, err = cli.Recv()
	if err != nil {
		t.Fatalf("cli recv: %v", err)
	}
	if ev.Type != FrameTCPData || string(ev.Payload) != "hi back" {
		t.Fatalf("client got %+v", ev)
	}

	cli.Close()
	srv.Close()
}

func TestSecureStream_UDPSubsessions(t *testing.T) {
	clientTr, serverTr := newMemPair()
	state, err := WriteClientHello(clientTr.SendMessage, testUUID, CommandUDP,
		Address{Addr: netip.MustParseAddrPort("8.8.8.8:53")})
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	hi, _ := serverTr.ReadMessage()
	srvHelloOut, srvRes, err := AcceptClientHello(hi, MakeUUIDLookup([][UUIDLen]byte{testUUID}))
	if err != nil {
		t.Fatalf("AcceptClientHello: %v", err)
	}
	_ = serverTr.SendMessage(srvHelloOut)
	sh, _ := clientTr.ReadMessage()
	cliRes, err := state.ReadServerHello(sh)
	if err != nil {
		t.Fatalf("ReadServerHello: %v", err)
	}

	cli, _ := NewClientSecureStream(clientTr, cliRes.Keys)
	srv, _ := NewServerSecureStream(serverTr, srvRes.Keys)

	gid := NewGlobalID()
	target := Address{Addr: netip.MustParseAddrPort("9.9.9.9:53")}

	if err := cli.SendUDPNew(gid, target, []byte("dns-query")); err != nil {
		t.Fatalf("SendUDPNew: %v", err)
	}
	ev, err := srv.Recv()
	if err != nil {
		t.Fatalf("srv Recv: %v", err)
	}
	if ev.Type != FrameUDPNew || ev.GlobalID != gid || !ev.HasAddr || ev.Address.Addr != target.Addr {
		t.Fatalf("UDP_NEW unexpected: %+v", ev)
	}
	if string(ev.Payload) != "dns-query" {
		t.Fatalf("payload mismatch: %q", ev.Payload)
	}

	// Server replies with a UDP_DATA bearing a *different* real-remote
	// to simulate a STUN-style reflective response.
	reflected := Address{Addr: netip.MustParseAddrPort("203.0.113.7:55555")}
	if err := srv.SendUDPData(gid, reflected, []byte("dns-answer")); err != nil {
		t.Fatalf("srv SendUDPData: %v", err)
	}
	ev, err = cli.Recv()
	if err != nil {
		t.Fatalf("cli Recv: %v", err)
	}
	if ev.Type != FrameUDPData || ev.GlobalID != gid || !ev.HasAddr {
		t.Fatalf("UDP_DATA unexpected: %+v", ev)
	}
	if ev.Address.Addr != reflected.Addr {
		t.Fatalf("real-remote not preserved: got %v want %v", ev.Address.Addr, reflected.Addr)
	}

	// Server cleanly tears down.
	if err := srv.SendUDPEnd(gid); err != nil {
		t.Fatalf("SendUDPEnd: %v", err)
	}
	ev, err = cli.Recv()
	if err != nil {
		t.Fatalf("cli Recv UDP_END: %v", err)
	}
	if ev.Type != FrameUDPEnd || ev.GlobalID != gid {
		t.Fatalf("UDP_END unexpected: %+v", ev)
	}

	cli.Close()
	srv.Close()
}

// TestNoPlaintextOnWire — corresponds to spec §8.1. Inspect every wire
// message after the handshake and assert no recognizable plaintext
// substrings appear.
func TestNoPlaintextOnWire(t *testing.T) {
	clientTr, serverTr := newMemPair()
	state, err := WriteClientHello(clientTr.SendMessage, testUUID, CommandTCP,
		Address{Addr: netip.MustParseAddrPort("1.2.3.4:443")})
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	hi, _ := serverTr.ReadMessage()
	srvHelloOut, srvRes, _ := AcceptClientHello(hi, MakeUUIDLookup([][UUIDLen]byte{testUUID}))
	_ = serverTr.SendMessage(srvHelloOut)
	sh, _ := clientTr.ReadMessage()
	cliRes, _ := state.ReadServerHello(sh)

	cli, _ := NewClientSecureStream(clientTr, cliRes.Keys)
	srv, _ := NewServerSecureStream(serverTr, srvRes.Keys)

	plaintext := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nSECRET-COOKIE-1234")
	if err := cli.SendTCPData(plaintext); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Drain wire on the server side: read the message that was just
	// written, BEFORE handing it to Recv (which would decrypt it).
	wire, err := serverTr.ReadMessage()
	if err != nil {
		t.Fatalf("serverTr.ReadMessage: %v", err)
	}
	for _, needle := range [][]byte{
		[]byte("GET "),
		[]byte("HTTP/"),
		[]byte("Host: example.com"),
		[]byte("SECRET-COOKIE-1234"),
	} {
		if bytes.Contains(wire, needle) {
			t.Fatalf("plaintext leaked on wire: %q", needle)
		}
	}

	cli.Close()
	srv.Close()
}
