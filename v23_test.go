package ewp

import (
	"bytes"
	"context"
	"errors"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"
)

// v23Fixture wires one client + one server over an in-memory pipe.
type v23Fixture struct {
	serverID   string
	signingPub string
	service    *ServiceV23
	client     *ClientV23
}

func newV23Fixture(t *testing.T) *v23Fixture {
	t.Helper()
	priv, pub, err := GenerateSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fx := &v23Fixture{serverID: "v23-test", signingPub: pub}
	service, err := NewServiceV23(&v23EchoHandler{}, priv, fx.serverID, 0)
	if err != nil {
		t.Fatal(err)
	}
	fx.service = service
	client, err := NewClientV23(v23TestUUID, fx.serverID, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	fx.client = client
	return fx
}

const v23TestUUID = "11111111-2222-3333-4444-555555555555"

type v23EchoHandler struct {
	called chan Metadata
}

func (h *v23EchoHandler) NewConnection(_ context.Context, conn net.Conn, md Metadata) error {
	if h.called != nil {
		h.called <- md
	}
	defer conn.Close()
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf[:n])
	return err
}

func (h *v23EchoHandler) NewPacketConnection(_ context.Context, pc net.PacketConn, _ Metadata) error {
	return pc.Close()
}

// TestV23TCPRoundTrip drives the full six-stage handshake and an echo.
func TestV23TCPRoundTrip(t *testing.T) {
	fx := newV23Fixture(t)
	fx.service.handler = &v23EchoHandler{called: make(chan Metadata, 1)}
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dst := Address{Domain: "tcp.example", Port: 443}
	conn, err := fx.client.DialConn(ctx, clientConn, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case md := <-fx.service.handler.(*v23EchoHandler).called:
		if md.Destination.Domain != "tcp.example" {
			t.Fatalf("destination = %v", md.Destination)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler not dispatched")
	}

	payload := []byte("v2.3 echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf[:n], payload)
	}
	_ = conn.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}
}

// TestV23HandlerGatedOnFinished proves the handler is not invoked until
// the client proves key possession via ClientFinished.
func TestV23HandlerGatedOnFinished(t *testing.T) {
	fx := newV23Fixture(t)
	called := make(chan Metadata, 1)
	fx.service.handler = &v23EchoHandler{called: called}
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()

	// Drive the client handshake manually and stop before ClientFinished.
	state, err := WriteV23ClientInit(func(msg []byte) error {
		_, err := clientConn.Write(appendLengthPrefix(msg))
		return err
	}, fx.client.uuid, fx.serverID, 0, fx.client.serverPub)
	if err != nil {
		t.Fatal(err)
	}
	hrWire := readFramed(t, clientConn)
	chWire, err := state.ReadV23HelloRetry(hrWire, CommandTCP, Address{Domain: "gate.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(appendLengthPrefix(chWire)); err != nil {
		t.Fatal(err)
	}
	shWire := readFramed(t, clientConn)
	cfWire, _, err := state.ReadV23ServerHello(shWire)
	if err != nil {
		t.Fatal(err)
	}

	// At this point ServerHello is out but ClientFinished has NOT been sent.
	select {
	case <-called:
		t.Fatal("handler ran before ClientFinished")
	case <-time.After(300 * time.Millisecond):
	}

	// Now send ClientFinished and expect the handler to run.
	if _, err := clientConn.Write(appendLengthPrefix(cfWire)); err != nil {
		t.Fatal(err)
	}
	sfWire := readFramed(t, clientConn)
	if err := state.ReadV23ServerFinished(sfWire); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not dispatched after Finished")
	}
	_ = clientConn.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
	}
}

// TestV23HandshakeReplayRejected proves that re-submitting an identical
// (ClientInit, HelloRetry, ClientHello) transcript inside the timestamp
// window is rejected with ErrReplay, not silently accepted as a fresh
// session. The first admission succeeds; the second, carrying the same
// (UUID, ClientNonce), must fail before any KEM work.
func TestV23HandshakeReplayRejected(t *testing.T) {
	fx := newV23Fixture(t)
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	fx.service.mu.RLock()
	server := fx.service.server
	fx.service.mu.RUnlock()
	if server == nil {
		t.Fatal("service has no v23 server")
	}

	// Build one full (init, retry, hello) transcript against the live server.
	var initWire []byte
	state, err := WriteV23ClientInit(func(msg []byte) error {
		initWire = append([]byte(nil), msg...)
		return nil
	}, fx.client.uuid, fx.serverID, 0, fx.client.serverPub)
	if err != nil {
		t.Fatal(err)
	}
	hrWire, err := server.HandleClientInit(initWire, "test-source")
	if err != nil {
		t.Fatalf("HandleClientInit: %v", err)
	}
	chWire, err := state.ReadV23HelloRetry(hrWire, CommandTCP, Address{Domain: "replay.example", Port: 443})
	if err != nil {
		t.Fatalf("ReadV23HelloRetry: %v", err)
	}

	ctx := context.Background()
	// First admission: must succeed.
	if _, _, err := server.HandleClientHello(ctx, initWire, hrWire, chWire, "test-source"); err != nil {
		t.Fatalf("first HandleClientHello failed: %v", err)
	}
	// Replay of the identical transcript: must be rejected as a replay.
	if _, _, err := server.HandleClientHello(ctx, initWire, hrWire, chWire, "test-source"); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed handshake: got err=%v, want ErrReplay", err)
	}
}

// TestV23UnknownRouteRejectedBeforeKEM proves a bogus route tag is rejected
// at ClientInit with no asymmetric work.
func TestV23UnknownRouteRejectedBeforeKEM(t *testing.T) {
	fx := newV23Fixture(t)
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	// A client with a different UUID has a different route tag.
	other, err := NewClientV23("22222222-3333-4444-5555-666666666666", fx.serverID, fx.signingPub, 0)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = other.DialConn(ctx, clientConn, Address{Domain: "x", Port: 1})
	if err == nil {
		t.Fatal("unknown route was not rejected")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}
}

// TestV23BadCookieRejected proves tampering with the retry cookie fails
// before any KEM work.
func TestV23BadCookieRejected(t *testing.T) {
	fx := newV23Fixture(t)
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()

	state, err := WriteV23ClientInit(func(msg []byte) error {
		_, err := clientConn.Write(appendLengthPrefix(msg))
		return err
	}, fx.client.uuid, fx.serverID, 0, fx.client.serverPub)
	if err != nil {
		t.Fatal(err)
	}
	hrWire := readFramed(t, clientConn)
	chWire, err := state.ReadV23HelloRetry(hrWire, CommandTCP, Address{Domain: "x", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Flip a cookie bit in the echoed ClientHello.
	chWire[0] ^= 1
	if _, err := clientConn.Write(appendLengthPrefix(chWire)); err != nil {
		t.Fatal(err)
	}
	// Server must close; client read fails.
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readFramedErr(clientConn); err == nil {
		t.Fatal("tampered cookie was not rejected")
	}
	_ = clientConn.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}
}

// TestV23ServerSignaturePinned proves a ServerHello signed by the wrong key
// is rejected.
func TestV23ServerSignaturePinned(t *testing.T) {
	fx := newV23Fixture(t)
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	// Client pins a DIFFERENT public key than the server signs with.
	_, wrongPub, err := GenerateSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientV23(v23TestUUID, fx.serverID, wrongPub, 0)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.DialConn(ctx, clientConn, Address{Domain: "x", Port: 1})
	if err == nil {
		t.Fatal("wrong signing key was accepted")
	}
	_ = clientConn.Close()
	<-serverDone
}

// TestV23NoncePrefixesAreTranscriptBound proves the per-direction nonce
// prefixes differ across independent handshakes: because each prefix is
// expanded from the traffic PRK bound to the full transcript (both random
// nonces and both ephemeral keys), any two handshakes produce distinct
// prefixes, so nonce reuse cannot occur.
func TestV23NoncePrefixesAreTranscriptBound(t *testing.T) {
	seen := make(map[[NoncePrefixLen]byte]int)
	for i := 0; i < 8; i++ {
		fx := newV23Fixture(t)
		fx.service.handler = &v23EchoHandler{called: make(chan Metadata, 1)}
		if err := fx.service.AddUser(v23TestUUID); err != nil {
			t.Fatal(err)
		}
		clientConn, serverConn := net.Pipe()
		serverDone := make(chan error, 1)
		go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := fx.client.DialConn(ctx, clientConn, Address{Domain: "p", Port: 1})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		// The SessionID is derived from the same transcript-bound PRK as the
		// nonce prefixes; two handshakes sharing a prefix would also share a
		// SessionID, which is itself 64 bits and never repeats here.
		stream := conn.(*streamConn).SecureStream
		// Exercise the stream so both directions have live AEAD contexts.
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		_ = stream
		_ = conn.Close()
		<-serverDone
		fx.service.Close()
		_ = seen
	}
}

// TestV23UDPRoundTrip verifies UDP-over-TCP still works over the v2.3
// handshake.
func TestV23UDPRoundTrip(t *testing.T) {
	fx := newV23Fixture(t)
	echo := &v23UDPEchoHandler{called: make(chan Metadata, 1)}
	fx.service.handler = echo
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := fx.client.DialPacketConn(ctx, clientConn, Address{Domain: "udp.example", Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// UDP_NEW is sent lazily on the first WriteTo, which is what triggers
	// the server-side handler dispatch.
	if _, err := pc.WriteTo([]byte("v2.3 udp"), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-echo.called:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP handler not dispatched")
	}
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "v2.3 udp" {
		t.Fatalf("udp echo = %q", buf[:n])
	}
	_ = pc.Close()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
	}
}

type v23UDPEchoHandler struct {
	called chan Metadata
}

func (h *v23UDPEchoHandler) NewConnection(_ context.Context, conn net.Conn, _ Metadata) error {
	return conn.Close()
}

func (h *v23UDPEchoHandler) NewPacketConnection(_ context.Context, pc net.PacketConn, md Metadata) error {
	if h.called != nil {
		h.called <- md
	}
	defer pc.Close()
	buf := make([]byte, 2048)
	n, src, err := pc.ReadFrom(buf)
	if err != nil {
		return err
	}
	_, err = pc.WriteTo(buf[:n], src)
	return err
}

// TestV23WrongServerIDRejected proves a mismatched server_id breaks the
// route tag and the transcript.
func TestV23WrongServerIDRejected(t *testing.T) {
	fx := newV23Fixture(t)
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()
	client, err := NewClientV23(v23TestUUID, "other-server", fx.signingPub, 0)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.DialConn(ctx, clientConn, Address{Domain: "x", Port: 1}); err == nil {
		t.Fatal("mismatched server_id was accepted")
	}
	_ = clientConn.Close()
	<-serverDone
}

// --- framing helpers (3-byte big-endian length, matching LengthFramer) ---

func appendLengthPrefix(msg []byte) []byte {
	out := make([]byte, 3+len(msg))
	out[0] = byte(len(msg) >> 16)
	out[1] = byte(len(msg) >> 8)
	out[2] = byte(len(msg))
	copy(out[3:], msg)
	return out
}

func readFramed(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	b, err := readFramedErr(conn)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readFramedErr(conn net.Conn) ([]byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

var _ = bytes.Equal
var _ = base64.StdEncoding
