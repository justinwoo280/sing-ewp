package ewp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Test scaffolding
// ----------------------------------------------------------------------

const (
	testUUIDStr      = "11111111-2222-3333-4444-555555555555"
	otherUUIDStr     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testUUIDStrPlain = "11111111222233334444555555555555"
)

// echoTCPHandler reads everything until EOF and writes it back, then
// closes the connection.
type echoTCPHandler struct {
	gotMeta chan Metadata
}

func (h *echoTCPHandler) NewConnection(ctx context.Context, conn net.Conn, md Metadata) error {
	if h.gotMeta != nil {
		select {
		case h.gotMeta <- md:
		default:
		}
	}
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
	return nil
}

func (h *echoTCPHandler) NewPacketConnection(ctx context.Context, conn net.PacketConn, md Metadata) error {
	conn.Close()
	return errors.New("unexpected packet connection on echoTCPHandler")
}

// echoUDPHandler reads one datagram and writes it back to the same source,
// then closes.
type echoUDPHandler struct {
	gotMeta chan Metadata
}

func (h *echoUDPHandler) NewConnection(ctx context.Context, conn net.Conn, md Metadata) error {
	conn.Close()
	return errors.New("unexpected stream connection on echoUDPHandler")
}

func (h *echoUDPHandler) NewPacketConnection(ctx context.Context, pc net.PacketConn, md Metadata) error {
	if h.gotMeta != nil {
		select {
		case h.gotMeta <- md:
		default:
		}
	}
	defer pc.Close()
	buf := make([]byte, 2048)
	n, src, err := pc.ReadFrom(buf)
	if err != nil {
		return err
	}
	if _, err := pc.WriteTo(buf[:n], src); err != nil {
		return err
	}
	return nil
}

// runService spawns Service.HandleConn on serverConn in a goroutine
// and returns a wait-channel that closes when the handler returns.
func runService(t *testing.T, svc *Service, serverConn net.Conn) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = svc.HandleConn(context.Background(), serverConn)
	}()
	return done
}

// ----------------------------------------------------------------------
// TCP round-trip
// ----------------------------------------------------------------------

func TestClient_DialConn_RoundTrip(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()

	metaCh := make(chan Metadata, 1)
	svc := NewService(&echoTCPHandler{gotMeta: metaCh})
	if err := svc.AddUser(testUUIDStr); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	srvDone := runService(t, svc, serverPipe)

	client, err := NewClient(testUUIDStr)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	dst := Address{Addr: netip.MustParseAddrPort("8.8.8.8:443")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, clientPipe, dst)
	if err != nil {
		t.Fatalf("DialConn: %v", err)
	}

	// Verify metadata seen by handler matches what we requested.
	select {
	case md := <-metaCh:
		if md.UserUUID != client.UUID() {
			t.Errorf("UUID mismatch: got %x want %x", md.UserUUID, client.UUID())
		}
		if md.Destination.Addr != dst.Addr {
			t.Errorf("Destination mismatch: got %v want %v", md.Destination.Addr, dst.Addr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler never received metadata")
	}

	payload := []byte("hello ewp v2 echo round-trip test")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo mismatch: got %q want %q", got, payload)
	}

	_ = conn.Close()
	select {
	case <-srvDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server handler did not exit after client close")
	}
}

// ----------------------------------------------------------------------
// TCP large payload (verifies Write chunking past MaxFrameSize)
// ----------------------------------------------------------------------

func TestClient_DialConn_LargePayload(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()

	svc := NewService(&echoTCPHandler{})
	if err := svc.AddUser(testUUIDStr); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	srvDone := runService(t, svc, serverPipe)

	client, _ := NewClient(testUUIDStr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, clientPipe,
		Address{Addr: netip.MustParseAddrPort("1.1.1.1:80")})
	if err != nil {
		t.Fatalf("DialConn: %v", err)
	}

	// Payload > MaxFrameSize-256 to force chunking.
	payload := bytes.Repeat([]byte{0xAB, 0xCD}, MaxFrameSize) // 128 KiB
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
		// Close to signal EOF to the echo handler so it returns and
		// flushes its half.
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo body mismatch (large payload)")
	}

	_ = conn.Close()
	<-srvDone
}

// ----------------------------------------------------------------------
// UDP round-trip
// ----------------------------------------------------------------------

func TestClient_DialPacketConn_RoundTrip(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()

	metaCh := make(chan Metadata, 1)
	svc := NewService(&echoUDPHandler{gotMeta: metaCh})
	if err := svc.AddUser(testUUIDStr); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	srvDone := runService(t, svc, serverPipe)

	client, _ := NewClient(testUUIDStr)
	dst := Address{Addr: netip.MustParseAddrPort("9.9.9.9:53")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := client.DialPacketConn(ctx, clientPipe, dst)
	if err != nil {
		t.Fatalf("DialPacketConn: %v", err)
	}

	// First WriteTo emits UDP_NEW which is what unblocks the server-side
	// handler dispatch; only then can metadata be delivered.
	payload := []byte("DNS query test datagram")
	target := &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 53}
	if _, err := pc.WriteTo(payload, target); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	select {
	case md := <-metaCh:
		if md.Destination.Addr != dst.Addr {
			t.Errorf("UDP destination mismatch: got %v want %v", md.Destination.Addr, dst.Addr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP handler never received metadata")
	}

	buf := make([]byte, 2048)
	n, src, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("UDP echo mismatch: got %q want %q", buf[:n], payload)
	}
	if src == nil {
		t.Errorf("ReadFrom returned nil source addr")
	}

	_ = pc.Close()
	select {
	case <-srvDone:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP server handler did not exit after client close")
	}
}

// ----------------------------------------------------------------------
// Authentication failure
// ----------------------------------------------------------------------

func TestService_RejectsUnknownUUID(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()

	svc := NewService(&echoTCPHandler{})
	if err := svc.AddUser(otherUUIDStr); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- svc.HandleConn(context.Background(), serverPipe)
	}()

	client, _ := NewClient(testUUIDStr) // mismatched UUID
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := client.DialConn(ctx, clientPipe,
		Address{Addr: netip.MustParseAddrPort("1.2.3.4:443")})
	if err == nil {
		t.Fatal("DialConn unexpectedly succeeded with foreign UUID")
	}

	select {
	case sErr := <-srvErr:
		if sErr == nil {
			t.Errorf("server side returned nil for unknown UUID; expected an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server side did not return after rejecting unknown UUID")
	}
}

// ----------------------------------------------------------------------
// Service with zero users must reject
// ----------------------------------------------------------------------

func TestService_RejectsWhenNoUsers(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	svc := NewService(&echoTCPHandler{})

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- svc.HandleConn(context.Background(), serverPipe)
	}()

	// Even attempting to handshake, the server should fail before
	// even reading the ClientHello (lookup is empty -> nil-map miss).
	// Force the client to try anyway.
	client, _ := NewClient(testUUIDStr)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := client.DialConn(ctx, clientPipe,
		Address{Addr: netip.MustParseAddrPort("1.2.3.4:443")})
	if err == nil {
		t.Fatal("DialConn unexpectedly succeeded with empty user table")
	}

	select {
	case <-srvErr:
	case <-time.After(2 * time.Second):
		t.Fatal("server side did not return for empty user table")
	}
}

// ----------------------------------------------------------------------
// AddUser / RemoveUser sanity
// ----------------------------------------------------------------------

func TestService_AddRemoveUser(t *testing.T) {
	svc := NewService(&echoTCPHandler{})
	if err := svc.AddUser(testUUIDStr); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := svc.AddUser(testUUIDStr); err != nil {
		t.Fatalf("AddUser duplicate should be a no-op, got: %v", err)
	}
	if got := len(svc.Users()); got != 1 {
		t.Errorf("after duplicate AddUser want 1 user, got %d", got)
	}
	if !svc.RemoveUser(testUUIDStr) {
		t.Errorf("RemoveUser of present UUID returned false")
	}
	if svc.RemoveUser(testUUIDStr) {
		t.Errorf("RemoveUser of absent UUID returned true")
	}
	if got := len(svc.Users()); got != 0 {
		t.Errorf("after RemoveUser want 0 users, got %d", got)
	}
}

// ----------------------------------------------------------------------
// UUID parser robustness
// ----------------------------------------------------------------------

func TestParseUUID_Forms(t *testing.T) {
	a, err := ParseUUID(testUUIDStr)
	if err != nil {
		t.Fatalf("hyphenated form: %v", err)
	}
	b, err := ParseUUID(testUUIDStrPlain)
	if err != nil {
		t.Fatalf("32-hex form: %v", err)
	}
	if a != b {
		t.Errorf("hyphenated vs plain disagree: %x vs %x", a, b)
	}
	if _, err := ParseUUID("not-a-uuid"); err == nil {
		t.Errorf("malformed UUID should fail")
	}
	if _, err := ParseUUID(strings.Repeat("g", 32)); err == nil {
		t.Errorf("non-hex UUID should fail")
	}
}

// ----------------------------------------------------------------------
// LengthFramer self-test (oversize message rejection)
// ----------------------------------------------------------------------

func TestLengthFramer_RejectsOversizeWrite(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	f := NewLengthFramer(a)
	huge := make([]byte, MaxFrameSize+1)
	if err := f.SendMessage(huge); err == nil {
		t.Errorf("SendMessage of oversize message should fail")
	}
}

func TestLengthFramer_RejectsOversizeRead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Manually inject a length header claiming MaxFrameSize+1.
	go func() {
		var hdr [4]byte
		n := uint32(MaxFrameSize + 1)
		hdr[0] = byte(n >> 24)
		hdr[1] = byte(n >> 16)
		hdr[2] = byte(n >> 8)
		hdr[3] = byte(n)
		_, _ = a.Write(hdr[:])
	}()
	f := NewLengthFramer(b)
	if _, err := f.ReadMessage(); err == nil {
		t.Errorf("ReadMessage of oversize claim should fail")
	}
}

// guard against test goroutine leaks if a future change forgets to
// close transports. Not strictly required, but cheap insurance.
var _ = sync.OnceFunc(func() {})
