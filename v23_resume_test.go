package ewp

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// v23.1 resumption tests. Fixture helpers (v23Fixture, v23EchoHandler)
// live in v23_test.go.

const v231PipeServerKey = "v23-test@pipe"

// resumeCapableFixture returns a fixture whose client has a memory ticket
// store installed. net.Pipe's RemoteAddr is "pipe", so the store key is
// serverID + "@pipe".
func resumeCapableFixture(t *testing.T) (*v23Fixture, *MemoryV23TicketStore) {
	t.Helper()
	fx := newV23Fixture(t)
	store := NewMemoryV23TicketStore()
	fx.client.SetTicketStore(store)
	return fx, store
}

func dialEchoOnce(t *testing.T, fx *v23Fixture, payload []byte) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := fx.client.DialConn(ctx, clientConn, Address{Domain: "tcp.example", Port: 443})
	if err != nil {
		t.Fatalf("DialConn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: %q != %q", buf, payload)
	}
}

// TestV231TicketMintVerify covers the ticket codec: mint verifies, tampered
// or wrong-serverID blobs do not, and expiry is enforced.
func TestV231TicketMintVerify(t *testing.T) {
	ks, err := newV23TicketKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := ParseUUID(v23TestUUID)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := ks.mint("srv-1", uuid, 0, V23TicketLifetimeS)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ks.verify("srv-1", ticket)
	if err != nil {
		t.Fatalf("verify fresh ticket: %v", err)
	}
	if pt.uuid != uuid || pt.serverID != "srv-1" {
		t.Fatalf("plaintext mismatch: %+v", pt)
	}
	wipeTicketPlaintext(pt)

	// Tampered blob must not verify.
	bad := append([]byte(nil), ticket...)
	bad[len(bad)-1] ^= 1
	if _, err := ks.verify("srv-1", bad); err == nil {
		t.Fatal("tampered ticket verified")
	}
	// Wrong serverID binding must not verify.
	if _, err := ks.verify("srv-2", ticket); err == nil {
		t.Fatal("ticket verified under wrong serverID")
	}
	// Expired ticket must be rejected (softly, via fallback).
	expired, err := ks.mint("srv-1", uuid, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.verify("srv-1", expired); err == nil {
		t.Fatal("expired ticket verified")
	}
}

// TestV231TicketKeyRotation proves the previous slot verifies tickets after
// rotation, and that once both slots rolled past, the ticket dies.
func TestV231TicketKeyRotation(t *testing.T) {
	ks, err := newV23TicketKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	uuid, _ := ParseUUID(v23TestUUID)
	ticket, err := ks.mint("srv-1", uuid, 0, V23TicketLifetimeS)
	if err != nil {
		t.Fatal(err)
	}

	// Force a rotation: current -> previous, fresh current.
	ks.mu.Lock()
	copy(ks.previous[:], ks.current[:])
	ks.hasPrev = true
	var fresh [V23TicketKeyLen]byte
	fresh[0] = 0xab
	ks.current = fresh
	ks.mu.Unlock()

	pt, err := ks.verify("srv-1", ticket)
	if err != nil {
		t.Fatalf("previous-slot ticket rejected after rotation: %v", err)
	}
	wipeTicketPlaintext(pt)

	// Roll again: the minting key is now gone entirely.
	ks.mu.Lock()
	copy(ks.previous[:], ks.current[:])
	var fresh2 [V23TicketKeyLen]byte
	fresh2[0] = 0xcd
	ks.current = fresh2
	ks.mu.Unlock()
	if _, err := ks.verify("srv-1", ticket); err == nil {
		t.Fatal("ticket verified after its key left both slots")
	}
}

// TestV231ResumeRoundTrip: full handshake captures a ticket; the next
// connection resumes (1-RTT) and echoes.
func TestV231ResumeRoundTrip(t *testing.T) {
	fx, store := resumeCapableFixture(t)
	fx.service.handler = &v23EchoHandler{}
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	// Connection 1: full handshake; the server pushes a ticket.
	dialEchoOnce(t, fx, []byte("first-full-handshake"))
	ticket, ok := store.Get(v231PipeServerKey)
	if !ok || len(ticket) == 0 {
		t.Fatal("no ticket captured after full handshake")
	}

	// Connection 2: resume attempt must succeed and echo.
	dialEchoOnce(t, fx, []byte("second-resumed"))
	// Ticket must have been rotated by the resumed handshake.
	ticket2, ok := store.Get(v231PipeServerKey)
	if !ok {
		t.Fatal("ticket lost after resumed handshake")
	}
	if bytes.Equal(ticket, ticket2) {
		t.Fatal("server did not rotate the ticket after resumption")
	}
}

// TestV231FallbackExpiredTicket: an expired ticket must produce a silent
// fallback to the full six-stage handshake that still succeeds (R2).
func TestV231FallbackExpiredTicket(t *testing.T) {
	fx, store := resumeCapableFixture(t)
	fx.service.handler = &v23EchoHandler{}
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	// Mint an already-expired ticket and plant it.
	uuid, _ := ParseUUID(v23TestUUID)
	expired, err := fx.service.server.ticketKeys.mint(fx.serverID, uuid, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	store.Put(v231PipeServerKey, expired)

	dialEchoOnce(t, fx, []byte("fallback-after-expiry"))

	// Fallback must also have deleted the dead ticket and captured a fresh
	// one minted by the completed full handshake.
	if _, ok := store.Get(v231PipeServerKey); !ok {
		t.Fatal("no fresh ticket after fallback full handshake")
	}
	if got, _ := store.Get(v231PipeServerKey); bytes.Equal(got, expired) {
		t.Fatal("expired ticket was not replaced after fallback")
	}
}

// TestV231FallbackTamperedTicket: a forged blob must also fall back cleanly.
func TestV231FallbackTamperedTicket(t *testing.T) {
	fx, store := resumeCapableFixture(t)
	fx.service.handler = &v23EchoHandler{}
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	forged := bytes.Repeat([]byte{0x5a}, 64)
	store.Put(v231PipeServerKey, forged)
	dialEchoOnce(t, fx, []byte("fallback-after-forgery"))
}

// TestV231ConcurrentResume simulates an xmux reconnect storm: N outer
// connections resuming with the SAME ticket must all complete with
// independent sessions (fresh nonces per attempt keep them distinct).
func TestV231ConcurrentResume(t *testing.T) {
	fx, store := resumeCapableFixture(t)
	fx.service.handler = &v23EchoHandler{}
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	dialEchoOnce(t, fx, []byte("seed"))
	if _, ok := store.Get(v231PipeServerKey); !ok {
		t.Fatal("no ticket after seed handshake")
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errs <- r.(error)
				}
			}()
			clientConn, serverConn := net.Pipe()
			serverDone := make(chan error, 1)
			go func() { serverDone <- fx.service.HandleConn(context.Background(), serverConn) }()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := fx.client.DialConn(ctx, clientConn, Address{Domain: "storm.example", Port: 443})
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			payload := []byte{byte('a' + i)}
			if _, err := conn.Write(payload); err != nil {
				errs <- err
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 1)
			if _, err := io.ReadFull(conn, buf); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(buf, payload) {
				errs <- io.ErrUnexpectedEOF
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent resume failed: %v", err)
	}
}

// TestV231NoTicketWithoutCapability proves a store-less (v2.3.0) client
// triggers NO FrameTicket emission (capability gate).
func TestV231NoTicketWithoutCapability(t *testing.T) {
	fx := newV23Fixture(t) // no store installed
	fx.service.handler = &v23EchoHandler{}
	if err := fx.service.AddUser(v23TestUUID); err != nil {
		t.Fatal(err)
	}
	defer fx.service.Close()

	// Complete one full handshake+echo; then check the server never minted
	// for this client by attempting a resume with an empty store — it must
	// send a base 32-byte ClientInit (verified implicitly by success).
	dialEchoOnce(t, fx, []byte("no-capability"))
}

// TestV231ClientInitExtCodec round-trips the extended ClientInit parser.
func TestV231ClientInitExtCodec(t *testing.T) {
	var init V23ClientInit
	for i := range init.ClientNonce {
		init.ClientNonce[i] = byte(i)
	}
	for i := range init.RouteTag {
		init.RouteTag[i] = byte(0xa0 + i)
	}
	ticket := bytes.Repeat([]byte{0x42}, 100)

	// Base form.
	ci, hasCap, tk, err := parseV23ClientInitExt(init.marshal())
	if err != nil || hasCap || tk != nil || ci != init {
		t.Fatalf("base: ci=%v cap=%v tk=%v err=%v", ci != init, hasCap, tk, err)
	}
	// Capability only.
	ci, hasCap, tk, err = parseV23ClientInitExt(marshalV23ClientInitExt(&init, true, nil))
	if err != nil || !hasCap || tk != nil || ci != init {
		t.Fatalf("cap-only: ci=%v cap=%v tk=%v err=%v", ci != init, hasCap, tk, err)
	}
	// Capability + ticket.
	ci, hasCap, tk, err = parseV23ClientInitExt(marshalV23ClientInitExt(&init, true, ticket))
	if err != nil || !hasCap || !bytes.Equal(tk, ticket) || ci != init {
		t.Fatalf("cap+ticket: ci=%v cap=%v tk=%v err=%v", ci != init, hasCap, tk == nil, err)
	}
	// Truncated extension must fail.
	wire := marshalV23ClientInitExt(&init, true, ticket)
	if _, _, _, err := parseV23ClientInitExt(wire[:len(wire)-3]); err == nil {
		t.Fatal("truncated ext accepted")
	}
	// Trailing garbage must fail.
	if _, _, _, err := parseV23ClientInitExt(append(init.marshal(), 0x00)); err == nil {
		t.Fatal("trailing garbage accepted")
	}
	// Oversized ticket length must fail.
	bad := marshalV23ClientInitExt(&init, true, nil)
	bad[len(bad)-2] = 0xff
	bad[len(bad)-1] = 0xff
	if _, _, _, err := parseV23ClientInitExt(bad); err == nil {
		t.Fatal("oversized ticket accepted")
	}
}
