package ewp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------
// loopback: in-memory MessageTransport pair
// ---------------------------------------------------------------------

type loopback struct {
	rd <-chan []byte
	wr chan<- []byte
	cl func()
}

func (l *loopback) SendMessage(b []byte) error {
	cp := append([]byte(nil), b...)
	l.wr <- cp
	return nil
}
func (l *loopback) ReadMessage() ([]byte, error) {
	b, ok := <-l.rd
	if !ok {
		return nil, io.EOF
	}
	return b, nil
}
func (l *loopback) Close() error { l.cl(); return nil }

func newLoopbackPair() (a, b *loopback) {
	c1 := make(chan []byte, 64)
	c2 := make(chan []byte, 64)
	var once sync.Once
	cl := func() { once.Do(func() { close(c1); close(c2) }) }
	a = &loopback{rd: c1, wr: c2, cl: cl}
	b = &loopback{rd: c2, wr: c1, cl: cl}
	return
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

func hardRandUUID(t *testing.T) [UUIDLen]byte {
	t.Helper()
	var u [UUIDLen]byte
	if _, err := rand.Read(u[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return u
}

func hardRandKey() (k [AEADKeyLen]byte) {
	rand.Read(k[:])
	return
}

func hardRandPrefix() (p [NoncePrefixLen]byte) {
	rand.Read(p[:])
	return
}

// performHandshake runs both sides of the handshake over a loopback
// pair and returns paired SecureStreams. Used by the concurrent
// sub-session test.
func performHandshake(t *testing.T, uuid [UUIDLen]byte, addr Address) (cs, ss *SecureStream) {
	t.Helper()
	clientLB, serverLB := newLoopbackPair()
	lookup := MakeUUIDLookup([][UUIDLen]byte{uuid})

	type pair struct {
		ss  *SecureStream
		err error
	}
	srvCh := make(chan pair, 1)

	// Server side spawns first so it's ready to receive the hello.
	go func() {
		hello, err := serverLB.ReadMessage()
		if err != nil {
			srvCh <- pair{nil, err}
			return
		}
		out, res, err := AcceptClientHello(hello, lookup)
		if err != nil {
			srvCh <- pair{nil, err}
			return
		}
		if err := serverLB.SendMessage(out); err != nil {
			srvCh <- pair{nil, err}
			return
		}
		s, err := NewServerSecureStream(serverLB, res.Keys)
		srvCh <- pair{s, err}
	}()

	// Client side: WriteClientHello sends the hello synchronously
	// via the closure we hand it.
	state, err := WriteClientHello(clientLB.SendMessage, uuid, CommandUDP, addr)
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	srvHello, err := clientLB.ReadMessage()
	if err != nil {
		t.Fatalf("read srv hello: %v", err)
	}
	cli, err := state.ReadServerHello(srvHello)
	if err != nil {
		t.Fatalf("ReadServerHello: %v", err)
	}
	cs, err = NewClientSecureStream(clientLB, cli.Keys)
	if err != nil {
		t.Fatalf("NewClientSecureStream: %v", err)
	}
	srv := <-srvCh
	if srv.err != nil {
		t.Fatalf("server side: %v", srv.err)
	}
	return cs, srv.ss
}

// ---------------------------------------------------------------------
// TestHardening_HandshakeRejectsTamperedServerHello
// ---------------------------------------------------------------------
// Flip a byte in the server's hello past the magic+x25519 prefix
// (somewhere inside the ML-KEM ciphertext block). The client MUST
// reject — derived keys won't match, server-confirm AEAD will fail.
func TestHardening_HandshakeRejectsTamperedServerHello(t *testing.T) {
	uuid := hardRandUUID(t)
	lookup := MakeUUIDLookup([][UUIDLen]byte{uuid})

	clientLB, serverLB := newLoopbackPair()

	cliErr := make(chan error, 1)
	go func() {
		state, err := WriteClientHello(clientLB.SendMessage, uuid, CommandTCP,
			Address{Addr: netip.MustParseAddrPort("1.2.3.4:80")})
		if err != nil {
			cliErr <- err
			return
		}
		srvHello, err := clientLB.ReadMessage()
		if err != nil {
			cliErr <- err
			return
		}
		_, err = state.ReadServerHello(srvHello)
		cliErr <- err
	}()

	hello, err := serverLB.ReadMessage()
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	out, _, err := AcceptClientHello(hello, lookup)
	if err != nil {
		t.Fatalf("AcceptClientHello: %v", err)
	}
	// Corrupt one byte well past the X25519 + magic prefix — that
	// puts us inside ML-KEM ciphertext or the server-confirm AEAD.
	if len(out) < 200 {
		t.Fatalf("server hello unexpectedly small: %d", len(out))
	}
	out[len(out)-100] ^= 0x01
	if err := serverLB.SendMessage(out); err != nil {
		t.Fatalf("send tampered: %v", err)
	}

	select {
	case e := <-cliErr:
		if e == nil {
			t.Fatal("client accepted a tampered server hello")
		}
		t.Logf("rejected as expected: %v", e)
	case <-time.After(2 * time.Second):
		t.Fatal("client handshake hung")
	}
}

// ---------------------------------------------------------------------
// TestHardening_HandshakeRejectsForeignUUID
// ---------------------------------------------------------------------
// The server MUST reject a hello whose UUID it doesn't know — and
// must do so before performing any expensive crypto.
func TestHardening_HandshakeRejectsForeignUUID(t *testing.T) {
	known := hardRandUUID(t)
	foreign := hardRandUUID(t)
	lookup := MakeUUIDLookup([][UUIDLen]byte{known})

	var sent []byte
	state, err := WriteClientHello(func(b []byte) error {
		sent = append([]byte(nil), b...)
		return nil
	}, foreign, CommandTCP, Address{Addr: netip.MustParseAddrPort("1.2.3.4:80")})
	if err != nil {
		t.Fatalf("WriteClientHello: %v", err)
	}
	_ = state

	if _, _, err := AcceptClientHello(sent, lookup); err == nil {
		t.Fatal("AcceptClientHello accepted foreign UUID")
	}
}

// ---------------------------------------------------------------------
// TestHardening_FrameDirectionKeysAreDistinct
// ---------------------------------------------------------------------
// Encrypting with one direction's key + decrypting with the other's
// MUST fail. Otherwise an attacker who flipped src/dst could replay
// upstream frames as downstream frames or vice-versa.
func TestHardening_FrameDirectionKeysAreDistinct(t *testing.T) {
	upK := hardRandKey()
	downK := hardRandKey()
	if bytes.Equal(upK[:], downK[:]) {
		t.Fatal("rng generated identical keys (unbelievable)")
	}
	prefix := hardRandPrefix()

	enc, err := NewFrameAEAD(upK, prefix)
	if err != nil {
		t.Fatalf("enc: %v", err)
	}
	dec, err := NewFrameAEAD(downK, prefix)
	if err != nil {
		t.Fatalf("dec: %v", err)
	}

	var buf bytes.Buffer
	if err := EncodeFrame(&buf, enc, FrameTCPData, nil, []byte("hello"), 0); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := DecodeFrame(&buf, dec); err == nil {
		t.Fatal("AEAD with downlink key decoded uplink ciphertext")
	}
}

// ---------------------------------------------------------------------
// TestHardening_FrameEmptyPayload
// ---------------------------------------------------------------------
// Zero-byte UDP datagrams are legal (some game protocols send them).
// Round-trip must work without splitting into a special path.
func TestHardening_FrameEmptyPayload(t *testing.T) {
	key := hardRandKey()
	prefix := hardRandPrefix()
	enc, _ := NewFrameAEAD(key, prefix)
	dec, _ := NewFrameAEAD(key, prefix)

	var buf bytes.Buffer
	gid := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	gidMeta := gid[:]
	if err := EncodeFrame(&buf, enc, FrameUDPData, gidMeta, nil, 0); err != nil {
		t.Fatalf("encode empty: %v", err)
	}
	df, err := DecodeFrame(&buf, dec)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(df.Payload) != 0 {
		t.Fatalf("payload len=%d want 0", len(df.Payload))
	}
}

// ---------------------------------------------------------------------
// TestHardening_AddressAllForms
// ---------------------------------------------------------------------
// Round-trip every address form (v4, v6, domain) to make sure no
// codec branch is silently broken.
func TestHardening_AddressAllForms(t *testing.T) {
	cases := []Address{
		{Addr: netip.MustParseAddrPort("1.2.3.4:80")},
		{Addr: netip.MustParseAddrPort("[2001:db8::1]:443")},
		{Domain: "very-long-domain-name.example.com.", Port: 8443},
	}
	for i, in := range cases {
		buf, err := in.Append(make([]byte, 0, in.EncodedLen()))
		if err != nil {
			t.Fatalf("[%d] append: %v", i, err)
		}
		out, n, err := DecodeAddress(buf)
		if err != nil {
			t.Fatalf("[%d] decode: %v", i, err)
		}
		if n != len(buf) {
			t.Fatalf("[%d] consumed %d of %d", i, n, len(buf))
		}
		if in.Domain != "" {
			if out.Domain != in.Domain || out.Port != in.Port {
				t.Fatalf("[%d] domain rt: in=%v out=%v", i, in, out)
			}
		} else if out.Addr != in.Addr {
			t.Fatalf("[%d] addr rt: in=%v out=%v", i, in, out)
		}
	}
}

// ---------------------------------------------------------------------
// TestHardening_ConcurrentSubSessions
// ---------------------------------------------------------------------
// 16 goroutines * 50 frames each, all on the same SecureStream pair.
// The server echoes every UDP_NEW back. We verify that:
//   - Send is safe under N writers,
//   - Recv dispatches by GlobalID without cross-delivery,
//   - No frame is lost.
func TestHardening_ConcurrentSubSessions(t *testing.T) {
	const N = 16
	const Per = 50

	uuid := hardRandUUID(t)
	addr := Address{Addr: netip.MustParseAddrPort("1.1.1.1:53")}
	cs, ss := performHandshake(t, uuid, addr)

	// Server: echo every UDP_NEW back as UDP_DATA on the same gid.
	srvDone := make(chan error, 1)
	go func() {
		for i := 0; i < N*Per; i++ {
			ev, err := ss.Recv()
			if err != nil {
				srvDone <- err
				return
			}
			if ev.Type != FrameUDPNew && ev.Type != FrameUDPData {
				continue
			}
			if err := ss.SendUDPData(ev.GlobalID, addr, ev.Payload); err != nil {
				srvDone <- err
				return
			}
		}
		srvDone <- nil
	}()

	// Reader thread on the client: counts echoes per gid.
	var muCount sync.Mutex
	count := make(map[[8]byte]int)
	readDone := make(chan struct{})
	go func() {
		got := 0
		for got < N*Per {
			ev, err := cs.Recv()
			if err != nil {
				return
			}
			if ev.Type != FrameUDPData {
				continue
			}
			muCount.Lock()
			count[ev.GlobalID]++
			muCount.Unlock()
			// Cross-delivery sentinel: payload[0] must equal gid[0]-1.
			if len(ev.Payload) == 1 && int(ev.Payload[0])+1 != int(ev.GlobalID[0]) {
				t.Errorf("frame mis-delivered: gid[0]=%d payload[0]=%d", ev.GlobalID[0], ev.Payload[0])
				close(readDone)
				return
			}
			got++
		}
		close(readDone)
	}()

	// N writer goroutines.
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var gid [8]byte
			gid[0] = byte(i + 1)
			for j := 0; j < Per; j++ {
				if err := cs.SendUDPNew(gid, addr, []byte{byte(i)}); err != nil {
					t.Errorf("writer %d frame %d: %v", i, j, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("reader didn't finish")
	}

	muCount.Lock()
	defer muCount.Unlock()
	if len(count) != N {
		t.Fatalf("got %d distinct gids, want %d", len(count), N)
	}
	for gid, n := range count {
		if n != Per {
			t.Errorf("gid[0]=%d got %d echoes, want %d", gid[0], n, Per)
		}
	}

	if err := <-srvDone; err != nil && !errors.Is(err, io.EOF) {
		t.Logf("server side: %v", err)
	}
}
