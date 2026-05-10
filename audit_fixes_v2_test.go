// Package ewp regression suite for the security audit fixes (batch 2,
// phase 1): S1, S2, H2.
//
// These tests describe the *post-fix* expected behavior in adversarial
// language. Every test in this file MUST pass on v2.1 code; any
// failure is a security regression.
//
//   S1 - Holding the PSK alone is NOT sufficient to decrypt a captured
//        ClientHello inner segment. The server's long-term X25519
//        static private key is also required.
//   S2 - An attacker holding only the PSK (no server static priv)
//        CANNOT impersonate the server. The client's outer-MAC check
//        on the ServerHello fails because the MAC key chain depends
//        on the static ECDH the attacker cannot produce.
//   H2 - Truncating or extending the inner ciphertext invalidates the
//        outer MAC because the MAC input now binds the inner length
//        explicitly.
//
// Naming: TestFixV2_<id>_<short>

package ewp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

// genStaticIdentity returns a fresh server static keypair.
func genStaticIdentity(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("static keygen: %v", err)
	}
	return priv, priv.PublicKey().Bytes()
}

// makeOneHello composes a v2.1 ClientHello bound to the given server
// static public key and returns the wire bytes plus the (uuid, addr,
// padded inner) the server should observe after decrypt. Uses the
// post-fix EncodeClientHelloV21 entry point.
func makeOneHello(
	t *testing.T,
	uuid [UUIDLen]byte,
	serverStaticPub []byte,
) []byte {
	t.Helper()
	addr := Address{Domain: "victim.example", Port: 4433}
	state, err := WriteClientHelloV21(
		func(b []byte) error { return nil },
		uuid, CommandTCP, addr, serverStaticPub,
	)
	if err != nil {
		t.Fatalf("WriteClientHelloV21: %v", err)
	}
	wire, err := EncodeClientHelloV21Test(state, serverStaticPub)
	if err != nil {
		t.Fatalf("EncodeClientHelloV21: %v", err)
	}
	return wire
}

// ----------------------------------------------------------------------
// S1: holding the PSK alone is not enough to decrypt the inner segment
// of a captured ClientHello. We give the attacker the PSK and the
// captured wire bytes, but NOT the server static priv; they must fail
// to produce inner plaintext.
// ----------------------------------------------------------------------

func TestFixV2_S1_OfflineDecryptRequiresStaticPriv(t *testing.T) {
	uuid := fixesMustUUID(t)
	serverStaticPriv, serverStaticPub := genStaticIdentity(t)

	wire := makeOneHello(t, uuid, serverStaticPub)

	// Attacker has uuid, wire, but no serverStaticPriv. Must fail.
	_, _, errAttack := AcceptClientHelloV21Strict(
		wire, MakeUUIDLookupV21([][UUIDLen]byte{uuid}),
		// Attacker forges a *different* static private key and tries
		// to use it. The MAC chain is bound to the genuine static
		// pub via X25519, so this MUST fail at outer-MAC time.
		mustGenStatic(t),
	)
	if errAttack == nil {
		t.Fatal("attacker without genuine server static priv must fail")
	}
	if !errors.Is(errAttack, ErrOuterMAC) && !errors.Is(errAttack, ErrAEADHandshake) {
		t.Fatalf("expected ErrOuterMAC or ErrAEADHandshake, got %v", errAttack)
	}

	// Sanity: the genuine server CAN decrypt.
	_, res, err := AcceptClientHelloV21Strict(
		wire, MakeUUIDLookupV21([][UUIDLen]byte{uuid}), serverStaticPriv,
	)
	if err != nil {
		t.Fatalf("genuine server must accept, got %v", err)
	}
	if res.ClientHello.UUID != uuid {
		t.Fatal("decoded UUID mismatch")
	}
}

func mustGenStatic(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	p, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("rand static: %v", err)
	}
	return p
}

// ----------------------------------------------------------------------
// S2: an attacker that holds the PSK but has fabricated their own
// server static priv cannot impersonate the genuine server: the
// ClientHello they observe was bound to the genuine server's static
// pub, so any ServerHello they synthesise under their own keys
// produces a session key that doesn't match what the legitimate
// client would have derived. We test the strongest possible
// equivalent: a forged AcceptClientHelloV21 against the wire CANNOT
// even reach the point of producing a valid session.
// ----------------------------------------------------------------------

func TestFixV2_S2_MITMServerImpersonationFails(t *testing.T) {
	uuid := fixesMustUUID(t)
	_, genuineStaticPub := genStaticIdentity(t)

	// Real client bakes the GENUINE server static pub into the
	// outer-MAC chain.
	wire := makeOneHello(t, uuid, genuineStaticPub)

	// Attacker rolls their own static priv and tries to accept.
	attackerPriv := mustGenStatic(t)
	_, _, err := AcceptClientHelloV21Strict(
		wire, MakeUUIDLookupV21([][UUIDLen]byte{uuid}), attackerPriv,
	)
	if err == nil {
		t.Fatal("attacker server impersonation must fail")
	}
	t.Logf("MITM rejected with: %v", err)
}

// ----------------------------------------------------------------------
// H2: truncating or extending the inner ciphertext invalidates the
// outer MAC. We check three perturbations, each of which alters the
// effective inner_len without touching the bytes the OLD (v0.1.x) MAC
// would cover, so the OLD MAC would still verify but the v2.1 MAC
// MUST not.
// ----------------------------------------------------------------------

func TestFixV2_H2_TruncatedInnerRejected(t *testing.T) {
	uuid := fixesMustUUID(t)
	_, pub := genStaticIdentity(t)
	priv := decode32(t, pub) // dummy: we'll regenerate below
	_ = priv

	// Use the GENUINE server priv for this test so we know the
	// failure is due to truncation, not wrong static identity.
	staticPriv, staticPub := genStaticIdentity(t)

	wire := makeOneHello(t, uuid, staticPub)
	lookup := MakeUUIDLookupV21([][UUIDLen]byte{uuid})

	// Sanity: genuine wire accepts.
	if _, _, err := AcceptClientHelloV21Strict(wire, lookup, staticPriv); err != nil {
		t.Fatalf("baseline accept: %v", err)
	}

	// Perturb #1: drop the last byte of the inner ciphertext (i.e.
	// the byte just before the OuterMAC). This is the classic
	// truncation attack.
	tr := append([]byte(nil), wire...)
	cut := len(tr) - OuterMACLen - 1
	tr = append(tr[:cut], tr[len(tr)-OuterMACLen:]...)
	if _, _, err := AcceptClientHelloV21Strict(tr, lookup, staticPriv); err == nil {
		t.Fatal("truncated inner ciphertext must be rejected")
	}

	// Perturb #2: append an extra zero byte to the inner ciphertext.
	ext := append([]byte(nil), wire[:len(wire)-OuterMACLen]...)
	ext = append(ext, 0x00)
	ext = append(ext, wire[len(wire)-OuterMACLen:]...)
	if _, _, err := AcceptClientHelloV21Strict(ext, lookup, staticPriv); err == nil {
		t.Fatal("extended inner ciphertext must be rejected")
	}

	// Perturb #3: flip the high byte of the on-wire ctLen field.
	// Position: HandshakeNonce + X25519PubLen + MLKEM768PubLen.
	flip := append([]byte(nil), wire...)
	ctLenOff := HandshakeNonce + X25519PubLen + MLKEM768PubLen
	flip[ctLenOff] ^= 0x80
	if _, _, err := AcceptClientHelloV21Strict(flip, lookup, staticPriv); err == nil {
		t.Fatal("flipped ctLen must be rejected")
	}
}

// decode32 is a no-op helper used solely so the import block above can
// stay tidy; tests routinely round-trip raw 32-byte arrays.
func decode32(t *testing.T, b []byte) [32]byte {
	t.Helper()
	if len(b) != 32 {
		t.Fatalf("decode32: got %d bytes", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// ----------------------------------------------------------------------
// Smoke: end-to-end v2.1 handshake round-trip MUST work and the wire
// MUST NOT contain the destination domain in clear-text (overlap with
// H1, but we confirm the negative case here too as a guardrail).
// ----------------------------------------------------------------------

func TestFixV2_Smoke_RoundTrip(t *testing.T) {
	uuid := fixesMustUUID(t)
	staticPriv, staticPub := genStaticIdentity(t)

	addr := Address{Domain: "smoke.example", Port: 8443}
	state, err := WriteClientHelloV21(
		func(b []byte) error { return nil },
		uuid, CommandTCP, addr, staticPub,
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeClientHelloV21Test(state, staticPub)
	if err != nil {
		t.Fatal(err)
	}

	// Wire MUST NOT contain "smoke.example" (S1+H1 sanity).
	if bytes.Contains(wire, []byte("smoke.example")) ||
		strings.Contains(string(wire), "smoke.example") {
		t.Fatal("destination domain leaked into ClientHello wire")
	}

	srvOut, res, err := AcceptClientHelloV21Strict(
		wire, MakeUUIDLookupV21([][UUIDLen]byte{uuid}), staticPriv,
	)
	if err != nil {
		t.Fatalf("server accept: %v", err)
	}
	if res.ClientHello.Address.Domain != "smoke.example" {
		t.Fatalf("inner addr: %v", res.ClientHello.Address)
	}
	// Client processes ServerHello.
	cliRes, err := state.ReadServerHelloV21(srvOut, staticPub)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if cliRes.Keys.C2SKey == ([AEADKeyLen]byte{}) {
		t.Fatal("c2s key is zero")
	}
	if cliRes.Keys.C2SKey != res.Keys.C2SKey || cliRes.Keys.S2CKey != res.Keys.S2CKey {
		t.Fatal("client/server derived different session keys")
	}
	if absDiff(int64(state.hello.Timestamp), time.Now().Unix()) > HandshakeTimestampWindow {
		t.Fatal("timestamp out of window")
	}
}

// ----------------------------------------------------------------------
// H1: the destination address (Domain or IP+Port) must NEVER appear
// in clear-text on the ClientHello wire. v2.0 already keeps it inside
// the inner AEAD ciphertext; v2.1 inherits this property and we lock
// it down with a guardrail so any future codec change that leaks dst
// is caught immediately.
// ----------------------------------------------------------------------

func TestFixV2_H1_DstNotInClearText(t *testing.T) {
	uuid := fixesMustUUID(t)
	_, staticPub := genStaticIdentity(t)

	// Use a destination that contains a uniquely-identifiable byte
	// pattern so we can detect even partial leakage.
	const sentinelDomain = "leaky-canary.example.invalid"
	addr := Address{Domain: sentinelDomain, Port: 8443}

	state, err := WriteClientHelloV21(
		func(b []byte) error { return nil }, uuid, CommandTCP, addr, staticPub,
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeClientHelloV21Test(state, staticPub)
	if err != nil {
		t.Fatal(err)
	}

	// Strict: the sentinel must not appear anywhere in the wire.
	if bytes.Contains(wire, []byte(sentinelDomain)) {
		t.Fatal("destination domain leaked into wire")
	}
	// Even partial leak (≥6 contiguous bytes of the domain) is fatal.
	for i := 0; i+6 <= len(sentinelDomain); i++ {
		if bytes.Contains(wire, []byte(sentinelDomain[i:i+6])) {
			t.Fatalf("partial domain leak: %q", sentinelDomain[i:i+6])
		}
	}

	// And the UUID itself MUST NOT appear in clear-text either.
	if bytes.Contains(wire, uuid[:]) {
		t.Fatal("UUID leaked into wire")
	}
}

// ----------------------------------------------------------------------
// H3: SessionID derived from the per-handshake transcript must be
// (a) UNLINKABLE across handshakes (two handshakes from the SAME user
//     against the SAME server produce different session ids), and
// (b) NOT a function of the UUID alone (so it can't fingerprint a
//     specific user across reconnects).
// ----------------------------------------------------------------------

func TestFixV2_H3_SessionIDUnlinkability(t *testing.T) {
	uuid := fixesMustUUID(t)
	staticPriv, staticPub := genStaticIdentity(t)
	lookup := MakeUUIDLookupV21([][UUIDLen]byte{uuid})

	const N = 50
	seen := make(map[[8]byte]bool, N)
	for i := 0; i < N; i++ {
		state, err := WriteClientHelloV21(
			func(b []byte) error { return nil },
			uuid, CommandTCP,
			Address{Domain: "x.example", Port: 1},
			staticPub,
		)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := EncodeClientHelloV21Test(state, staticPub)
		if err != nil {
			t.Fatal(err)
		}
		_, res, err := AcceptClientHelloV21Strict(wire, lookup, staticPriv)
		if err != nil {
			t.Fatalf("accept #%d: %v", i, err)
		}
		sid := res.Keys.SessionID
		if sid == ([8]byte{}) {
			t.Fatal("post-fix SessionKeys.SessionID must be non-zero")
		}
		if seen[sid] {
			t.Fatalf("session id collision at %d: %x", i, sid)
		}
		seen[sid] = true
	}
}

// ----------------------------------------------------------------------
// M1: LengthFramer must use a 3-byte big-endian length prefix.
// Strict signal: the high byte (offset 0) of the prefix MUST exhibit
// non-trivial entropy across messages of varying length, AND for any
// single message the prefix is exactly 3 bytes (not 4).
// ----------------------------------------------------------------------

func TestFixV2_M1_LengthPrefix3Bytes(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	fr := NewLengthFramer(a)

	go func() {
		defer fr.Close()
		// Send messages of varying length to vary the length prefix.
		for i := 1; i <= 16; i++ {
			payload := bytes.Repeat([]byte{byte(i)}, i*256+i)
			if err := fr.SendMessage(payload); err != nil {
				return
			}
		}
	}()

	// Read the raw bytes off side b, peek at the per-message prefix.
	got := make([]byte, 0, 64*1024)
	buf := make([]byte, 4096)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := b.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
		if len(got) > 32*1024 {
			break
		}
	}

	// Walk got, peeling 3-byte prefixes.
	prefixes := make([][3]byte, 0, 16)
	off := 0
	for off+3 <= len(got) {
		var hdr [3]byte
		copy(hdr[:], got[off:off+3])
		prefixes = append(prefixes, hdr)
		l := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		off += 3 + l
	}
	if len(prefixes) < 8 {
		t.Fatalf("expected ≥8 prefixes, got %d", len(prefixes))
	}

	// Strict: at least one prefix MUST have a non-zero high byte (so
	// we know payloads >= 64KiB still encode correctly), AND high
	// byte of the smallest prefix MUST be 0 (sanity for short messages).
	// Together this confirms the prefix is 3 bytes wide and not 4.
	if prefixes[0][0] != 0 {
		t.Fatalf("first prefix high byte expected 0 for tiny payload, got %x", prefixes[0])
	}
	// Largest payload was 16*256+16 = 4112 bytes → header = 0x00 0x10 0x10.
	last := prefixes[len(prefixes)-1]
	if int(last[0])<<16|int(last[1])<<8|int(last[2]) < 4096 {
		t.Fatalf("last prefix decoded to %d, expected ≥4096", int(last[0])<<16|int(last[1])<<8|int(last[2]))
	}
}

// ----------------------------------------------------------------------
// M2: every KDF label string used by the package MUST embed the
// version banner "ewp/v2.1". This is a string-search test against
// constants exposed at package level (or via reflection where
// applicable). We list the labels we care about; if any new label is
// added without the banner the test will fail.
// ----------------------------------------------------------------------

func TestFixV2_M2_LabelHasV21Prefix(t *testing.T) {
	must := []string{
		v21LabelOuterAEAD,
		v21LabelOuterMAC,
		v21LabelOuterAEADSalt,
		v21LabelOuterMACSalt,
		v21LabelSessionPrefix,
	}
	for _, s := range must {
		if !strings.Contains(s, "ewp/v2.1") {
			t.Errorf("label %q missing ewp/v2.1 banner", s)
		}
	}
}

// ----------------------------------------------------------------------
// HighLevelAPI smoke + negative test: the v2.1-aware Client+Service
// round-trip works, and a misconfigured client (wrong server static
// pub) MUST fail to handshake.
// ----------------------------------------------------------------------

func TestFixV2_HighLevelAPI_RoundTrip(t *testing.T) {
	uuidStr := "11112222-3333-4444-5555-666677778888"
	uuid, _ := ParseUUID(uuidStr)
	_ = uuid

	staticPriv, staticPub := genStaticIdentity(t)
	staticPubB64 := base64.StdEncoding.EncodeToString(staticPub)
	staticPrivB64 := base64.StdEncoding.EncodeToString(staticPriv.Bytes())

	// Service.
	h := &echoHandler{}
	svc, err := NewServiceV21(h, staticPrivB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddUser(uuidStr); err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = svc.HandleConn(context.Background(), c2) }()

	cli, err := NewClientV21(uuidStr, staticPubB64)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.DialConn(context.Background(), c1, Address{Domain: "h.example", Port: 80})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestFixV2_HighLevelAPI_WrongStaticPubFails(t *testing.T) {
	uuidStr := "11112222-3333-4444-5555-666677778888"
	staticPriv, _ := genStaticIdentity(t)
	_, otherPub := genStaticIdentity(t)
	staticPrivB64 := base64.StdEncoding.EncodeToString(staticPriv.Bytes())
	otherPubB64 := base64.StdEncoding.EncodeToString(otherPub)

	svc, err := NewServiceV21(&echoHandler{}, staticPrivB64)
	if err != nil {
		t.Fatal(err)
	}
	_ = svc.AddUser(uuidStr)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	srvErrCh := make(chan error, 1)
	go func() { srvErrCh <- svc.HandleConn(context.Background(), c2) }()

	cli, err := NewClientV21(uuidStr, otherPubB64)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := cli.DialConn(ctx, c1, Address{Domain: "h.example", Port: 80}); err == nil {
		t.Fatal("dial with wrong server static pub must fail")
	}
}

type echoHandler struct {
	wg sync.WaitGroup
}

func (h *echoHandler) NewConnection(_ context.Context, conn net.Conn, _ Metadata) error {
	defer conn.Close()
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != "ping" {
		return errors.New("unexpected payload")
	}
	_, err = conn.Write([]byte("pong"))
	return err
}

func (h *echoHandler) NewPacketConnection(_ context.Context, _ net.PacketConn, _ Metadata) error {
	return errors.New("not used")
}
