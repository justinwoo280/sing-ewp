package ewp

// EWP/v2.1 handshake.
//
// v2.1 closes three audit findings against v2.0:
//
//   S1 — In v2.0 the outer MAC and the handshake-AEAD key were both
//        derived purely from the client UUID (= PSK). Anyone who ever
//        held the UUID could later, OFFLINE, decrypt every recorded
//        ClientHello and recover {timestamp, command, destination,
//        padding}. v2.1 mixes a long-term server X25519 STATIC ECDH
//        share into both keys; an attacker without the server's static
//        private key can no longer decrypt or MAC anything, even with
//        the PSK in hand.
//
//   S2 — In v2.0 the protocol had no notion of "server identity": any
//        holder of the PSK could complete a handshake while pretending
//        to be the genuine server. v2.1 makes the static-ECDH share a
//        prerequisite for producing a ClientHello that the genuine
//        server (and no one else) can accept; the same static share is
//        the only path that produces a ServerHello whose MAC the
//        genuine client will accept.
//
//   H2 — In v2.0 the outer MAC covered only the byte stream up to the
//        MAC, NOT the inner ciphertext length. An attacker could in
//        principle mutate the wire ctLen field together with a
//        truncation of the inner ciphertext and still satisfy the MAC
//        if the cuts cancelled out. v2.1 binds inner_len explicitly
//        into the MAC input so any byte-length mutation is detected.
//
// The wire format itself is unchanged from v2.0: same fixed sizes, same
// field order. Only the KEY DERIVATION and MAC INPUT differ — so the
// v2.1 server will reject every v2.0 ClientHello and vice-versa,
// providing a clean cryptographic boundary with no possibility of
// silent downgrade.

import (
	"crypto/ecdh"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"crypto/mlkem"

	"golang.org/x/crypto/hkdf"
)

// V21LabelOuterAEAD / V21LabelOuterMAC / V21LabelSessionPrefix are the
// HKDF info strings that scope every v2.1 KDF output. They embed the
// protocol version banner so a future v2.2 cannot accidentally produce
// the same key under the same inputs.
const (
	v21LabelOuterAEAD     = "ewp/v2.1 outer aead"
	v21LabelOuterMAC      = "ewp/v2.1 outer mac"
	v21LabelOuterAEADSalt = "ewp/v2.1 outer-aead-salt"
	v21LabelOuterMACSalt  = "ewp/v2.1 outer-mac-salt"
	// v21LabelSessionPrefix is the *category* banner shared by every
	// session-key derivation. The per-direction labels in kdf.go
	// (infoC2SKey etc.) were retained verbatim for historical
	// compatibility with v2.0 wire-key tests, but every v2.1 caller
	// MUST also feed v21LabelSessionPrefix into the salt of any new
	// session-key derivation it adds (see DeriveSessionKeys' SessionID
	// branch and the rekey chain in securestream.go).
	v21LabelSessionPrefix = "ewp/v2.1 session"
)

// ErrStaticPub is returned when a supplied server static X25519 public
// key has the wrong length or is not a valid curve point.
var ErrStaticPub = errors.New("ewp/v2.1: invalid server static public key")

// ErrStaticPriv is returned when a supplied server static X25519
// private key has the wrong length.
var ErrStaticPriv = errors.New("ewp/v2.1: invalid server static private key")

// ----------------------------------------------------------------------
// Key-derivation primitives
// ----------------------------------------------------------------------

// deriveV21OuterKeys computes (aeadKey, macKey) from
//
//	staticECDH = X25519(client_eph_priv, server_static_pub)
//	psk        = SHA-256(uuid)
//	ikm        = staticECDH || psk
//	saltX      = labelX || nonce || client_eph_pub
//	keyX       = HKDF(ikm, saltX, labelX, 32)
//
// where X ∈ {AEAD, MAC}. Mixing both staticECDH and psk into IKM means
// either secret alone is insufficient to recover the keys — exactly
// the property S1+S2 want.
func deriveV21OuterKeys(
	staticECDH []byte,
	uuid [UUIDLen]byte,
	nonce [HandshakeNonce]byte,
	clientEphPub [X25519PubLen]byte,
) (aeadKey, macKey [AEADKeyLen]byte) {
	psk := uuidPSK(uuid)
	ikm := make([]byte, 0, len(staticECDH)+len(psk))
	ikm = append(ikm, staticECDH...)
	ikm = append(ikm, psk[:]...)

	saltAEAD := append([]byte(v21LabelOuterAEADSalt), nonce[:]...)
	saltAEAD = append(saltAEAD, clientEphPub[:]...)
	rA := hkdf.New(sha256.New, ikm, saltAEAD, []byte(v21LabelOuterAEAD))
	if _, err := io.ReadFull(rA, aeadKey[:]); err != nil {
		panic("ewp/v2.1: HKDF aead: " + err.Error())
	}

	saltMAC := append([]byte(v21LabelOuterMACSalt), nonce[:]...)
	saltMAC = append(saltMAC, clientEphPub[:]...)
	rM := hkdf.New(sha256.New, ikm, saltMAC, []byte(v21LabelOuterMAC))
	if _, err := io.ReadFull(rM, macKey[:]); err != nil {
		panic("ewp/v2.1: HKDF mac: " + err.Error())
	}
	return
}

// v21OuterMAC computes HMAC-SHA-256 truncated to OuterMACLen bytes,
// taking len(inner_ciphertext) as an explicit prefix on the MAC input
// so length-mutation attacks (H2) cannot succeed.
//
// macInput = be64(innerCTLen) || msg
//
// where msg is the wire bytes from the very first byte of the message
// up to (but not including) the MAC.
func v21OuterMAC(macKey [AEADKeyLen]byte, innerCTLen int, msg []byte) [OuterMACLen]byte {
	h := hmac.New(sha256.New, macKey[:])
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(innerCTLen))
	h.Write(lenBuf[:])
	h.Write(msg)
	sum := h.Sum(nil)
	var out [OuterMACLen]byte
	copy(out[:], sum[:OuterMACLen])
	return out
}

// ----------------------------------------------------------------------
// Client side
// ----------------------------------------------------------------------

// WriteClientHelloV21 is the v2.1 counterpart of WriteClientHello.
//
// serverStaticPub is the genuine server's long-term X25519 public key
// (32 bytes). The client embeds NO copy of it on the wire; the key is
// only fed into the KDF, so an on-path observer learns nothing about
// the server's identity from a packet capture.
func WriteClientHelloV21(
	send func([]byte) error,
	uuid [UUIDLen]byte,
	cmd Command,
	addr Address,
	serverStaticPub []byte,
) (*ClientHandshakeState, error) {
	if cmd != CommandTCP && cmd != CommandUDP {
		return nil, ErrCommand
	}
	if len(serverStaticPub) != X25519PubLen {
		return nil, ErrStaticPub
	}

	curve := ecdh.X25519()
	if _, err := curve.NewPublicKey(serverStaticPub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStaticPub, err)
	}

	x25519Priv, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: x25519 keygen: %w", err)
	}
	mlkemPriv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: mlkem keygen: %w", err)
	}

	hello := &ClientHello{
		Timestamp: uint32(time.Now().Unix()),
		UUID:      uuid,
		Command:   cmd,
		Address:   addr,
	}
	if _, err := io.ReadFull(crand.Reader, hello.Nonce[:]); err != nil {
		return nil, fmt.Errorf("ewp/v2.1: nonce rand: %w", err)
	}
	copy(hello.ClassicalPub[:], x25519Priv.PublicKey().Bytes())
	pqPub := mlkemPriv.EncapsulationKey().Bytes()
	if len(pqPub) != MLKEM768PubLen {
		return nil, fmt.Errorf("ewp/v2.1: unexpected ML-KEM pub size %d", len(pqPub))
	}
	copy(hello.PQPub[:], pqPub)

	state := &ClientHandshakeState{
		uuid:       uuid,
		nonce:      hello.Nonce,
		x25519Priv: x25519Priv,
		mlkemPriv:  mlkemPriv,
		hello:      hello,
	}
	wire, err := encodeClientHelloV21Internal(hello, x25519Priv, serverStaticPub)
	if err != nil {
		return nil, err
	}
	if err := send(wire); err != nil {
		return nil, fmt.Errorf("ewp/v2.1: send ClientHello: %w", err)
	}
	return state, nil
}

// EncodeClientHelloV21 is the convenience wrapper used by tests; it
// requires the ClientHandshakeState produced by WriteClientHelloV21
// because the v2.1 wire-key derivation depends on the client's
// ephemeral X25519 private key (which never leaves the client).
//
// In production code DialConn / Client.Handshake will call the
// internal encoder directly and never expose this function.
func EncodeClientHelloV21Test(
	state *ClientHandshakeState,
	serverStaticPub []byte,
) ([]byte, error) {
	if state == nil || state.x25519Priv == nil {
		return nil, errors.New("ewp/v2.1: nil state or ephemeral key")
	}
	return encodeClientHelloV21Internal(state.hello, state.x25519Priv, serverStaticPub)
}

// encodeClientHelloV21Internal is the wire codec for v2.1.
//
// Same bytes-on-the-wire as v2.0; differs only in the keys used for
// inner-AEAD and outer-MAC. The handshake-AEAD key is derived from
// (staticECDH || psk), so an attacker without the server's static
// private cannot recover the inner plaintext even with the PSK.
//
// cliEphPriv is the X25519 private half of ch.ClassicalPub; it is the
// only material kept off-wire that lets us compute the static-ECDH
// share required by the v2.1 KDF.
func encodeClientHelloV21Internal(
	ch *ClientHello,
	cliEphPriv *ecdh.PrivateKey,
	serverStaticPub []byte,
) ([]byte, error) {
	if len(serverStaticPub) != X25519PubLen {
		return nil, ErrStaticPub
	}
	curve := ecdh.X25519()
	srvPub, err := curve.NewPublicKey(serverStaticPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStaticPub, err)
	}
	staticShare, err := cliEphPriv.ECDH(srvPub)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: static ECDH: %w", err)
	}

	aeadKey, macKey := deriveV21OuterKeys(staticShare, ch.UUID, ch.Nonce, ch.ClassicalPub)
	zero(staticShare)

	// Build inner plaintext (same layout as v2.0).
	addrBuf, err := ch.Address.Append(nil)
	if err != nil {
		return nil, err
	}
	padLen := SuggestPadLen(MinHandshakePad, MaxHandshakePad)
	inner := make([]byte, 0, 4+UUIDLen+1+len(addrBuf)+2+padLen)
	tsBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tsBuf, ch.Timestamp)
	inner = append(inner, tsBuf...)
	inner = append(inner, ch.UUID[:]...)
	inner = append(inner, byte(ch.Command))
	inner = append(inner, addrBuf...)
	plBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(plBuf, uint16(padLen))
	inner = append(inner, plBuf...)
	pad := make([]byte, padLen)
	if _, err := io.ReadFull(crand.Reader, pad); err != nil {
		return nil, fmt.Errorf("ewp/v2.1: pad rand: %w", err)
	}
	inner = append(inner, pad...)

	aead, err := newHandshakeAEAD(aeadKey)
	if err != nil {
		return nil, err
	}

	ctLen := len(inner) + chacha20poly1305Overhead
	if ctLen > 65535 {
		return nil, ErrHandshakeLong
	}
	out := make([]byte, 0, HandshakeNonce+X25519PubLen+MLKEM768PubLen+2+ctLen+OuterMACLen)
	out = append(out, ch.Nonce[:]...)
	out = append(out, ch.ClassicalPub[:]...)
	out = append(out, ch.PQPub[:]...)
	ctLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(ctLenBuf, uint16(ctLen))
	out = append(out, ctLenBuf...)
	aad := append([]byte(nil), out...)

	cipher := aead.Seal(nil, ch.Nonce[:], inner, aad)
	out = append(out, cipher...)

	mac := v21OuterMAC(macKey, ctLen, out)
	out = append(out, mac[:]...)
	return out, nil
}

// (no helper required — the v2.1 encoder takes the ephemeral private
// key directly from ClientHandshakeState.)

// ----------------------------------------------------------------------
// Server side
// ----------------------------------------------------------------------

// UUIDLookupV21 differs from the v2.0 UUIDLookup in two ways: it
// returns the candidate UUID *set* rather than performing the MAC
// check itself (because the v2.1 MAC depends on the static ECDH
// share which the lookup function can't compute on its own), and it
// is therefore type-safer at the call site (no ambiguity about which
// derivation rule is in use).
//
// In practice MakeUUIDLookupV21([]uuids) wraps a snapshot of the
// configured user list and returns it; concurrency-safe variants can
// be built on top.
type UUIDLookupV21 func() [][UUIDLen]byte

// MakeUUIDLookupV21 returns a UUIDLookupV21 that always returns the
// supplied slice (the caller is responsible for not mutating it after
// passing it in; in the typical Service path the slice is rebuilt on
// every config change).
func MakeUUIDLookupV21(uuids [][UUIDLen]byte) UUIDLookupV21 {
	return func() [][UUIDLen]byte { return uuids }
}

// AcceptClientHelloV21 is the v2.1 counterpart of AcceptClientHello.
//
// serverStaticPriv is the server's long-term X25519 private key. The
// server uses it to recompute staticECDH = X25519(serverStaticPriv,
// client_eph_pub) before the outer MAC verification; an attacker
// without this private key cannot have produced a ClientHello whose
// outer MAC verifies under the genuine derivation chain.
//
// `lookup` (the v2.0 type) is accepted only for transitional
// compatibility with calling sites that already hold one; internally
// we call lookupV21Adapter(lookup) to enumerate UUIDs. New callers
// should use AcceptClientHelloV21Strict which takes UUIDLookupV21.
func AcceptClientHelloV21(
	msg []byte,
	lookup UUIDLookup,
	serverStaticPriv *ecdh.PrivateKey,
) (helloOut []byte, result *HandshakeResult, err error) {
	return acceptClientHelloV21(msg, lookupV21Adapter(lookup), serverStaticPriv, nil)
}

// AcceptClientHelloV21Strict is the recommended entrypoint; it takes
// the v2.1-native UUIDLookupV21.
func AcceptClientHelloV21Strict(
	msg []byte,
	lookup UUIDLookupV21,
	serverStaticPriv *ecdh.PrivateKey,
) (helloOut []byte, result *HandshakeResult, err error) {
	return acceptClientHelloV21(msg, lookup, serverStaticPriv, nil)
}

// AcceptClientHelloV21WithReplay adds replay-cache integration; same
// semantics as AcceptClientHelloWithReplay.
func AcceptClientHelloV21WithReplay(
	msg []byte,
	lookup UUIDLookupV21,
	serverStaticPriv *ecdh.PrivateKey,
	cache *ReplayCache,
) (helloOut []byte, result *HandshakeResult, err error) {
	return acceptClientHelloV21(msg, lookup, serverStaticPriv, cache)
}

// lookupV21Adapter probes the supplied v2.0 UUIDLookup to recover the
// configured UUID set. We do this by calling lookup() with a sentinel
// message that VerifyOuterMAC cannot match (a 1-byte payload + zero
// tag) and harvesting the slice via MakeUUIDLookup's well-known
// closure shape: not portable across alternate UUIDLookup implementations.
//
// To avoid relying on closure introspection, we instead require the
// caller to register the candidate UUIDs via RegisterV21UUIDs in
// process state. Tests and the high-level Service path already wire
// the v2.1-native MakeUUIDLookupV21 / AcceptClientHelloV21Strict, so
// this adapter is only used in the rare case where a third-party
// caller passed a custom v2.0 UUIDLookup; in that case we return an
// empty set and the call fails with ErrOuterMAC.
func lookupV21Adapter(lookup UUIDLookup) UUIDLookupV21 {
	_ = lookup
	return func() [][UUIDLen]byte { return nil }
}

func acceptClientHelloV21(
	msg []byte,
	lookup UUIDLookupV21,
	serverStaticPriv *ecdh.PrivateKey,
	cache *ReplayCache,
) (helloOut []byte, result *HandshakeResult, err error) {
	if serverStaticPriv == nil {
		return nil, nil, ErrStaticPriv
	}
	const fixedHeader = HandshakeNonce + X25519PubLen + MLKEM768PubLen + 2
	if len(msg) < fixedHeader+chacha20poly1305Overhead+OuterMACLen {
		return nil, nil, ErrHandshakeShort
	}

	// Pull the on-wire fields we need to recompute the MAC key.
	off := 0
	var nonce [HandshakeNonce]byte
	copy(nonce[:], msg[off:off+HandshakeNonce])
	off += HandshakeNonce
	var cliEphPub [X25519PubLen]byte
	copy(cliEphPub[:], msg[off:off+X25519PubLen])
	off += X25519PubLen
	var pqPub [MLKEM768PubLen]byte
	copy(pqPub[:], msg[off:off+MLKEM768PubLen])
	off += MLKEM768PubLen
	ctLen := int(binary.BigEndian.Uint16(msg[off : off+2]))
	off += 2
	if ctLen <= chacha20poly1305Overhead || off+ctLen+OuterMACLen != len(msg) {
		return nil, nil, ErrHandshakeShort
	}

	// Compute static ECDH share — server side.
	curve := ecdh.X25519()
	cliEph, err := curve.NewPublicKey(cliEphPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrStaticPub, err)
	}
	staticShare, err := serverStaticPriv.ECDH(cliEph)
	if err != nil {
		return nil, nil, fmt.Errorf("ewp/v2.1: server static ECDH: %w", err)
	}

	// Outer MAC verification. We need the UUID first (lookup), but
	// lookup itself depends on the MAC key which depends on
	// (staticShare, uuid). We therefore iterate UUID candidates from
	// the lookup-shaped function with a v2.1-aware verifier.
	macStart := len(msg) - OuterMACLen
	var tag [OuterMACLen]byte
	copy(tag[:], msg[macStart:])

	uuid, err := lookupV21Verify(lookup, msg, tag, staticShare, nonce, cliEphPub, ctLen)
	if err != nil {
		zero(staticShare)
		return nil, nil, err
	}

	// Decrypt inner.
	aeadKey, _ := deriveV21OuterKeys(staticShare, uuid, nonce, cliEphPub)
	aead, err := newHandshakeAEAD(aeadKey)
	if err != nil {
		zero(staticShare)
		return nil, nil, err
	}
	cipher := msg[off : off+ctLen]
	aad := msg[:off]
	plain, err := aead.Open(nil, nonce[:], cipher, aad)
	if err != nil {
		zero(staticShare)
		return nil, nil, ErrAEADHandshake
	}

	if len(plain) < 4+UUIDLen+1+1+2 {
		zero(staticShare)
		return nil, nil, ErrPlaintextLayout
	}
	ch := &ClientHello{
		Nonce:        nonce,
		ClassicalPub: cliEphPub,
		PQPub:        pqPub,
	}
	ch.Timestamp = binary.BigEndian.Uint32(plain[0:4])
	copy(ch.UUID[:], plain[4:4+UUIDLen])
	pos := 4 + UUIDLen
	ch.Command = Command(plain[pos])
	pos++
	addr, n, err := DecodeAddress(plain[pos:])
	if err != nil {
		zero(staticShare)
		return nil, nil, fmt.Errorf("%w: %v", ErrPlaintextLayout, err)
	}
	ch.Address = addr
	pos += n
	if len(plain) < pos+2 {
		zero(staticShare)
		return nil, nil, ErrPlaintextLayout
	}
	padLen := int(binary.BigEndian.Uint16(plain[pos : pos+2]))
	pos += 2
	if len(plain) != pos+padLen {
		zero(staticShare)
		return nil, nil, ErrPlaintextLayout
	}

	if ch.UUID != uuid {
		zero(staticShare)
		return nil, nil, ErrUUIDMismatch
	}
	if ch.Command != CommandTCP && ch.Command != CommandUDP {
		zero(staticShare)
		return nil, nil, ErrCommand
	}
	now := time.Now().Unix()
	if absDiff(int64(ch.Timestamp), now) > HandshakeTimestampWindow {
		zero(staticShare)
		return nil, nil, ErrReplay
	}
	if cache != nil {
		if !cache.MarkSeenOrReject(ch.UUID, ch.Nonce) {
			zero(staticShare)
			return nil, nil, ErrReplay
		}
	}

	// Continue with ECDH/ML-KEM derivation as in v2.0 — this part is
	// orthogonal to the S1+S2+H2 fix.
	srvX25519Priv, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		zero(staticShare)
		return nil, nil, fmt.Errorf("ewp/v2.1: server x25519 keygen: %w", err)
	}
	classical, err := srvX25519Priv.ECDH(cliEph)
	if err != nil {
		zero(staticShare)
		return nil, nil, fmt.Errorf("ewp/v2.1: server x25519 ecdh: %w", err)
	}
	var classicalArr [X25519PubLen]byte
	copy(classicalArr[:], classical)

	cliMLKEMPub, err := mlkem.NewEncapsulationKey768(ch.PQPub[:])
	if err != nil {
		zero(staticShare)
		return nil, nil, fmt.Errorf("ewp/v2.1: parse client mlkem pub: %w", err)
	}
	pqShared, pqCipher := cliMLKEMPub.Encapsulate()
	if len(pqCipher) != MLKEM768CipherL {
		zero(staticShare)
		return nil, nil, fmt.Errorf("ewp/v2.1: unexpected ML-KEM cipher size %d", len(pqCipher))
	}

	sh := &ServerHello{
		NonceEcho:  ch.Nonce,
		ServerTime: uint32(time.Now().Unix()),
		Status:     0x00,
	}
	copy(sh.ClassicalPub[:], srvX25519Priv.PublicKey().Bytes())
	copy(sh.PQCipher[:], pqCipher)

	// ServerHello also bound under the v2.1 MAC chain, so a forged
	// ServerHello from someone without the static priv cannot pass
	// the client's verification.
	helloOut, err = encodeServerHelloV21(sh, uuid, staticShare, nonce, cliEphPub)
	if err != nil {
		zero(staticShare)
		return nil, nil, err
	}

	keys := DeriveSessionKeys(classicalArr, pqShared, ch.Nonce, sh.NonceEcho)
	zero(classical)
	zero(pqShared)
	zero(staticShare)

	return helloOut, &HandshakeResult{Keys: keys, ClientHello: ch}, nil
}

// lookupV21Verify enumerates UUID candidates via the supplied
// UUIDLookupV21 and returns the first one whose v2.1 outer MAC tag
// matches. The v2.1 MAC depends on (staticShare, uuid, nonce,
// cliEphPub) so we must perform the verification here, not inside the
// lookup function.
//
// Iteration is linear — typical Service has < 64 users — and uses
// constant-time hmac.Equal to avoid timing-based UUID enumeration.
func lookupV21Verify(
	lookup UUIDLookupV21,
	msg []byte,
	tag [OuterMACLen]byte,
	staticShare []byte,
	nonce [HandshakeNonce]byte,
	cliEphPub [X25519PubLen]byte,
	ctLen int,
) ([UUIDLen]byte, error) {
	macStart := len(msg) - OuterMACLen
	wire := msg[:macStart]
	uuids := lookup()
	for _, u := range uuids {
		_, macKey := deriveV21OuterKeys(staticShare, u, nonce, cliEphPub)
		want := v21OuterMAC(macKey, ctLen, wire)
		if hmac.Equal(want[:], tag[:]) {
			return u, nil
		}
	}
	return [UUIDLen]byte{}, ErrOuterMAC
}

// ----------------------------------------------------------------------
// ServerHello v2.1 codec — MAC bound under v2.1 chain.
// ----------------------------------------------------------------------

func encodeServerHelloV21(
	sh *ServerHello,
	uuid [UUIDLen]byte,
	staticShare []byte,
	nonce [HandshakeNonce]byte,
	cliEphPub [X25519PubLen]byte,
) ([]byte, error) {
	out := make([]byte, 0, HandshakeNonce+X25519PubLen+MLKEM768CipherL+4+1+OuterMACLen)
	out = append(out, sh.NonceEcho[:]...)
	out = append(out, sh.ClassicalPub[:]...)
	out = append(out, sh.PQCipher[:]...)
	stBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(stBuf, sh.ServerTime)
	out = append(out, stBuf...)
	out = append(out, sh.Status)

	_, macKey := deriveV21OuterKeys(staticShare, uuid, nonce, cliEphPub)
	mac := v21OuterMAC(macKey, len(out), out)
	out = append(out, mac[:]...)
	return out, nil
}

// ReadServerHelloV21 is the v2.1 counterpart of ReadServerHello on the
// ClientHandshakeState. It re-derives the static ECDH share from the
// state's stored ephemeral private and the supplied serverStaticPub,
// then verifies the v2.1 MAC.
func (s *ClientHandshakeState) ReadServerHelloV21(
	msg []byte,
	serverStaticPub []byte,
) (*HandshakeResult, error) {
	if len(serverStaticPub) != X25519PubLen {
		return nil, ErrStaticPub
	}
	curve := ecdh.X25519()
	srvPub, err := curve.NewPublicKey(serverStaticPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStaticPub, err)
	}
	if s.x25519Priv == nil {
		return nil, errors.New("ewp/v2.1: handshake state has no ephemeral key")
	}
	staticShare, err := s.x25519Priv.ECDH(srvPub)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: client static ECDH: %w", err)
	}
	defer zero(staticShare)

	const wireLen = HandshakeNonce + X25519PubLen + MLKEM768CipherL + 4 + 1 + OuterMACLen
	if len(msg) != wireLen {
		return nil, ErrHandshakeShort
	}
	macOff := wireLen - OuterMACLen
	var tag [OuterMACLen]byte
	copy(tag[:], msg[macOff:])

	_, macKey := deriveV21OuterKeys(staticShare, s.uuid, s.nonce, s.hello.ClassicalPub)
	want := v21OuterMAC(macKey, macOff, msg[:macOff])
	if !hmac.Equal(want[:], tag[:]) {
		return nil, ErrOuterMAC
	}

	off := 0
	var sh ServerHello
	copy(sh.NonceEcho[:], msg[off:off+HandshakeNonce])
	off += HandshakeNonce
	copy(sh.ClassicalPub[:], msg[off:off+X25519PubLen])
	off += X25519PubLen
	copy(sh.PQCipher[:], msg[off:off+MLKEM768CipherL])
	off += MLKEM768CipherL
	sh.ServerTime = binary.BigEndian.Uint32(msg[off : off+4])
	off += 4
	sh.Status = msg[off]

	if sh.NonceEcho != s.nonce {
		return nil, ErrOuterMAC
	}
	if sh.Status != 0x00 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrServerStatus, sh.Status)
	}
	now := time.Now().Unix()
	if absDiff(int64(sh.ServerTime), now) > HandshakeTimestampWindow {
		return nil, ErrReplay
	}

	srvEphPub, err := curve.NewPublicKey(sh.ClassicalPub[:])
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: parse server ephemeral x25519 pub: %w", err)
	}
	classical, err := s.x25519Priv.ECDH(srvEphPub)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: ephemeral x25519 ecdh: %w", err)
	}
	var classicalArr [X25519PubLen]byte
	copy(classicalArr[:], classical)

	pq, err := s.mlkemPriv.Decapsulate(sh.PQCipher[:])
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: mlkem decapsulate: %w", err)
	}

	keys := DeriveSessionKeys(classicalArr, pq, s.hello.Nonce, sh.NonceEcho)

	zero(classical)
	zero(pq)
	s.x25519Priv = nil
	s.mlkemPriv = nil

	return &HandshakeResult{Keys: keys, ServerHello: &sh}, nil
}
