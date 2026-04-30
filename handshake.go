package ewp

import (
	"crypto/ecdh"
	"crypto/mlkem"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Handshake errors. All of these MUST cause the underlying transport
// to be closed without writing any further bytes.
var (
	ErrMagic            = errors.New("ewp/v2: bad magic")
	ErrHandshakeShort   = errors.New("ewp/v2: handshake message too short")
	ErrHandshakeLong    = errors.New("ewp/v2: handshake ciphertext exceeds bound")
	ErrOuterMAC         = errors.New("ewp/v2: outer MAC verification failed")
	ErrAEADHandshake    = errors.New("ewp/v2: handshake AEAD open failed")
	ErrTimestamp        = errors.New("ewp/v2: handshake timestamp out of window")
	ErrUUIDMismatch     = errors.New("ewp/v2: inner UUID does not match outer")
	ErrCommand          = errors.New("ewp/v2: unsupported command")
	ErrServerStatus     = errors.New("ewp/v2: server returned non-OK status")
	ErrUnknownUUID      = errors.New("ewp/v2: unknown UUID")
	ErrPlaintextLayout  = errors.New("ewp/v2: handshake plaintext malformed")
)

// Command is the operation requested by the client in the handshake.
type Command byte

const (
	CommandTCP Command = 0x01
	CommandUDP Command = 0x02
)

// ClientHello holds the parsed contents of a v2 ClientHello.
//
// On the wire this struct is encoded by EncodeClientHello and decoded
// by DecodeClientHello.
type ClientHello struct {
	// Public, on-wire fields
	Nonce        [HandshakeNonce]byte
	ClassicalPub [X25519PubLen]byte
	PQPub        [MLKEM768PubLen]byte

	// Inner-encrypted fields
	Timestamp uint32 // Unix seconds
	UUID      [UUIDLen]byte
	Command   Command
	Address   Address
}

// ServerHello holds the parsed contents of a v2 ServerHello.
type ServerHello struct {
	NonceEcho    [HandshakeNonce]byte
	ClassicalPub [X25519PubLen]byte
	PQCipher     [MLKEM768CipherL]byte
	ServerTime   uint32
	Status       byte // 0x00 = OK
}

// HandshakeResult bundles the materials a SecureStream needs after a
// successful handshake on either side.
type HandshakeResult struct {
	Keys           SessionKeys
	ClientHello    *ClientHello // populated on the server side
	ServerHello    *ServerHello // populated on the client side
}

// ClientHandshakeState holds ephemeral material the client needs
// between WriteClientHello and ReadServerHello.
type ClientHandshakeState struct {
	uuid         [UUIDLen]byte
	nonce        [HandshakeNonce]byte
	x25519Priv   *ecdh.PrivateKey
	mlkemPriv    *mlkem.DecapsulationKey768
	hello        *ClientHello
}

// ----------------------------------------------------------------------
// CLIENT side
// ----------------------------------------------------------------------

// WriteClientHello composes a v2 ClientHello, sends it over t (a
// transport that delivers full messages atomically), and returns the
// handshake state needed to process the upcoming ServerHello.
//
// The caller supplies the UUID (PSK), the desired Command, and the
// destination Address.
func WriteClientHello(
	send func([]byte) error,
	uuid [UUIDLen]byte,
	cmd Command,
	addr Address,
) (*ClientHandshakeState, error) {
	if cmd != CommandTCP && cmd != CommandUDP {
		return nil, ErrCommand
	}

	// Generate ephemeral keys.
	curve := ecdh.X25519()
	x25519Priv, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2: x25519 keygen: %w", err)
	}
	mlkemPriv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ewp/v2: mlkem keygen: %w", err)
	}

	hello := &ClientHello{
		Timestamp: uint32(time.Now().Unix()),
		UUID:      uuid,
		Command:   cmd,
		Address:   addr,
	}
	if _, err := io.ReadFull(crand.Reader, hello.Nonce[:]); err != nil {
		return nil, fmt.Errorf("ewp/v2: nonce rand: %w", err)
	}
	copy(hello.ClassicalPub[:], x25519Priv.PublicKey().Bytes())
	pqPub := mlkemPriv.EncapsulationKey().Bytes()
	if len(pqPub) != MLKEM768PubLen {
		return nil, fmt.Errorf("ewp/v2: unexpected ML-KEM pub size %d", len(pqPub))
	}
	copy(hello.PQPub[:], pqPub)

	wire, err := EncodeClientHello(hello)
	if err != nil {
		return nil, err
	}
	if err := send(wire); err != nil {
		return nil, fmt.Errorf("ewp/v2: send ClientHello: %w", err)
	}

	return &ClientHandshakeState{
		uuid:       uuid,
		nonce:      hello.Nonce,
		x25519Priv: x25519Priv,
		mlkemPriv:  mlkemPriv,
		hello:      hello,
	}, nil
}

// ReadServerHello parses the server's response and derives the
// post-handshake session keys. The returned HandshakeResult.Keys can
// then be used to construct two FrameAEAD contexts (c2s and s2c).
//
// The state's ephemeral private keys are zeroed before return.
func (s *ClientHandshakeState) ReadServerHello(msg []byte) (*HandshakeResult, error) {
	sh, err := DecodeServerHello(msg, s.uuid)
	if err != nil {
		return nil, err
	}
	if sh.NonceEcho != s.nonce {
		return nil, ErrOuterMAC // wire-level rejection
	}
	if sh.Status != 0x00 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrServerStatus, sh.Status)
	}

	// Classical shared secret.
	curve := ecdh.X25519()
	serverPub, err := curve.NewPublicKey(sh.ClassicalPub[:])
	if err != nil {
		return nil, fmt.Errorf("ewp/v2: parse server x25519 pub: %w", err)
	}
	classical, err := s.x25519Priv.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2: x25519 ecdh: %w", err)
	}
	var classicalArr [X25519PubLen]byte
	copy(classicalArr[:], classical)

	// PQ shared secret.
	pq, err := s.mlkemPriv.Decapsulate(sh.PQCipher[:])
	if err != nil {
		return nil, fmt.Errorf("ewp/v2: mlkem decapsulate: %w", err)
	}

	keys := DeriveSessionKeys(classicalArr, pq, s.hello.Nonce, sh.NonceEcho)

	// Best-effort scrub of intermediate secrets.
	zero(classical)
	zero(pq)
	s.x25519Priv = nil
	s.mlkemPriv = nil

	return &HandshakeResult{Keys: keys, ServerHello: sh}, nil
}

// ----------------------------------------------------------------------
// SERVER side
// ----------------------------------------------------------------------

// UUIDLookup resolves an incoming ClientHello to the matching UUID, or
// returns ErrUnknownUUID. The server accepts any UUID for which Verify
// returns true; the typical implementation iterates a configured set
// and uses VerifyOuterMAC.
type UUIDLookup func(msg []byte, mac [OuterMACLen]byte) ([UUIDLen]byte, error)

// AcceptClientHello parses and authenticates a ClientHello, derives
// the session keys, and produces the wire-encoded ServerHello plus a
// HandshakeResult.
//
// The returned ServerHello bytes MUST be delivered to the client via
// the same transport's SendMessage path.
func AcceptClientHello(
	msg []byte,
	lookup UUIDLookup,
) (helloOut []byte, result *HandshakeResult, err error) {
	if len(msg) < MagicLen+OuterMACLen {
		return nil, nil, ErrHandshakeShort
	}

	// Outer MAC sits at the very end; lookup needs the message minus
	// the MAC and the MAC itself.
	macStart := len(msg) - OuterMACLen
	var outerTag [OuterMACLen]byte
	copy(outerTag[:], msg[macStart:])

	uuid, err := lookup(msg[:macStart], outerTag)
	if err != nil {
		return nil, nil, err
	}

	ch, err := DecodeClientHello(msg, uuid)
	if err != nil {
		return nil, nil, err
	}
	if ch.UUID != uuid {
		return nil, nil, ErrUUIDMismatch
	}
	if ch.Command != CommandTCP && ch.Command != CommandUDP {
		return nil, nil, ErrCommand
	}
	now := time.Now().Unix()
	if absDiff(int64(ch.Timestamp), now) > HandshakeTimestampWindow {
		return nil, nil, ErrTimestamp
	}

	// Server ephemeral keys.
	curve := ecdh.X25519()
	x25519Priv, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ewp/v2: server x25519 keygen: %w", err)
	}
	clientX25519Pub, err := curve.NewPublicKey(ch.ClassicalPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("ewp/v2: parse client x25519 pub: %w", err)
	}
	classical, err := x25519Priv.ECDH(clientX25519Pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ewp/v2: server x25519 ecdh: %w", err)
	}
	var classicalArr [X25519PubLen]byte
	copy(classicalArr[:], classical)

	// ML-KEM encapsulation against client's public key.
	clientMLKEMPub, err := mlkem.NewEncapsulationKey768(ch.PQPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("ewp/v2: parse client mlkem pub: %w", err)
	}
	pqShared, pqCipher := clientMLKEMPub.Encapsulate()
	if len(pqCipher) != MLKEM768CipherL {
		return nil, nil, fmt.Errorf("ewp/v2: unexpected ML-KEM cipher size %d", len(pqCipher))
	}

	sh := &ServerHello{
		NonceEcho:  ch.Nonce, // echo
		ServerTime: uint32(time.Now().Unix()),
		Status:     0x00,
	}
	copy(sh.ClassicalPub[:], x25519Priv.PublicKey().Bytes())
	copy(sh.PQCipher[:], pqCipher)

	helloOut, err = EncodeServerHello(sh, uuid)
	if err != nil {
		return nil, nil, err
	}

	keys := DeriveSessionKeys(classicalArr, pqShared, ch.Nonce, sh.NonceEcho)
	zero(classical)
	zero(pqShared)

	return helloOut, &HandshakeResult{Keys: keys, ClientHello: ch}, nil
}

// MakeUUIDLookup returns a UUIDLookup that linearly searches uuids and
// accepts the first whose OuterMAC matches.
//
// Linear search is intentional: the typical server has < 64 UUIDs, and
// this avoids any timing side channel from associative lookup.
func MakeUUIDLookup(uuids [][UUIDLen]byte) UUIDLookup {
	return func(msg []byte, tag [OuterMACLen]byte) ([UUIDLen]byte, error) {
		for _, u := range uuids {
			if VerifyOuterMAC(u, msg, tag) {
				return u, nil
			}
		}
		return [UUIDLen]byte{}, ErrUnknownUUID
	}
}

// ----------------------------------------------------------------------
// Wire codecs (encode / decode of ClientHello / ServerHello)
// ----------------------------------------------------------------------

// EncodeClientHello produces the wire bytes for ch, including outer
// MAC. The caller MUST have populated all public-on-wire fields (Nonce,
// ClassicalPub, PQPub) and the inner fields (Timestamp, UUID, Command,
// Address). PadLen is generated internally per the spec.
func EncodeClientHello(ch *ClientHello) ([]byte, error) {
	// Build inner plaintext.
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
		return nil, fmt.Errorf("ewp/v2: pad rand: %w", err)
	}
	inner = append(inner, pad...)

	// Encrypt.
	key := HandshakeAEADKey(ch.UUID, ch.Nonce)
	aead, err := newHandshakeAEAD(key)
	if err != nil {
		return nil, err
	}

	// Compose AAD = Magic || Nonce || ClassicalPub || PQPub || CTLen.
	ctLen := len(inner) + chacha20poly1305Overhead
	if ctLen > 65535 {
		return nil, ErrHandshakeLong
	}

	out := make([]byte, 0, MagicLen+HandshakeNonce+X25519PubLen+MLKEM768PubLen+2+ctLen+OuterMACLen)
	out = append(out, Magic[:]...)
	out = append(out, ch.Nonce[:]...)
	out = append(out, ch.ClassicalPub[:]...)
	out = append(out, ch.PQPub[:]...)
	ctLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(ctLenBuf, uint16(ctLen))
	out = append(out, ctLenBuf...)
	aad := append([]byte(nil), out...) // AAD = everything before the ciphertext.

	cipher := aead.Seal(nil, ch.Nonce[:], inner, aad)
	out = append(out, cipher...)

	mac := OuterMAC(ch.UUID, out)
	out = append(out, mac[:]...)
	return out, nil
}

// DecodeClientHello parses msg under the assumption that the supplied
// uuid is the correct PSK (i.e. the outer MAC has already validated).
func DecodeClientHello(msg []byte, uuid [UUIDLen]byte) (*ClientHello, error) {
	const fixedHeader = MagicLen + HandshakeNonce + X25519PubLen + MLKEM768PubLen + 2
	if len(msg) < fixedHeader+chacha20poly1305Overhead+OuterMACLen {
		return nil, ErrHandshakeShort
	}
	if string(msg[:MagicLen]) != string(Magic[:]) {
		return nil, ErrMagic
	}
	off := MagicLen

	var nonce [HandshakeNonce]byte
	copy(nonce[:], msg[off:off+HandshakeNonce])
	off += HandshakeNonce

	var cpub [X25519PubLen]byte
	copy(cpub[:], msg[off:off+X25519PubLen])
	off += X25519PubLen

	var pqpub [MLKEM768PubLen]byte
	copy(pqpub[:], msg[off:off+MLKEM768PubLen])
	off += MLKEM768PubLen

	ctLen := int(binary.BigEndian.Uint16(msg[off : off+2]))
	off += 2

	if ctLen <= chacha20poly1305Overhead {
		return nil, ErrHandshakeShort
	}
	if off+ctLen+OuterMACLen != len(msg) {
		return nil, ErrHandshakeShort
	}
	cipher := msg[off : off+ctLen]
	aad := msg[:off]

	key := HandshakeAEADKey(uuid, nonce)
	aead, err := newHandshakeAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce[:], cipher, aad)
	if err != nil {
		return nil, ErrAEADHandshake
	}

	if len(plain) < 4+UUIDLen+1+1+2 {
		return nil, ErrPlaintextLayout
	}
	ch := &ClientHello{
		Nonce:        nonce,
		ClassicalPub: cpub,
		PQPub:        pqpub,
	}
	ch.Timestamp = binary.BigEndian.Uint32(plain[0:4])
	copy(ch.UUID[:], plain[4:4+UUIDLen])
	pos := 4 + UUIDLen
	ch.Command = Command(plain[pos])
	pos++
	addr, n, err := DecodeAddress(plain[pos:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPlaintextLayout, err)
	}
	ch.Address = addr
	pos += n
	if len(plain) < pos+2 {
		return nil, ErrPlaintextLayout
	}
	padLen := int(binary.BigEndian.Uint16(plain[pos : pos+2]))
	pos += 2
	if len(plain) != pos+padLen {
		return nil, ErrPlaintextLayout
	}
	return ch, nil
}

// EncodeServerHello produces the wire bytes for sh including the outer
// MAC under uuid.
func EncodeServerHello(sh *ServerHello, uuid [UUIDLen]byte) ([]byte, error) {
	out := make([]byte, 0, MagicLen+HandshakeNonce+X25519PubLen+MLKEM768CipherL+4+1+OuterMACLen)
	out = append(out, Magic[:]...)
	out = append(out, sh.NonceEcho[:]...)
	out = append(out, sh.ClassicalPub[:]...)
	out = append(out, sh.PQCipher[:]...)
	stBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(stBuf, sh.ServerTime)
	out = append(out, stBuf...)
	out = append(out, sh.Status)
	mac := OuterMAC(uuid, out)
	out = append(out, mac[:]...)
	return out, nil
}

// DecodeServerHello parses msg under the supplied uuid and returns the
// ServerHello if the outer MAC verifies.
func DecodeServerHello(msg []byte, uuid [UUIDLen]byte) (*ServerHello, error) {
	const wireLen = MagicLen + HandshakeNonce + X25519PubLen + MLKEM768CipherL + 4 + 1 + OuterMACLen
	if len(msg) != wireLen {
		return nil, ErrHandshakeShort
	}
	if string(msg[:MagicLen]) != string(Magic[:]) {
		return nil, ErrMagic
	}
	macOff := wireLen - OuterMACLen
	var tag [OuterMACLen]byte
	copy(tag[:], msg[macOff:])
	if !VerifyOuterMAC(uuid, msg[:macOff], tag) {
		return nil, ErrOuterMAC
	}

	off := MagicLen
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
	return &sh, nil
}

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

// chacha20poly1305Overhead exists as a package-level constant to keep
// EncodeClientHello self-contained without importing the cipher package
// just for the constant.
const chacha20poly1305Overhead = 16

func newHandshakeAEAD(key [AEADKeyLen]byte) (aead, error) {
	a, err := newChaChaAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2: handshake AEAD construct: %w", err)
	}
	return a, nil
}

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
