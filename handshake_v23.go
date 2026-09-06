package ewp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"crypto/mlkem"

	"golang.org/x/crypto/hkdf"
)

// ----------------------------------------------------------------------
// v2.3 wire messages
//
// All multi-byte integers are big-endian. Each message is one framed
// MessageTransport record; the framing layer supplies length delimiters.
// ----------------------------------------------------------------------

// V23ClientInit is the first message. It carries no secret and can be
// answered with a stateless cookie.
//
//	client_nonce(16) || route_tag(16)
type V23ClientInit struct {
	ClientNonce [V23ClientNonceLen]byte
	RouteTag    [V23RouteTagLen]byte
}

func (m *V23ClientInit) marshal() []byte {
	out := make([]byte, 0, V23ClientNonceLen+V23RouteTagLen)
	out = append(out, m.ClientNonce[:]...)
	out = append(out, m.RouteTag[:]...)
	return out
}

func parseV23ClientInit(b []byte) (V23ClientInit, error) {
	var m V23ClientInit
	if len(b) != V23ClientNonceLen+V23RouteTagLen {
		return m, ErrHandshakeShort
	}
	copy(m.ClientNonce[:], b[:V23ClientNonceLen])
	copy(m.RouteTag[:], b[V23ClientNonceLen:])
	return m, nil
}

// V23HelloRetry is the stateless anti-DoS answer. It also carries the
// current short-term outer key (signed by the server identity).
//
//	client_nonce(16) || server_nonce(16) || expires_at(8) ||
//	cookie(32) || outer_key_id(8) || not_before(8) || not_after(8) ||
//	outer_x25519_public(32) || ed25519_signature(64)
type V23HelloRetry struct {
	ClientNonce   [V23ClientNonceLen]byte
	ServerNonce   [V23ServerNonceLen]byte
	ExpiresAt     uint64
	Cookie        [V23CookieLen]byte
	OuterKeyID    [V23OuterKeyIDLen]byte
	NotBefore     uint64
	NotAfter      uint64
	OuterX25519   [X25519PubLen]byte
	Signature     [ed25519.SignatureSize]byte
}

func (m *V23HelloRetry) marshal() []byte {
	out := make([]byte, 0, V23ClientNonceLen+V23ServerNonceLen+8+V23CookieLen+
		V23OuterKeyIDLen+8+8+X25519PubLen+ed25519.SignatureSize)
	out = append(out, m.ClientNonce[:]...)
	out = append(out, m.ServerNonce[:]...)
	out = binary.BigEndian.AppendUint64(out, m.ExpiresAt)
	out = append(out, m.Cookie[:]...)
	out = append(out, m.OuterKeyID[:]...)
	out = binary.BigEndian.AppendUint64(out, m.NotBefore)
	out = binary.BigEndian.AppendUint64(out, m.NotAfter)
	out = append(out, m.OuterX25519[:]...)
	out = append(out, m.Signature[:]...)
	return out
}

func parseV23HelloRetry(b []byte) (V23HelloRetry, error) {
	var m V23HelloRetry
	const want = V23ClientNonceLen + V23ServerNonceLen + 8 + V23CookieLen +
		V23OuterKeyIDLen + 8 + 8 + X25519PubLen + ed25519.SignatureSize
	if len(b) != want {
		return m, ErrHandshakeShort
	}
	off := 0
	copy(m.ClientNonce[:], b[off:]); off += V23ClientNonceLen
	copy(m.ServerNonce[:], b[off:]); off += V23ServerNonceLen
	m.ExpiresAt = binary.BigEndian.Uint64(b[off:]); off += 8
	copy(m.Cookie[:], b[off:]); off += V23CookieLen
	copy(m.OuterKeyID[:], b[off:]); off += V23OuterKeyIDLen
	m.NotBefore = binary.BigEndian.Uint64(b[off:]); off += 8
	m.NotAfter = binary.BigEndian.Uint64(b[off:]); off += 8
	copy(m.OuterX25519[:], b[off:]); off += X25519PubLen
	copy(m.Signature[:], b[off:])
	return m, nil
}

// ----------------------------------------------------------------------
// Cookie mint/verify (stateless)
// ----------------------------------------------------------------------

func v23RouteTag(uuid [UUIDLen]byte, serverID string, routeEpoch uint64) [V23RouteTagLen]byte {
	psk := uuidPSK(uuid)
	h := hmac.New(sha256.New, psk[:])
	h.Write([]byte(v23Suite.labelRoute))
	h.Write([]byte(serverID))
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], routeEpoch)
	h.Write(epochBuf[:])
	var tag [V23RouteTagLen]byte
	copy(tag[:], h.Sum(nil))
	return tag
}

func v23Cookie(cookieKey [32]byte, serverID, source string, ci *V23ClientInit, serverNonce [V23ServerNonceLen]byte, expiresAt uint64, keyID [V23OuterKeyIDLen]byte) [V23CookieLen]byte {
	h := hmac.New(sha256.New, cookieKey[:])
	h.Write([]byte(v23Suite.labelCookie))
	h.Write([]byte(serverID))
	h.Write([]byte(source))
	h.Write(ci.ClientNonce[:])
	h.Write(serverNonce[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], expiresAt)
	h.Write(buf[:])
	h.Write(keyID[:])
	var c [V23CookieLen]byte
	copy(c[:], h.Sum(nil))
	return c
}

// ----------------------------------------------------------------------
// Transcript
// ----------------------------------------------------------------------

func v23Transcript(label string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(label))
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		h.Write(l[:])
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func v23HKDF(psk []byte, label string, context []byte, outLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, psk, context, []byte(label))
	out := make([]byte, outLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("%s: hkdf %s: %w", v23Name, label, err)
	}
	return out, nil
}

// ----------------------------------------------------------------------
// Short-term outer key store (server side)
// ----------------------------------------------------------------------

type v23OuterKey struct {
	id        [V23OuterKeyIDLen]byte
	priv      *ecdh.PrivateKey
	pub       [X25519PubLen]byte
	notBefore uint64
	notAfter  uint64
}

// v23OuterKeyStore rotates short-term outer X25519 keys. The previous key
// is accepted during an overlap window so in-flight handshakes that fetched
// HelloRetry just before rotation still complete.
type v23OuterKeyStore struct {
	mu          sync.Mutex
	serverID    string
	signing     ed25519.PrivateKey
	current     *v23OuterKey
	previous    *v23OuterKey
	lifetimeS   uint64
	overlapS    uint64
	generation  uint64
	now         func() time.Time
}

func newV23OuterKeyStore(serverID string, signing ed25519.PrivateKey) (*v23OuterKeyStore, error) {
	if len(signing) != ed25519.PrivateKeySize {
		return nil, ErrV23Signature
	}
	s := &v23OuterKeyStore{
		serverID:  serverID,
		signing:   signing,
		lifetimeS: V23OuterKeyDefaultLifetimeS,
		overlapS:  V23OuterKeyOverlapS,
		now:       time.Now,
	}
	if err := s.rotateLocked(time.Now()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *v23OuterKeyStore) rotateLocked(now time.Time) error {
	priv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return err
	}
	s.generation++
	k := &v23OuterKey{
		priv:      priv,
		notBefore: uint64(now.Unix()),
		notAfter:  uint64(now.Unix()) + s.lifetimeS,
	}
	copy(k.pub[:], priv.PublicKey().Bytes())
	binary.BigEndian.PutUint64(k.id[:], s.generation)
	if s.current != nil {
		old := s.current
		old.notAfter = uint64(now.Unix()) + s.overlapS
		s.previous = old
	}
	s.current = k
	return nil
}

// current returns the active key, rotating when expired. The previous key
// remains acceptable for ClientHello decryption during its overlap.
func (s *v23OuterKeyStore) currentKey() (*v23OuterKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if now.Unix() >= int64(s.current.notAfter) {
		if err := s.rotateLocked(now); err != nil {
			return nil, err
		}
	}
	return s.current, nil
}

// lookup returns the private key for a key id if it is still within its
// validity window (current, or previous within overlap).
func (s *v23OuterKeyStore) lookup(id [V23OuterKeyIDLen]byte) *v23OuterKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := uint64(s.now().Unix())
	if s.current != nil && s.current.id == id && now < s.current.notAfter {
		return s.current
	}
	if s.previous != nil && s.previous.id == id && now < s.previous.notAfter {
		return s.previous
	}
	return nil
}

func (s *v23OuterKeyStore) signKey(k *v23OuterKey) [ed25519.SignatureSize]byte {
	h := sha256.New()
	h.Write([]byte(v23Suite.labelOuterKeyID))
	h.Write([]byte(s.serverID))
	h.Write(k.id[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], k.notBefore)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], k.notAfter)
	h.Write(buf[:])
	h.Write(k.pub[:])
	sig := ed25519.Sign(s.signing, h.Sum(nil))
	var out [ed25519.SignatureSize]byte
	copy(out[:], sig)
	return out
}

// verifyOuterKeySignature checks the HelloRetry outer-key signature against
// the pinned server public key.
func verifyV23OuterKeySignature(serverPub ed25519.PublicKey, serverID string, hr *V23HelloRetry) bool {
	h := sha256.New()
	h.Write([]byte(v23Suite.labelOuterKeyID))
	h.Write([]byte(serverID))
	h.Write(hr.OuterKeyID[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], hr.NotBefore)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], hr.NotAfter)
	h.Write(buf[:])
	h.Write(hr.OuterX25519[:])
	return ed25519.Verify(serverPub, h.Sum(nil), hr.Signature[:])
}

// ----------------------------------------------------------------------
// Admission controller (bounded, fail-closed)
// ----------------------------------------------------------------------

type v23Admission struct {
	mu           sync.Mutex
	perSource    map[string]int
	perPrincipal map[[UUIDLen]byte]int
	global       int
	maxSource    int
	maxPrincipal int
	maxGlobal    int
	kem          chan struct{}
}

func newV23Admission(maxGlobal, maxSource, maxPrincipal, maxKEM int) *v23Admission {
	if maxGlobal <= 0 {
		maxGlobal = 64
	}
	if maxSource <= 0 {
		maxSource = 16
	}
	if maxPrincipal <= 0 {
		maxPrincipal = 16
	}
	if maxKEM <= 0 {
		maxKEM = 4
	}
	return &v23Admission{
		perSource:    make(map[string]int),
		perPrincipal: make(map[[UUIDLen]byte]int),
		maxSource:    maxSource,
		maxPrincipal: maxPrincipal,
		maxGlobal:    maxGlobal,
		kem:          make(chan struct{}, maxKEM),
	}
}

func (a *v23Admission) acquire(source string) (func(), error) {
	a.mu.Lock()
	if a.global >= a.maxGlobal || a.perSource[source] >= a.maxSource {
		a.mu.Unlock()
		return nil, ErrV23Admission
	}
	a.global++
	a.perSource[source]++
	a.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			a.global--
			a.perSource[source]--
			a.mu.Unlock()
		})
	}, nil
}

func (a *v23Admission) acquireKEM(ctx interface{ Done() <-chan struct{} }) (func(), error) {
	select {
	case a.kem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-a.kem }) }, nil
	case <-ctx.Done():
		return nil, ErrV23Admission
	}
}

// ----------------------------------------------------------------------
// Client handshake state machine
// ----------------------------------------------------------------------

// V23ClientState carries the in-flight v2.3 handshake.
type V23ClientState struct {
	uuid       [UUIDLen]byte
	serverID   string
	routeEpoch uint64
	serverPub  ed25519.PublicKey

	init     V23ClientInit
	retry    V23HelloRetry
	tCI      [32]byte
	tHR      [32]byte
	tCH      [32]byte

	x25519Priv *ecdh.PrivateKey
	mlkemPriv  *mlkem.DecapsulationKey768
	outerECDH  []byte

	// Set by ReadV23ServerHello for the final ServerFinished check.
	finKeyS   []byte
	tServerH  [32]byte
	clientFin [V23FinishedVrfLen]byte
	closed    bool
}

// WriteV23ClientInit begins a v2.3 handshake: send ClientInit and return the
// state that consumes HelloRetry.
func WriteV23ClientInit(
	send func([]byte) error,
	uuid [UUIDLen]byte,
	serverID string,
	routeEpoch uint64,
	serverPub ed25519.PublicKey,
) (*V23ClientState, error) {
	if len(serverID) == 0 || len(serverID) > 255 {
		return nil, errors.New("ewp/v2.3: invalid server_id")
	}
	if len(serverPub) != ed25519.PublicKeySize {
		return nil, ErrV23Signature
	}
	s := &V23ClientState{
		uuid:       uuid,
		serverID:   serverID,
		routeEpoch: routeEpoch,
		serverPub:  append(ed25519.PublicKey(nil), serverPub...),
	}
	if _, err := io.ReadFull(crand.Reader, s.init.ClientNonce[:]); err != nil {
		return nil, err
	}
	s.init.RouteTag = v23RouteTag(uuid, serverID, routeEpoch)
	wire := s.init.marshal()
	if err := send(wire); err != nil {
		return nil, fmt.Errorf("ewp/v2.3: send ClientInit: %w", err)
	}
	s.tCI = v23Transcript(v23Suite.labelTCI, wire)
	return s, nil
}

// ReadV23HelloRetry verifies the cookie freshness and outer-key signature and
// produces the encrypted ClientHello.
func (s *V23ClientState) ReadV23HelloRetry(msg []byte, cmd Command, addr Address) (clientHello []byte, err error) {
	if s == nil || s.closed {
		return nil, ErrV23State
	}
	if cmd != CommandTCP && cmd != CommandUDP {
		return nil, ErrCommand
	}
	hr, err := parseV23HelloRetry(msg)
	if err != nil {
		return nil, err
	}
	if hr.ClientNonce != s.init.ClientNonce {
		return nil, ErrV23Cookie
	}
	now := uint64(time.Now().Unix())
	if hr.ExpiresAt <= now || hr.NotBefore > now || hr.NotAfter <= now {
		return nil, ErrV23Cookie
	}
	if !verifyV23OuterKeySignature(s.serverPub, s.serverID, &hr) {
		return nil, ErrV23Signature
	}
	s.retry = hr
	s.tHR = v23Transcript(v23Suite.labelTHR, s.tCI[:], msg)

	// Fresh ephemeral hybrid keypair for the data plane.
	curve := ecdh.X25519()
	if s.x25519Priv, err = curve.GenerateKey(crand.Reader); err != nil {
		return nil, err
	}
	if s.mlkemPriv, err = mlkem.GenerateKey768(); err != nil {
		return nil, err
	}

	// Outer ECDH against the signed short-term key.
	outerPub, err := curve.NewPublicKey(hr.OuterX25519[:])
	if err != nil {
		return nil, ErrV23Signature
	}
	s.outerECDH, err = s.x25519Priv.ECDH(outerPub)
	if err != nil {
		return nil, err
	}

	psk := uuidPSK(s.uuid)
	outerKeyBytes, err := v23HKDF(psk[:], v23Suite.labelOuterKey,
		append(s.outerECDH, s.tHR[:]...), AEADKeyLen)
	if err != nil {
		return nil, err
	}
	var outerKey [AEADKeyLen]byte
	copy(outerKey[:], outerKeyBytes)
	zero(outerKeyBytes)

	// Inner plaintext: timestamp || uuid || command || address || pad.
	addrBuf, err := addr.Append(nil)
	if err != nil {
		return nil, err
	}
	padLen := SuggestPadLen(MinHandshakePad, MaxHandshakePad)
	inner := make([]byte, 0, 4+UUIDLen+1+len(addrBuf)+2+padLen)
	var tsBuf [4]byte
	binary.BigEndian.PutUint32(tsBuf[:], uint32(time.Now().Unix()))
	inner = append(inner, tsBuf[:]...)
	inner = append(inner, s.uuid[:]...)
	inner = append(inner, byte(cmd))
	inner = append(inner, addrBuf...)
	var plBuf [2]byte
	binary.BigEndian.PutUint16(plBuf[:], uint16(padLen))
	inner = append(inner, plBuf[:]...)
	pad := make([]byte, padLen)
	if _, err := io.ReadFull(crand.Reader, pad); err != nil {
		return nil, err
	}
	inner = append(inner, pad...)

	aead, err := newHandshakeAEAD(outerKey)
	zero(outerKey[:])
	if err != nil {
		return nil, err
	}
	var aeadNonce [AEADNonceLen]byte
	copy(aeadNonce[:], s.init.ClientNonce[:AEADNonceLen])

	// ClientHello wire: retry cookie echo || client eph pubs || ct.
	ct := aead.Seal(nil, aeadNonce[:], inner, s.tHR[:])
	zero(inner)
	var xPub [X25519PubLen]byte
	copy(xPub[:], s.x25519Priv.PublicKey().Bytes())
	pqPub := s.mlkemPriv.EncapsulationKey().Bytes()

	out := make([]byte, 0, V23CookieLen+X25519PubLen+MLKEM768PubLen+len(ct))
	out = append(out, s.retry.Cookie[:]...)
	out = append(out, xPub[:]...)
	out = append(out, pqPub...)
	out = append(out, ct...)
	s.tCH = v23Transcript(v23Suite.labelTCH, s.tHR[:], out)
	return out, nil
}

// ----------------------------------------------------------------------
// Server handshake
// ----------------------------------------------------------------------

// V23ServerConfig bundles the static server inputs for a v2.3 listener.
type V23ServerConfig struct {
	ServerID     string
	RouteEpoch   uint64
	SigningKey   ed25519.PrivateKey
	CookieKey    [32]byte
	UUIDs        [][UUIDLen]byte
	SourceFor    func() string // optional; defaults to "" for tests
}

// V23ServerHelloResult carries the derived session and the decoded hello.
type V23ServerHelloResult struct {
	Keys       SessionKeys
	ClientHello *ClientHello
	TSH        [32]byte
	FinKeyC    []byte
	FinKeyS    []byte
	TrafficPRK []byte
	uuid       [UUIDLen]byte
}

type v23Server struct {
	cfg       *V23ServerConfig
	keys      *v23OuterKeyStore
	routes    map[[V23RouteTagLen]byte][UUIDLen]byte
	admission *v23Admission
	replay    *ReplayCache
	now       func() time.Time
}

func newV23Server(cfg *V23ServerConfig) (*v23Server, error) {
	if cfg == nil || len(cfg.SigningKey) != ed25519.PrivateKeySize || cfg.ServerID == "" {
		return nil, errors.New("ewp/v2.3: invalid server config")
	}
	keys, err := newV23OuterKeyStore(cfg.ServerID, cfg.SigningKey)
	if err != nil {
		return nil, err
	}
	s := &v23Server{
		cfg:       cfg,
		keys:      keys,
		routes:    make(map[[V23RouteTagLen]byte][UUIDLen]byte, len(cfg.UUIDs)),
		admission: newV23Admission(0, 0, 0, 0),
		replay:    NewReplayCache(ReplayWindow),
		now:       time.Now,
	}
	for _, u := range cfg.UUIDs {
		s.routes[v23RouteTag(u, cfg.ServerID, cfg.RouteEpoch)] = u
	}
	return s, nil
}

// HandleClientInit answers a ClientInit with a stateless HelloRetry. No
// asymmetric work is performed here.
func (s *v23Server) HandleClientInit(msg []byte, source string) ([]byte, error) {
	ci, err := parseV23ClientInit(msg)
	if err != nil {
		return nil, err
	}
	if _, ok := s.routes[ci.RouteTag]; !ok {
		return nil, ErrV23Route
	}
	key, err := s.keys.currentKey()
	if err != nil {
		return nil, err
	}
	var hr V23HelloRetry
	hr.ClientNonce = ci.ClientNonce
	if _, err := io.ReadFull(crand.Reader, hr.ServerNonce[:]); err != nil {
		return nil, err
	}
	hr.ExpiresAt = uint64(s.now().Unix()) + V23CookieLifetimeS
	hr.OuterKeyID = key.id
	hr.NotBefore = key.notBefore
	hr.NotAfter = key.notAfter
	copy(hr.OuterX25519[:], key.pub[:])
	hr.Cookie = v23Cookie(s.cfg.CookieKey, s.cfg.ServerID, source, &ci, hr.ServerNonce, hr.ExpiresAt, hr.OuterKeyID)
	hr.Signature = s.keys.signKey(key)
	return hr.marshal(), nil
}

// HandleClientHello verifies cookie + route + admission, then performs the
// hybrid key exchange and produces ServerHello. No handler is invoked yet.
func (s *v23Server) HandleClientHello(ctx interface{ Done() <-chan struct{} }, initWire, retryWire, chWire []byte, source string) (serverHello []byte, res *V23ServerHelloResult, err error) {
	release, err := s.admission.acquire(source)
	if err != nil {
		return nil, nil, err
	}
	defer release()

	ci, err := parseV23ClientInit(initWire)
	if err != nil {
		return nil, nil, err
	}
	hr, err := parseV23HelloRetry(retryWire)
	if err != nil {
		return nil, nil, err
	}
	// Cookie check is first: zero asymmetric work on failure.
	want := v23Cookie(s.cfg.CookieKey, s.cfg.ServerID, source, &ci, hr.ServerNonce, hr.ExpiresAt, hr.OuterKeyID)
	if subtle.ConstantTimeCompare(want[:], hr.Cookie[:]) != 1 || hr.ExpiresAt <= uint64(s.now().Unix()) {
		return nil, nil, ErrV23Cookie
	}
	uuid, ok := s.routes[ci.RouteTag]
	if !ok {
		return nil, nil, ErrV23Route
	}
	key := s.keys.lookup(hr.OuterKeyID)
	if key == nil {
		return nil, nil, ErrV23Cookie
	}

	// Cross-handshake replay rejection. The cookie proves the ClientInit is
	// fresh (bound to source + a server nonce + a 10 s expiry), but it does
	// not stop an on-path observer from re-submitting the *same* ClientInit
	// and ClientHello inside the timestamp window: each replay would pass
	// the cookie and timestamp checks and, because the server picks a fresh
	// ServerNonce every time, would derive an independent session — the
	// server could not tell the replay apart from a legitimate reconnect.
	// Remembering (UUID, ClientNonce) for the replay window lets the server
	// *reject* the duplicate outright instead of silently accepting it,
	// before any expensive KEM work. The ClientNonce is the client-generated
	// random nonce already authenticated by the cookie and the outer AEAD, so
	// a replay necessarily repeats it.
	var nonce [HandshakeNonce]byte
	copy(nonce[:], ci.ClientNonce[:HandshakeNonce])
	if s.replay != nil && !s.replay.MarkSeenOrReject(uuid, nonce) {
		return nil, nil, ErrReplay
	}

	kemRelease, err := s.admission.acquireKEM(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer kemRelease()

	// Decrypt ClientHello outer AEAD.
	if len(chWire) < V23CookieLen+X25519PubLen+MLKEM768PubLen+chacha20poly1305Overhead {
		return nil, nil, ErrHandshakeShort
	}
	off := 0
	cookie := chWire[off : off+V23CookieLen]; off += V23CookieLen
	if subtle.ConstantTimeCompare(cookie, hr.Cookie[:]) != 1 {
		return nil, nil, ErrV23Cookie
	}
	var cliEphPub [X25519PubLen]byte
	copy(cliEphPub[:], chWire[off:]); off += X25519PubLen
	var pqPub [MLKEM768PubLen]byte
	copy(pqPub[:], chWire[off:]); off += MLKEM768PubLen
	ct := chWire[off:]

	curve := ecdh.X25519()
	cliEph, err := curve.NewPublicKey(cliEphPub[:])
	if err != nil {
		return nil, nil, ErrStaticPub
	}
	outerECDH, err := key.priv.ECDH(cliEph)
	if err != nil {
		return nil, nil, err
	}
	defer zero(outerECDH)

	tCI := v23Transcript(v23Suite.labelTCI, initWire)
	tHR := v23Transcript(v23Suite.labelTHR, tCI[:], retryWire)

	psk := uuidPSK(uuid)
	outerKeyBytes, err := v23HKDF(psk[:], v23Suite.labelOuterKey, append(outerECDH, tHR[:]...), AEADKeyLen)
	if err != nil {
		return nil, nil, err
	}
	var outerKey [AEADKeyLen]byte
	copy(outerKey[:], outerKeyBytes)
	zero(outerKeyBytes)
	aead, err := newHandshakeAEAD(outerKey)
	zero(outerKey[:])
	if err != nil {
		return nil, nil, err
	}
	var aeadNonce [AEADNonceLen]byte
	copy(aeadNonce[:], ci.ClientNonce[:AEADNonceLen])
	plain, err := aead.Open(nil, aeadNonce[:], ct, tHR[:])
	if err != nil {
		return nil, nil, ErrAEADHandshake
	}
	defer zero(plain)

	// Inner layout: timestamp || uuid || command || address || padlen || pad.
	if len(plain) < 4+UUIDLen+1+1+2 {
		return nil, nil, ErrPlaintextLayout
	}
	ch := &ClientHello{Nonce: [12]byte(ci.ClientNonce[:AEADNonceLen]), ClassicalPub: cliEphPub, PQPub: pqPub}
	ch.Timestamp = binary.BigEndian.Uint32(plain[:4])
	copy(ch.UUID[:], plain[4:4+UUIDLen])
	pos := 4 + UUIDLen
	ch.Command = Command(plain[pos]); pos++
	addr, n, err := DecodeAddress(plain[pos:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPlaintextLayout, err)
	}
	ch.Address = addr
	pos += n
	if len(plain) < pos+2 {
		return nil, nil, ErrPlaintextLayout
	}
	padLen := int(binary.BigEndian.Uint16(plain[pos:])); pos += 2
	if len(plain) != pos+padLen {
		return nil, nil, ErrPlaintextLayout
	}
	if ch.UUID != uuid {
		return nil, nil, ErrUUIDMismatch
	}
	if ch.Command != CommandTCP && ch.Command != CommandUDP {
		return nil, nil, ErrCommand
	}
	if absDiff(int64(ch.Timestamp), s.now().Unix()) > HandshakeTimestampWindow {
		return nil, nil, ErrReplay
	}

	tCH := v23Transcript(v23Suite.labelTCH, tHR[:], chWire)

	// Data-plane hybrid exchange.
	srvX25519Priv, err := curve.GenerateKey(crand.Reader)
	if err != nil {
		return nil, nil, err
	}
	classical, err := srvX25519Priv.ECDH(cliEph)
	if err != nil {
		return nil, nil, err
	}
	cliMLKEM, err := mlkem.NewEncapsulationKey768(pqPub[:])
	if err != nil {
		zero(classical)
		return nil, nil, err
	}
	pqShared, pqCipher := cliMLKEM.Encapsulate()

	var classicalArr [X25519PubLen]byte
	copy(classicalArr[:], classical)

	// ServerHello: server eph x25519 || mlkem ciphertext || AEAD(status) || sig.
	shBody := make([]byte, 0, X25519PubLen+MLKEM768CipherL)
	shBody = append(shBody, srvX25519Priv.PublicKey().Bytes()...)
	shBody = append(shBody, pqCipher...)

	// Traffic PRK from hybrid IKM bound to the transcript so far. The status
	// byte is encrypted under hello_key so the server proves possession before
	// the Finished round.
	ikm := append(append([]byte(nil), classicalArr[:]...), pqShared...)
	zero(classical)
	zero(pqShared)

	tSH := v23Transcript(v23Suite.labelTSH, tCH[:], shBody)
	trafficPRK, err := v23HKDF(ikm, v23Suite.labelTraffic, append(tSH[:], []byte(s.cfg.ServerID)...), 32)
	zero(ikm)
	if err != nil {
		return nil, nil, err
	}
	helloKeyBytes, err := v23HKDF(psk[:], v23Suite.labelHelloKey, tSH[:], AEADKeyLen)
	if err != nil {
		return nil, nil, err
	}
	var helloKey [AEADKeyLen]byte
	copy(helloKey[:], helloKeyBytes)
	zero(helloKeyBytes)
	helloAEAD, err := newHandshakeAEAD(helloKey)
	zero(helloKey[:])
	if err != nil {
		return nil, nil, err
	}
	var shNonce [AEADNonceLen]byte
	copy(shNonce[:], hr.ServerNonce[:AEADNonceLen])
	statusCt := helloAEAD.Seal(nil, shNonce[:], []byte{0x00}, tSH[:])

	shWire := append(shBody, statusCt...)
	// Signature over the ServerHello transcript authenticates the server.
	sigHash := v23Transcript(v23Suite.labelTSH, tCH[:], shWire)
	sig := ed25519.Sign(s.cfg.SigningKey, sigHash[:])
	shWire = append(shWire, sig...)

	finKeyC, err := v23HKDF(trafficPRK, v23Suite.labelFinC, []byte("client"), 32)
	if err != nil {
		return nil, nil, err
	}
	finKeyS, err := v23HKDF(trafficPRK, v23Suite.labelFinS, []byte("server"), 32)
	if err != nil {
		return nil, nil, err
	}
	keys := deriveV23SessionKeys(trafficPRK, classicalArr, ci.ClientNonce, hr.ServerNonce, tSH)

	return shWire, &V23ServerHelloResult{
		Keys:        keys,
		ClientHello: ch,
		TSH:         tSH,
		FinKeyC:     finKeyC,
		FinKeyS:     finKeyS,
		TrafficPRK:  trafficPRK,
		uuid:        uuid,
	}, nil
}

// ----------------------------------------------------------------------
// Finished exchange
// ----------------------------------------------------------------------

func v23FinishedVerifyData(finKey []byte, transcript [32]byte) [V23FinishedVrfLen]byte {
	h := hmac.New(sha256.New, finKey)
	h.Write(transcript[:])
	var out [V23FinishedVrfLen]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HandleClientFinished verifies the client's Finished and returns
// ServerFinished. Only after this returns nil may the handler run.
func (s *v23Server) HandleClientFinished(res *V23ServerHelloResult, cfWire []byte) (sfWire []byte, err error) {
	if len(cfWire) != V23FinishedVrfLen {
		return nil, ErrV23Finished
	}
	want := v23FinishedVerifyData(res.FinKeyC, res.TSH)
	if subtle.ConstantTimeCompare(want[:], cfWire) != 1 {
		return nil, ErrV23Finished
	}
	tCF := v23Transcript(v23Suite.labelTCF, res.TSH[:], cfWire)
	sf := v23FinishedVerifyData(res.FinKeyS, tCF)
	return sf[:], nil
}

// ReadV23ServerHello completes the client side of the ServerHello and emits
// ClientFinished.
func (s *V23ClientState) ReadV23ServerHello(msg []byte) (clientFinished []byte, res *HandshakeResult, err error) {
	if s == nil || s.closed || s.x25519Priv == nil {
		return nil, nil, ErrV23State
	}
	const minLen = X25519PubLen + MLKEM768CipherL + 1 + chacha20poly1305Overhead + ed25519.SignatureSize
	if len(msg) != minLen {
		return nil, nil, ErrHandshakeShort
	}
	off := 0
	var srvEphPub [X25519PubLen]byte
	copy(srvEphPub[:], msg[off:]); off += X25519PubLen
	var pqCipher [MLKEM768CipherL]byte
	copy(pqCipher[:], msg[off:]); off += MLKEM768CipherL
	statusLen := 1 + chacha20poly1305Overhead
	statusCt := msg[off : off+statusLen]; off += statusLen
	sig := msg[off:]

	shBody := msg[:X25519PubLen+MLKEM768CipherL]
	tSH := v23Transcript(v23Suite.labelTSH, s.tCH[:], shBody)

	// Verify server signature over the full ServerHello wire minus nothing.
	sigHash := v23Transcript(v23Suite.labelTSH, s.tCH[:], msg[:len(msg)-ed25519.SignatureSize])
	if !ed25519.Verify(s.serverPub, sigHash[:], sig) {
		return nil, nil, ErrV23Signature
	}

	// Hybrid decapsulation.
	curve := ecdh.X25519()
	srvEph, err := curve.NewPublicKey(srvEphPub[:])
	if err != nil {
		return nil, nil, err
	}
	classical, err := s.x25519Priv.ECDH(srvEph)
	if err != nil {
		return nil, nil, err
	}
	pqShared, err := s.mlkemPriv.Decapsulate(pqCipher[:])
	if err != nil {
		zero(classical)
		return nil, nil, err
	}
	var classicalArr [X25519PubLen]byte
	copy(classicalArr[:], classical)

	ikm := append(append([]byte(nil), classicalArr[:]...), pqShared...)
	zero(classical)
	zero(pqShared)

	trafficPRK, err := v23HKDF(ikm, v23Suite.labelTraffic, append(tSH[:], []byte(s.serverID)...), 32)
	zero(ikm)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt the status byte.
	psk := uuidPSK(s.uuid)
	helloKeyBytes, err := v23HKDF(psk[:], v23Suite.labelHelloKey, tSH[:], AEADKeyLen)
	if err != nil {
		return nil, nil, err
	}
	var helloKey [AEADKeyLen]byte
	copy(helloKey[:], helloKeyBytes)
	zero(helloKeyBytes)
	helloAEAD, err := newHandshakeAEAD(helloKey)
	zero(helloKey[:])
	if err != nil {
		return nil, nil, err
	}
	var shNonce [AEADNonceLen]byte
	copy(shNonce[:], s.retry.ServerNonce[:AEADNonceLen])
	status, err := helloAEAD.Open(nil, shNonce[:], statusCt, tSH[:])
	if err != nil || len(status) != 1 || status[0] != 0x00 {
		return nil, nil, ErrV23Finished
	}

	finKeyC, err := v23HKDF(trafficPRK, v23Suite.labelFinC, []byte("client"), 32)
	if err != nil {
		return nil, nil, err
	}
	finKeyS, err := v23HKDF(trafficPRK, v23Suite.labelFinS, []byte("server"), 32)
	if err != nil {
		return nil, nil, err
	}

	cf := v23FinishedVerifyData(finKeyC, tSH)
	keys := deriveV23SessionKeys(trafficPRK, classicalArr, s.init.ClientNonce, s.retry.ServerNonce, tSH)

	s.closed = true
	s.x25519Priv = nil
	s.mlkemPriv = nil
	zero(s.outerECDH)

	copy(s.clientFin[:], cf[:])
	s.tServerH = tSH
	s.finKeyS = finKeyS
	res = &HandshakeResult{Keys: keys, ServerHello: &ServerHello{NonceEcho: [12]byte(s.init.ClientNonce[:AEADNonceLen])}}
	return cf[:], res, nil
}

// ReadV23ServerFinished verifies the server's Finished: the server must
// prove it derived the same traffic PRK by producing
// HMAC(fin_key_s, T_cf) where T_cf covers T_sh and our ClientFinished.
func (s *V23ClientState) ReadV23ServerFinished(sfWire []byte) error {
	if len(sfWire) != V23FinishedVrfLen || len(s.finKeyS) == 0 {
		return ErrV23Finished
	}
	tCF := v23Transcript(v23Suite.labelTCF, s.tServerH[:], s.clientFin[:])
	want := v23FinishedVerifyData(s.finKeyS, tCF)
	if subtle.ConstantTimeCompare(want[:], sfWire) != 1 {
		return ErrV23Finished
	}
	zero(s.finKeyS)
	s.finKeyS = nil
	return nil
}

// deriveV23SessionKeys derives per-direction keys from the v2.3 traffic PRK.
//
// Unlike v2.1/v2.2, both nonces are independent random values (the server
// nonce is not an echo), and the nonce *prefixes* are derived from the full
// traffic transcript T_sh rather than from a 4-byte KDF output. This makes
// prefix reuse across handshakes cryptographically impossible instead of
// merely improbable: any change in either nonce, either ephemeral key, or
// any handshake message changes T_sh and therefore both prefixes.
func deriveV23SessionKeys(trafficPRK []byte, classical [X25519PubLen]byte, cNonce [V23ClientNonceLen]byte, sNonce [V23ServerNonceLen]byte, tSH [32]byte) SessionKeys {
	salt := append(append([]byte(v23Suite.labelTraffic), cNonce[:]...), sNonce[:]...)
	prk := hkdf.Extract(sha256.New, trafficPRK, salt)
	var sk SessionKeys
	if err := expand(prk, v23Suite.c2sKey, sk.C2SKey[:]); err != nil {
		panic(v23Name + ": derive C2S key: " + err.Error())
	}
	if err := expand(prk, v23Suite.s2cKey, sk.S2CKey[:]); err != nil {
		panic(v23Name + ": derive S2C key: " + err.Error())
	}
	// 8-byte prefixes derived from the transcript, not from the legacy
	// 4-byte label expansion. The remaining 4 bytes of the 12-byte AEAD
	// nonce still carry the record counter.
	deriveV23NoncePrefix(prk, v23Suite.c2sNonce, tSH[:], sk.C2SNonce[:])
	deriveV23NoncePrefix(prk, v23Suite.s2cNonce, tSH[:], sk.S2CNonce[:])
	if err := expand(prk, v23Suite.sessionID, sk.SessionID[:]); err != nil {
		panic(v23Name + ": derive SessionID: " + err.Error())
	}
	sk.version = protocolVersionV22 // share the v2.2 opaque record layer
	return sk
}

// deriveV23NoncePrefix expands an 8-byte nonce prefix from the traffic PRK
// bound to the transcript. It is separate from deriveSessionKeys' 4-byte
// expansion so the legacy path is untouched.
func deriveV23NoncePrefix(prk []byte, label string, transcript []byte, out []byte) {
	r := hkdf.Expand(sha256.New, prk, append([]byte(label), transcript...))
	// Read 8 bytes; callers copy into their prefix storage.
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		panic(v23Name + ": derive nonce prefix: " + err.Error())
	}
	copy(out, buf[:NoncePrefixLen])
	zero(buf)
}
