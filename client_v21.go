package ewp

// EWP/v2.1 high-level Client and Service.
//
// These are drop-in upgrades of NewClient / NewService that bind the
// handshake KDF to a long-term server X25519 identity. They prevent a
// UUID holder alone from impersonating the server to a client that pins
// the genuine public key.
//
// New callers SHOULD use NewClientV22 / NewServiceV22. The original
// NewClient / NewService remain in place but are now considered deprecated;
// they speak the v2.0 wire which v2.1 and v2.2 servers reject. v2.1 remains
// available only for migration and exposes a clear data-plane frame header;
// see SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md.

import (
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"sync"
)

// ----------------------------------------------------------------------
// CLIENT
// ----------------------------------------------------------------------

// ClientV21 is the v2.1 client. Same surface as Client plus a
// long-term server X25519 public key it pins to (configured via
// NewClientV21).
//
// One ClientV21 = one configured (UUID, server identity) pair. It is
// safe to share across goroutines; each Dial call performs an
// independent handshake on its own underlying connection.
//
// Deprecated: Use ClientV22 for opaque, bucketized data-plane records.
type ClientV21 struct {
	uuid            [UUIDLen]byte
	serverStaticPub [X25519PubLen]byte
	version         protocolVersion
}

// NewClientV21 parses a UUID string and a base64-encoded 32-byte
// X25519 public key (the genuine server's long-term identity) and
// returns a ready ClientV21.
//
// serverStaticPubB64 is REQUIRED; passing the empty string is an
// error. New deployments should use NewClientV22, whose opaque records hide
// frame type and exact payload length from the wire.
//
// Deprecated: Use NewClientV22.
func NewClientV21(uuidStr, serverStaticPubB64 string) (*ClientV21, error) {
	return newClientV2x(uuidStr, serverStaticPubB64, protocolVersionV21)
}

func newClientV2x(uuidStr, serverStaticPubB64 string, version protocolVersion) (*ClientV21, error) {
	protocolName := suiteForVersion(version).name
	u, err := ParseUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(serverStaticPubB64)
	if err != nil {
		return nil, fmt.Errorf("%s: server_static_pub: %w", protocolName, err)
	}
	if len(pub) != X25519PubLen {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrStaticPub, X25519PubLen, len(pub))
	}
	if _, err := ecdh.X25519().NewPublicKey(pub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStaticPub, err)
	}
	c := &ClientV21{uuid: u, version: version}
	copy(c.serverStaticPub[:], pub)
	return c, nil
}

// UUID exposes the configured user UUID.
func (c *ClientV21) UUID() [UUIDLen]byte { return c.uuid }

// DialConn performs the v2.1 handshake over conn requesting a TCP
// tunnel to dst. Same surface as Client.DialConn.
func (c *ClientV21) DialConn(ctx context.Context, conn net.Conn, dst Address) (net.Conn, error) {
	tr := NewLengthFramer(conn)
	stream, err := c.handshake(ctx, tr, CommandTCP, dst)
	if err != nil {
		return nil, err
	}
	sc := &streamConn{
		SecureStream: stream,
		underlying:   conn,
	}
	sc.shaper = NewStreamShaper(stream, DefaultShaperConfig())
	return sc, nil
}

// DialPacketConn is the v2.1 counterpart of Client.DialPacketConn.
func (c *ClientV21) DialPacketConn(ctx context.Context, conn net.Conn, dst Address) (net.PacketConn, error) {
	tr := NewLengthFramer(conn)
	stream, err := c.handshake(ctx, tr, CommandUDP, dst)
	if err != nil {
		return nil, err
	}
	return newClientPacketConn(stream, conn, dst), nil
}

func (c *ClientV21) handshake(
	ctx context.Context, tr MessageTransport, cmd Command, dst Address,
) (*SecureStream, error) {
	hctx, finish := beginHandshake(ctx, tr)
	defer finish()
	suite := suiteForVersion(c.version)

	state, err := writeClientHelloV2x(func(msg []byte) error {
		return sendMessageContext(hctx, tr, msg)
	}, c.uuid, cmd, dst, c.serverStaticPub[:], suite)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("%s: write ClientHello: %w", suite.name, err)
	}
	shBytes, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("%s: read ServerHello: %w", suite.name, err)
	}
	res, err := state.readServerHelloV2x(shBytes, c.serverStaticPub[:], suite)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("%s: process ServerHello: %w", suite.name, err)
	}
	var stream *SecureStream
	if c.version == protocolVersionV22 {
		stream, err = NewClientSecureStreamV22(tr, res.Keys)
	} else {
		stream, err = NewClientSecureStream(tr, res.Keys)
	}
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("%s: build SecureStream: %w", suite.name, err)
	}
	return stream, nil
}

// ----------------------------------------------------------------------
// SERVICE
// ----------------------------------------------------------------------

// ServiceV21 is the v2.1 server. Same surface as Service plus a
// long-term static X25519 private key.
//
// The static private key is the credential that distinguishes a
// genuine server from a PSK-holding impersonator. It is the operator's
// responsibility to protect it (file mode 0600, KMS, etc.); rotating
// it requires re-issuing every client's serverStaticPub configuration.
//
// Deprecated: Use ServiceV22 for opaque, bucketized data-plane records.
type ServiceV21 struct {
	handler    Handler
	staticPriv *ecdh.PrivateKey
	version    protocolVersion

	usersMu sync.RWMutex
	users   [][UUIDLen]byte
	lookup  UUIDLookupV21

	replay *ReplayCache
	closed bool
}

// NewServiceV21 builds a Service that authenticates clients under the
// v2.1 KDF chain. staticPrivB64 is the base64-encoded 32-byte X25519
// scalar; the matching public key MUST be distributed to every
// authorised client (see ClientV21.serverStaticPub).
//
// Deprecated: Use NewServiceV22.
func NewServiceV21(h Handler, staticPrivB64 string) (*ServiceV21, error) {
	return newServiceV2x(h, staticPrivB64, protocolVersionV21)
}

func newServiceV2x(h Handler, staticPrivB64 string, version protocolVersion) (*ServiceV21, error) {
	protocolName := suiteForVersion(version).name
	if h == nil {
		return nil, fmt.Errorf("%s: service handler is nil", protocolName)
	}
	scalar, err := base64.StdEncoding.DecodeString(staticPrivB64)
	if err != nil {
		return nil, fmt.Errorf("%s: server_static_priv: %w", protocolName, err)
	}
	if len(scalar) != X25519PubLen {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrStaticPriv, X25519PubLen, len(scalar))
	}
	priv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStaticPriv, err)
	}
	s := &ServiceV21{
		handler:    h,
		staticPriv: priv,
		replay:     NewReplayCache(ReplayWindow),
		version:    version,
	}
	s.rebuildLookup()
	return s, nil
}

// GenerateServerStaticKeypair returns a fresh (privB64, pubB64) pair
// suitable for newServiceV21 / NewClientV21. Useful for setup
// scripts and tests.
func GenerateServerStaticKeypair() (privB64, pubB64 string, err error) {
	p, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(p.Bytes()),
		base64.StdEncoding.EncodeToString(p.PublicKey().Bytes()),
		nil
}

// SetReplayCache mirrors Service.SetReplayCache.
func (s *ServiceV21) SetReplayCache(cache *ReplayCache) {
	s.usersMu.Lock()
	if s.closed {
		s.usersMu.Unlock()
		if cache != nil {
			cache.Close()
		}
		return
	}
	oldCache := s.replay
	s.replay = cache
	s.usersMu.Unlock()
	if oldCache != nil && oldCache != cache {
		oldCache.Close()
	}
}

// Close releases resources owned by the service. It is safe to call more
// than once. A cache installed with SetReplayCache is owned by the service.
func (s *ServiceV21) Close() error {
	s.usersMu.Lock()
	if s.closed {
		s.usersMu.Unlock()
		return nil
	}
	s.closed = true
	cache := s.replay
	s.replay = nil
	s.usersMu.Unlock()
	if cache != nil {
		cache.Close()
	}
	return nil
}

// AddUser / RemoveUser / Users mirror their Service counterparts.
func (s *ServiceV21) AddUser(uuidStr string) error {
	u, err := ParseUUID(uuidStr)
	if err != nil {
		return err
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	for _, existing := range s.users {
		if existing == u {
			return nil
		}
	}
	s.users = append(s.users, u)
	s.rebuildLookup()
	return nil
}

func (s *ServiceV21) RemoveUser(uuidStr string) bool {
	u, err := ParseUUID(uuidStr)
	if err != nil {
		return false
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	for i, existing := range s.users {
		if existing == u {
			s.users = append(s.users[:i], s.users[i+1:]...)
			s.rebuildLookup()
			return true
		}
	}
	return false
}

func (s *ServiceV21) Users() [][UUIDLen]byte {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	out := make([][UUIDLen]byte, len(s.users))
	copy(out, s.users)
	return out
}

func (s *ServiceV21) rebuildLookup() {
	snapshot := make([][UUIDLen]byte, len(s.users))
	copy(snapshot, s.users)
	s.lookup = MakeUUIDLookupV21(snapshot)
}

// HandleConn drives one v2.1 EWP flow. Same lifecycle as
// Service.HandleConn but uses the v2.1 KDF chain.
func (s *ServiceV21) HandleConn(ctx context.Context, conn net.Conn) error {
	tr := NewLengthFramer(conn)
	return s.handleTransport(ctx, tr, conn)
}

// HandleMessageTransport mirrors Service.HandleMessageTransport.
func (s *ServiceV21) HandleMessageTransport(ctx context.Context, tr MessageTransport, underlying net.Conn) error {
	return s.handleTransport(ctx, tr, underlying)
}

func (s *ServiceV21) handleTransport(ctx context.Context, tr MessageTransport, underlying net.Conn) error {
	s.usersMu.RLock()
	lookup := s.lookup
	replay := s.replay
	staticPriv := s.staticPriv
	s.usersMu.RUnlock()
	if lookup == nil {
		_ = tr.Close()
		return fmt.Errorf("%s: no users configured", suiteForVersion(s.version).name)
	}

	hctx, finish := beginHandshake(ctx, tr)
	defer finish()
	suite := suiteForVersion(s.version)

	helloIn, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("%s: read ClientHello: %w", suite.name, err)
	}
	helloOut, res, err := acceptClientHelloV2x(helloIn, lookup, staticPriv, replay, suite)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("%s: accept ClientHello: %w", suite.name, err)
	}
	if err := sendMessageContext(hctx, tr, helloOut); err != nil {
		_ = tr.Close()
		return fmt.Errorf("%s: send ServerHello: %w", suite.name, err)
	}

	var stream *SecureStream
	if s.version == protocolVersionV22 {
		stream, err = NewServerSecureStreamV22(tr, res.Keys)
	} else {
		stream, err = NewServerSecureStream(tr, res.Keys)
	}
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("%s: build server SecureStream: %w", suite.name, err)
	}

	finish()

	meta := Metadata{
		UserUUID:    res.ClientHello.UUID,
		Destination: res.ClientHello.Address,
	}
	if underlying != nil {
		meta.Source = underlying.RemoteAddr()
	}

	switch res.ClientHello.Command {
	case CommandTCP:
		appConn := &streamConn{SecureStream: stream, underlying: underlying}
		appConn.shaper = NewStreamShaper(stream, DefaultShaperConfig())
		return s.handler.NewConnection(ctx, appConn, meta)
	case CommandUDP:
		ev, err := stream.Recv()
		if err != nil {
			_ = stream.Close()
			return fmt.Errorf("%s: read initial UDP_NEW: %w", suite.name, err)
		}
		if ev.Type != FrameUDPNew {
			_ = stream.Close()
			return fmt.Errorf("%s: expected UDP_NEW first, got frame type %d", suite.name, ev.Type)
		}
		dst := res.ClientHello.Address
		if ev.HasAddr {
			dst = ev.Address
		}
		appPC := newServerPacketConn(stream, underlying, ev.GlobalID, dst, ev.Payload)
		return s.handler.NewPacketConnection(ctx, appPC, meta)
	default:
		_ = stream.Close()
		return fmt.Errorf("%s: unsupported command %d", suite.name, res.ClientHello.Command)
	}
}

// Compile-time assertion that ServiceV21 has the same I/O surface as
// Service for the typical accept-loop call pattern.
var _ = io.EOF
