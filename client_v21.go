package ewp

// EWP/v2.1 high-level Client and Service.
//
// These are drop-in upgrades of NewClient / NewService that bind the
// handshake KDF to a long-term server X25519 identity, closing audit
// findings S1, S2, and H2.
//
// New callers SHOULD use NewClientV21 / NewServiceV21. The original
// NewClient / NewService remain in place but are now considered
// deprecated; they speak the v2.0 wire which the v2.1 server will
// REJECT, so a mismatched pair fails closed.

import (
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
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
type ClientV21 struct {
	uuid            [UUIDLen]byte
	serverStaticPub [X25519PubLen]byte
}

// NewClientV21 parses a UUID string and a base64-encoded 32-byte
// X25519 public key (the genuine server's long-term identity) and
// returns a ready ClientV21.
//
// serverStaticPubB64 is REQUIRED; passing the empty string is an
// error. Operators that wish to opt out of server identity binding
// should use the legacy NewClient (which speaks v2.0 and is vulnerable
// to S1 / S2 / H2).
func NewClientV21(uuidStr, serverStaticPubB64 string) (*ClientV21, error) {
	u, err := ParseUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(serverStaticPubB64)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: server_static_pub: %w", err)
	}
	if len(pub) != X25519PubLen {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrStaticPub, X25519PubLen, len(pub))
	}
	if _, err := ecdh.X25519().NewPublicKey(pub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStaticPub, err)
	}
	c := &ClientV21{uuid: u}
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
	return &streamConn{
		SecureStream: stream,
		underlying:   conn,
	}, nil
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
	if dl, ok := ctx.Deadline(); ok {
		if dc, ok := tr.(deadlineSetter); ok {
			_ = dc.SetDeadline(dl)
			defer func() { _ = dc.SetDeadline(time.Time{}) }()
		}
	}

	state, err := WriteClientHelloV21(tr.SendMessage, c.uuid, cmd, dst, c.serverStaticPub[:])
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.1: write ClientHello: %w", err)
	}
	shBytes, err := tr.ReadMessage()
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.1: read ServerHello: %w", err)
	}
	res, err := state.ReadServerHelloV21(shBytes, c.serverStaticPub[:])
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.1: process ServerHello: %w", err)
	}
	stream, err := NewClientSecureStream(tr, res.Keys)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.1: build SecureStream: %w", err)
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
type ServiceV21 struct {
	handler   Handler
	staticPriv *ecdh.PrivateKey

	usersMu sync.RWMutex
	users   [][UUIDLen]byte
	lookup  UUIDLookupV21

	replay *ReplayCache
}

// NewServiceV21 builds a Service that authenticates clients under the
// v2.1 KDF chain. staticPrivB64 is the base64-encoded 32-byte X25519
// scalar; the matching public key MUST be distributed to every
// authorised client (see ClientV21.serverStaticPub).
func NewServiceV21(h Handler, staticPrivB64 string) (*ServiceV21, error) {
	if h == nil {
		return nil, errors.New("ewp/v2.1: NewServiceV21: handler is nil")
	}
	scalar, err := base64.StdEncoding.DecodeString(staticPrivB64)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.1: server_static_priv: %w", err)
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
	s.replay = cache
	s.usersMu.Unlock()
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
		return errors.New("ewp/v2.1: no users configured")
	}

	if dl, ok := ctx.Deadline(); ok {
		if dc, ok := tr.(deadlineSetter); ok {
			_ = dc.SetDeadline(dl)
		}
	}

	helloIn, err := tr.ReadMessage()
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.1: read ClientHello: %w", err)
	}
	helloOut, res, err := AcceptClientHelloV21WithReplay(helloIn, lookup, staticPriv, replay)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.1: accept ClientHello: %w", err)
	}
	if err := tr.SendMessage(helloOut); err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.1: send ServerHello: %w", err)
	}

	stream, err := NewServerSecureStream(tr, res.Keys)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.1: build server SecureStream: %w", err)
	}

	if dc, ok := tr.(deadlineSetter); ok {
		_ = dc.SetDeadline(time.Time{})
	}

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
		return s.handler.NewConnection(ctx, appConn, meta)
	case CommandUDP:
		ev, err := stream.Recv()
		if err != nil {
			_ = stream.Close()
			return fmt.Errorf("ewp/v2.1: read initial UDP_NEW: %w", err)
		}
		if ev.Type != FrameUDPNew {
			_ = stream.Close()
			return fmt.Errorf("ewp/v2.1: expected UDP_NEW first, got frame type %d", ev.Type)
		}
		dst := res.ClientHello.Address
		if ev.HasAddr {
			dst = ev.Address
		}
		appPC := newServerPacketConn(stream, underlying, ev.GlobalID, dst, ev.Payload)
		return s.handler.NewPacketConnection(ctx, appPC, meta)
	default:
		_ = stream.Close()
		return fmt.Errorf("ewp/v2.1: unsupported command %d", res.ClientHello.Command)
	}
}

// Compile-time assertion that ServiceV21 has the same I/O surface as
// Service for the typical accept-loop call pattern.
var _ = io.EOF
