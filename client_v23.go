package ewp

import (
	"context"
	crand "crypto/rand"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"
)

// ClientV23 is the EWP/v2.3 client. It performs the six-stage handshake
// (ClientInit, HelloRetry, ClientHello, ServerHello, ClientFinished,
// ServerFinished) with transcript-bound keys and a signed short-term outer
// key for ClientHello forward secrecy. There is no fallback to v2.1/v2.2.
type ClientV23 struct {
	uuid       [UUIDLen]byte
	serverID   string
	routeEpoch uint64
	serverPub  ed25519.PublicKey
}

// NewClientV23 builds a v2.3 client.
//
//   - uuidStr: user UUID (same format as v2.1/v2.2).
//   - serverID: the listener identifier; must match the server exactly.
//   - serverPubB64: base64-encoded Ed25519 public key that signs the
//     server's short-term outer keys and ServerHello transcripts.
//   - routeEpoch: routes sharing epoch; 0 unless the operator rotates routes.
func NewClientV23(uuidStr, serverID, serverPubB64 string, routeEpoch uint64) (*ClientV23, error) {
	uuid, err := ParseUUID(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("ewp/v2.3: uuid: %w", err)
	}
	pubRaw, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ewp/v2.3: server public key: %w", ErrV23Signature)
	}
	if serverID == "" || len(serverID) > 255 {
		return nil, fmt.Errorf("ewp/v2.3: invalid server_id")
	}
	return &ClientV23{
		uuid:       uuid,
		serverID:   serverID,
		routeEpoch: routeEpoch,
		serverPub:  append(ed25519.PublicKey(nil), pubRaw...),
	}, nil
}

// UUID returns the configured user UUID.
func (c *ClientV23) UUID() [UUIDLen]byte { return c.uuid }

// DialConn performs the v2.3 handshake over conn and returns an opaque-record
// TCP stream. The returned conn owns the transport.
func (c *ClientV23) DialConn(ctx context.Context, conn net.Conn, dst Address) (net.Conn, error) {
	tr := NewLengthFramer(conn)
	stream, err := c.handshake(ctx, tr, CommandTCP, dst)
	if err != nil {
		return nil, err
	}
	sc := &streamConn{SecureStream: stream, underlying: conn}
	sc.shaper = NewStreamShaper(stream, DefaultShaperConfig())
	return sc, nil
}

// DialPacketConn performs the v2.3 handshake and returns an opaque-record
// UDP-over-TCP packet conn.
func (c *ClientV23) DialPacketConn(ctx context.Context, conn net.Conn, dst Address) (net.PacketConn, error) {
	tr := NewLengthFramer(conn)
	stream, err := c.handshake(ctx, tr, CommandUDP, dst)
	if err != nil {
		return nil, err
	}
	return newClientPacketConn(stream, conn, dst), nil
}

func (c *ClientV23) handshake(ctx context.Context, tr MessageTransport, cmd Command, dst Address) (*SecureStream, error) {
	hctx, finish := beginHandshake(ctx, tr)
	defer finish()

	state, err := WriteV23ClientInit(func(msg []byte) error {
		return sendMessageContext(hctx, tr, msg)
	}, c.uuid, c.serverID, c.routeEpoch, c.serverPub)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: send ClientInit: %w", err)
	}
	hrWire, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: read HelloRetry: %w", err)
	}
	chWire, err := state.ReadV23HelloRetry(hrWire, cmd, dst)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: build ClientHello: %w", err)
	}
	if err := sendMessageContext(hctx, tr, chWire); err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: send ClientHello: %w", err)
	}
	shWire, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: read ServerHello: %w", err)
	}
	cfWire, res, err := state.ReadV23ServerHello(shWire)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: process ServerHello: %w", err)
	}
	if err := sendMessageContext(hctx, tr, cfWire); err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: send ClientFinished: %w", err)
	}
	sfWire, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: read ServerFinished: %w", err)
	}
	if err := state.ReadV23ServerFinished(sfWire); err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: verify ServerFinished: %w", err)
	}

	stream, err := NewClientSecureStreamV22(tr, res.Keys)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp/v2.3: build SecureStream: %w", err)
	}
	return stream, nil
}

// ----------------------------------------------------------------------
// ServiceV23
// ----------------------------------------------------------------------

// ServiceV23 is the EWP/v2.3 server. It replaces the static X25519 identity
// with an Ed25519 signing key and a rotating short-term outer key, and gates
// handler dispatch behind the Finished exchange.
type ServiceV23 struct {
	handler Handler
	cfg     V23ServerConfig

	mu      sync.RWMutex
	server  *v23Server
	users   [][UUIDLen]byte
	closed  bool
}

// NewServiceV23 builds a v2.3 service.
//
//   - signingPrivB64: base64-encoded 64-byte Ed25519 private key used to
//     sign short-term outer keys and ServerHello transcripts.
//   - serverID: listener identifier distributed to clients.
//   - routeEpoch: 0 unless rotating route tags.
func NewServiceV23(h Handler, signingPrivB64, serverID string, routeEpoch uint64) (*ServiceV23, error) {
	if h == nil {
		return nil, fmt.Errorf("ewp/v2.3: service handler is nil")
	}
	privRaw, err := base64.StdEncoding.DecodeString(signingPrivB64)
	if err != nil || len(privRaw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ewp/v2.3: signing key: %w", ErrV23Signature)
	}
	if serverID == "" || len(serverID) > 255 {
		return nil, fmt.Errorf("ewp/v2.3: invalid server_id")
	}
	var cookieKey [32]byte
	if _, err := crand.Read(cookieKey[:]); err != nil {
		return nil, err
	}
	s := &ServiceV23{
		handler: h,
		cfg: V23ServerConfig{
			ServerID:   serverID,
			RouteEpoch: routeEpoch,
			SigningKey: append(ed25519.PrivateKey(nil), privRaw...),
			CookieKey:  cookieKey,
		},
	}
	if err := s.rebuildLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// AddUser registers a UUID. Safe to call concurrently with HandleConn.
func (s *ServiceV23) AddUser(uuidStr string) error {
	uuid, err := ParseUUID(uuidStr)
	if err != nil {
		return fmt.Errorf("ewp/v2.3: uuid: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = append(s.users, uuid)
	return s.rebuildLocked()
}

// RemoveUser deregisters a UUID.
func (s *ServiceV23) RemoveUser(uuidStr string) error {
	uuid, err := ParseUUID(uuidStr)
	if err != nil {
		return fmt.Errorf("ewp/v2.3: uuid: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.users[:0]
	for _, u := range s.users {
		if u != uuid {
			out = append(out, u)
		}
	}
	s.users = out
	return s.rebuildLocked()
}

func (s *ServiceV23) rebuildLocked() error {
	s.cfg.UUIDs = append([][UUIDLen]byte(nil), s.users...)
	srv, err := newV23Server(&s.cfg)
	if err != nil {
		return err
	}
	old := s.server
	s.server = srv
	if old != nil && old.replay != nil {
		old.replay.Close()
	}
	return nil
}

// HandleConn drives one v2.3 EWP flow over a byte-stream carrier.
func (s *ServiceV23) HandleConn(ctx context.Context, conn net.Conn) error {
	return s.handleTransport(ctx, NewLengthFramer(conn), conn)
}

// HandleMessageTransport drives one v2.3 flow over a message carrier.
func (s *ServiceV23) HandleMessageTransport(ctx context.Context, tr MessageTransport, underlying net.Conn) error {
	return s.handleTransport(ctx, tr, underlying)
}

func (s *ServiceV23) handleTransport(ctx context.Context, tr MessageTransport, underlying net.Conn) error {
	s.mu.RLock()
	server := s.server
	s.mu.RUnlock()
	if server == nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: service closed")
	}

	hctx, finish := beginHandshake(ctx, tr)
	defer finish()

	source := ""
	if underlying != nil && underlying.RemoteAddr() != nil {
		source = underlying.RemoteAddr().String()
	}

	initWire, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: read ClientInit: %w", err)
	}
	hrWire, err := server.HandleClientInit(initWire, source)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: answer ClientInit: %w", err)
	}
	if err := sendMessageContext(hctx, tr, hrWire); err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: send HelloRetry: %w", err)
	}
	chWire, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: read ClientHello: %w", err)
	}
	shWire, res, err := server.HandleClientHello(hctx, initWire, hrWire, chWire, source)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: accept ClientHello: %w", err)
	}
	if err := sendMessageContext(hctx, tr, shWire); err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: send ServerHello: %w", err)
	}
	cfWire, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: read ClientFinished: %w", err)
	}
	sfWire, err := server.HandleClientFinished(res, cfWire)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: verify ClientFinished: %w", err)
	}
	if err := sendMessageContext(hctx, tr, sfWire); err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: send ServerFinished: %w", err)
	}

	stream, err := NewServerSecureStreamV22(tr, res.Keys)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp/v2.3: build server SecureStream: %w", err)
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
		// The host handler may hand the connection to an asynchronous
		// router and return from NewConnection immediately (sing-box's
		// RouteConnectionEx does exactly that). If we returned right
		// away, the caller of HandleConn would consider the flow done
		// and tear down the carrier underneath the router — transports
		// whose handler lifetime equals the connection lifetime (gRPC:
		// the Tun handler returns → stream closes) break instantly.
		// Wait until the connection is actually closed (or the service
		// is shut down) before returning. A handler that returns an
		// error still tears the carrier down immediately.
		connClosed := make(chan struct{})
		appConn := &streamConn{
			SecureStream: stream,
			underlying:   underlying,
			onClose:      func() { close(connClosed) },
		}
		appConn.shaper = NewStreamShaper(stream, DefaultShaperConfig())
		if err := s.handler.NewConnection(ctx, appConn, meta); err != nil {
			_ = stream.Close()
			return err
		}
		select {
		case <-connClosed:
		case <-ctx.Done():
		}
		return nil
	case CommandUDP:
		ev, err := stream.Recv()
		if err != nil {
			_ = stream.Close()
			return fmt.Errorf("ewp/v2.3: read initial UDP_NEW: %w", err)
		}
		if ev.Type != FrameUDPNew {
			_ = stream.Close()
			return fmt.Errorf("ewp/v2.3: expected UDP_NEW first, got frame type %d", ev.Type)
		}
		dst := res.ClientHello.Address
		if ev.HasAddr {
			dst = ev.Address
		}
		// Same handoff rule as the TCP branch: the host may dispatch the
		// packet session to an asynchronous router and return from
		// NewPacketConnection immediately. Wait for the session to close
		// (or the service to shut down) before returning, so transports
		// whose handler lifetime equals the connection lifetime (gRPC)
		// do not tear the carrier down underneath the router.
		pcClosed := make(chan struct{})
		appPC := newServerPacketConn(stream, underlying, ev.GlobalID, dst, ev.Payload)
		appPC.onClose = func() { close(pcClosed) }
		if err := s.handler.NewPacketConnection(ctx, appPC, meta); err != nil {
			_ = stream.Close()
			return err
		}
		select {
		case <-pcClosed:
		case <-ctx.Done():
		}
		return nil
	default:
		_ = stream.Close()
		return fmt.Errorf("ewp/v2.3: unsupported command %d", res.ClientHello.Command)
	}
}

// Close stops the service. In-flight handshakes are interrupted by their
// own context / transport deadlines.
func (s *ServiceV23) Close() error {
	s.mu.Lock()
	s.closed = true
	server := s.server
	s.server = nil
	s.mu.Unlock()
	if server != nil && server.replay != nil {
		server.replay.Close()
	}
	return nil
}

// GenerateSigningIdentity produces a fresh Ed25519 keypair for a v2.3
// server. The private key goes to NewServiceV23; the public key is pinned
// in every client's NewClientV23 call.
func GenerateSigningIdentity() (privB64, pubB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv),
		base64.StdEncoding.EncodeToString(pub), nil
}

// startOuterKeyRotation is a helper for servers that want automatic
// short-term key rotation. It is not started by default; production callers
// should rotate on their own schedule via the outer key store.
func (s *ServiceV23) rotateOuterKeyNow() error {
	s.mu.RLock()
	server := s.server
	s.mu.RUnlock()
	if server == nil {
		return fmt.Errorf("ewp/v2.3: service closed")
	}
	server.keys.mu.Lock()
	defer server.keys.mu.Unlock()
	return server.keys.rotateLocked(time.Now())
}
