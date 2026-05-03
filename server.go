package ewp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Handler is the application-side hook invoked by Service after a
// successful EWP v2 handshake.
//
// Implementations decide what to do with the proxied flow: typically
// the sing-box outbound dispatcher dials the requested destination and
// pipes bytes both ways.
//
// Handler methods MUST eventually close the supplied conn /
// packetConn.
type Handler interface {
	// NewConnection is called for a CommandTCP handshake. conn carries
	// the application byte stream after EWP encryption is removed.
	NewConnection(ctx context.Context, conn net.Conn, metadata Metadata) error

	// NewPacketConnection is called for a CommandUDP handshake. The
	// returned PacketConn lets the handler send/receive UDP datagrams
	// through the tunnel.
	NewPacketConnection(ctx context.Context, conn net.PacketConn, metadata Metadata) error
}

// Metadata describes a freshly-handshaked EWP flow.
type Metadata struct {
	// UserUUID identifies the authenticated user (the UUID resolved by
	// the configured UUIDLookup).
	UserUUID [UUIDLen]byte

	// Destination is the address the client wants to reach, as parsed
	// from the inner ClientHello. For UDP flows this is the
	// "anchor" / default target — per-packet targets may differ.
	Destination Address

	// Source is the EWP server's view of where the client connected
	// from (typically the remote end of the underlying transport
	// connection). Implementations may use it for ACL / logging.
	Source net.Addr
}

// Service is the high-level EWP v2 server.
//
// The Service does NOT own a listener: the caller is responsible for
// accepting underlying transport connections (TLS, WebSocket, etc.)
// and handing each established net.Conn to HandleConn.
//
// Concurrency: HandleConn is goroutine-safe and is the typical entry
// point from a transport "accept" loop.
type Service struct {
	handler Handler

	usersMu sync.RWMutex
	users   [][UUIDLen]byte
	lookup  UUIDLookup // rebuilt on user changes

	// replay defends against duplicate ClientHello within the
	// handshake timestamp window. Always enabled for new Services
	// created via NewService; tests that need to disable it can call
	// SetReplayCache(nil).
	replay *ReplayCache
}

// NewService creates a Service that dispatches handshaked flows to h.
//
// The returned Service has anti-replay enabled by default with a
// ReplayWindow-sized cache; call SetReplayCache to override (e.g. to
// install a custom-sized cache or disable for tests).
func NewService(h Handler) *Service {
	if h == nil {
		panic("ewp: NewService: handler is nil")
	}
	s := &Service{
		handler: h,
		replay:  NewReplayCache(ReplayWindow),
	}
	s.rebuildLookup()
	return s
}

// SetReplayCache replaces the Service's anti-replay cache. Pass nil to
// disable replay protection entirely (NOT recommended outside tests).
//
// Safe to call concurrently with HandleConn — the swap is atomic from
// the perspective of in-flight handshakes (they may use either the
// old or the new cache, never a torn state).
func (s *Service) SetReplayCache(cache *ReplayCache) {
	s.usersMu.Lock()
	s.replay = cache
	s.usersMu.Unlock()
}

// AddUser registers a UUID. Duplicates are ignored.
func (s *Service) AddUser(uuidStr string) error {
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

// RemoveUser unregisters a UUID. Returns false if it was not present.
func (s *Service) RemoveUser(uuidStr string) bool {
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

// Users returns a snapshot of currently-registered UUIDs.
func (s *Service) Users() [][UUIDLen]byte {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	out := make([][UUIDLen]byte, len(s.users))
	copy(out, s.users)
	return out
}

func (s *Service) rebuildLookup() {
	// Caller already holds usersMu.
	snapshot := make([][UUIDLen]byte, len(s.users))
	copy(snapshot, s.users)
	s.lookup = MakeUUIDLookup(snapshot)
}

// HandleConn drives one EWP v2 flow on conn:
//
//  1. Reads ClientHello, runs AcceptClientHello.
//  2. Sends ServerHello, builds the server-side SecureStream.
//  3. Dispatches to handler.NewConnection / NewPacketConnection
//     according to the requested Command.
//
// HandleConn returns when the handler finishes (or on any handshake
// error). It always closes conn before returning.
//
// ctx is forwarded to the handler. Its deadline (if any) bounds the
// handshake itself.
func (s *Service) HandleConn(ctx context.Context, conn net.Conn) error {
	tr := NewLengthFramer(conn)
	return s.handleTransport(ctx, tr, conn)
}

// HandleMessageTransport is the variant for transports that already
// guarantee message boundaries (WebSocket, gRPC, etc.). It does NOT
// add a length prefix.
//
// underlying is supplied for Metadata.Source; if nil, Source will be
// set to a (*net.TCPAddr)(nil)-style sentinel.
func (s *Service) HandleMessageTransport(ctx context.Context, tr MessageTransport, underlying net.Conn) error {
	return s.handleTransport(ctx, tr, underlying)
}

func (s *Service) handleTransport(ctx context.Context, tr MessageTransport, underlying net.Conn) error {
	s.usersMu.RLock()
	lookup := s.lookup
	replay := s.replay
	s.usersMu.RUnlock()
	if lookup == nil {
		_ = tr.Close()
		return errors.New("ewp: no users configured")
	}

	if dl, ok := ctx.Deadline(); ok {
		if dc, ok := tr.(deadlineSetter); ok {
			_ = dc.SetDeadline(dl)
		}
	}

	helloIn, err := tr.ReadMessage()
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp: read ClientHello: %w", err)
	}
	helloOut, res, err := AcceptClientHelloWithReplay(helloIn, lookup, replay)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp: accept ClientHello: %w", err)
	}
	if err := tr.SendMessage(helloOut); err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp: send ServerHello: %w", err)
	}

	stream, err := NewServerSecureStream(tr, res.Keys)
	if err != nil {
		_ = tr.Close()
		return fmt.Errorf("ewp: build server SecureStream: %w", err)
	}

	// Clear any handshake deadline before yielding to the handler.
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
		// For UDP we need to wait for the first UDP_NEW frame so we can
		// learn the client's globalID; the protocol guarantees the
		// client emits exactly one UDP_NEW immediately after handshake.
		ev, err := stream.Recv()
		if err != nil {
			_ = stream.Close()
			return fmt.Errorf("ewp: read initial UDP_NEW: %w", err)
		}
		if ev.Type != FrameUDPNew {
			_ = stream.Close()
			return fmt.Errorf("ewp: expected UDP_NEW first, got frame type %d", ev.Type)
		}
		dst := res.ClientHello.Address
		if ev.HasAddr {
			dst = ev.Address
		}
		appPC := newServerPacketConn(stream, underlying, ev.GlobalID, dst, ev.Payload)
		return s.handler.NewPacketConnection(ctx, appPC, meta)
	default:
		_ = stream.Close()
		return fmt.Errorf("ewp: unsupported command %d", res.ClientHello.Command)
	}
}
