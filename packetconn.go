package ewp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// packetConn is the net.PacketConn adapter for an EWP UDP sub-session.
//
// Wire mapping:
//   - First WriteTo opens a UDP_NEW sub-session lazily (or eagerly via
//     the constructor's initial dst).
//   - Subsequent WriteTo emit UDP_DATA frames carrying the per-packet
//     target Address.
//   - Inbound UDP_DATA frames decoded by SecureStream.Recv become
//     ReadFrom returns.
//
// Concurrency: WriteTo and Close are goroutine-safe. A single ReadFrom caller
// is recommended for predictable datagram ordering.
type packetConn struct {
	stream     *SecureStream
	underlying net.Conn
	globalID   [8]byte
	defaultDst Address
	runtime    v3Runtime

	// isServer is true on the server side: WriteTo always emits
	// UDP_DATA (never UDP_NEW) and the constructor pre-marks opened.
	isServer bool

	// pendingFirst is a payload pulled out of UDP_NEW by the server-side
	// constructor; the first ReadFrom returns it before reading from
	// the wire.
	pendingFirst    []byte
	pendingFirstSrc Address
	pendingFirstSet bool
	closed          bool
	remoteEnded     bool

	openedMu sync.Mutex
	opened   bool

	closeOnce sync.Once
	closeErr  error
}

// newClientPacketConn builds a client-side packet conn. globalID is
// freshly generated and the first WriteTo will emit UDP_NEW.
func newClientPacketConn(stream *SecureStream, underlying net.Conn, dst Address) *packetConn {
	return newClientPacketConnWithRuntime(stream, underlying, dst, productionV3Runtime())
}

func newClientPacketConnWithRuntime(stream *SecureStream, underlying net.Conn, dst Address, runtime v3Runtime) *packetConn {
	return &packetConn{
		stream:     stream,
		underlying: underlying,
		globalID:   newGlobalIDWithReader(runtime.reader()),
		defaultDst: dst,
		runtime:    runtime,
	}
}

// newServerPacketConn builds a server-side packet conn from an already
// received UDP_NEW frame. globalID, default dst and any initial payload
// come from that frame.
func newServerPacketConn(stream *SecureStream, underlying net.Conn,
	globalID [8]byte, defaultDst Address, initial []byte) *packetConn {
	return newServerPacketConnWithRuntime(stream, underlying, globalID, defaultDst, initial, productionV3Runtime())
}

func newServerPacketConnWithRuntime(stream *SecureStream, underlying net.Conn,
	globalID [8]byte, defaultDst Address, initial []byte, runtime v3Runtime) *packetConn {
	return &packetConn{
		stream:          stream,
		underlying:      underlying,
		globalID:        globalID,
		defaultDst:      defaultDst,
		isServer:        true,
		opened:          true,
		pendingFirst:    initial,
		pendingFirstSrc: defaultDst,
		pendingFirstSet: true,
		runtime:         runtime,
	}
}

// WriteTo sends b to addr through the EWP tunnel. addr may be a
// *net.UDPAddr or an *net.IPAddr; FQDN destinations require callers
// to use WriteToAddress (see below).
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	target, err := addrToEWP(addr)
	if err != nil {
		return 0, err
	}
	return p.WriteToAddress(b, target)
}

// WriteToAddress is the EWP-native variant of WriteTo accepting an
// EWP Address (which can carry FQDN destinations).
func (p *packetConn) WriteToAddress(b []byte, target Address) (int, error) {
	if p == nil {
		return 0, ErrPacketConnClosed
	}
	p.openedMu.Lock()
	defer p.openedMu.Unlock()
	if p.closed || p.remoteEnded || p.stream == nil {
		return 0, ErrPacketConnClosed
	}
	if !p.isServer && !p.opened {
		initialTarget := target
		if !hasV3Address(initialTarget) {
			initialTarget = p.defaultDst
		}
		if !hasV3Address(initialTarget) {
			return 0, errors.New("ewp/v3: UDP_NEW requires a target address")
		}
		if err := p.stream.SendUDPNew(p.globalID, initialTarget, b); err != nil {
			return 0, err
		}
		p.opened = true
		// Initial datagram piggy-backed on UDP_NEW.
		return len(b), nil
	}
	if err := p.stream.SendUDPData(p.globalID, target, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom reads one decrypted UDP datagram. The returned net.Addr is
// a *net.UDPAddr if the source is a literal IP, or an FqdnAddr for
// domain sources.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if p == nil {
		return 0, nil, ErrPacketConnClosed
	}
	p.openedMu.Lock()
	if p.closed {
		p.openedMu.Unlock()
		return 0, nil, ErrPacketConnClosed
	}
	if p.remoteEnded {
		p.openedMu.Unlock()
		return 0, nil, io.EOF
	}
	if p.stream == nil {
		p.openedMu.Unlock()
		return 0, nil, ErrPacketConnClosed
	}
	if p.pendingFirstSet {
		first := p.pendingFirst
		src := p.pendingFirstSrc
		p.pendingFirst = nil
		p.pendingFirstSet = false
		p.openedMu.Unlock()
		n := copy(b, first)
		return n, ewpToNetAddr(src), nil
	}
	p.openedMu.Unlock()
	for {
		p.openedMu.Lock()
		closed := p.closed
		p.openedMu.Unlock()
		if closed {
			return 0, nil, ErrPacketConnClosed
		}
		ev, err := p.stream.Recv()
		if err != nil {
			p.openedMu.Lock()
			closed = p.closed
			p.openedMu.Unlock()
			if closed {
				return 0, nil, ErrPacketConnClosed
			}
			return 0, nil, err
		}
		switch ev.Type {
		case FrameUDPData:
			if ev.GlobalID != p.globalID {
				// A SecureStream may carry multiple UDP sub-sessions. The
				// single-session adapter skips frames owned by another one.
				continue
			}
			n := copy(b, ev.Payload)
			if n < len(ev.Payload) {
				// truncated; net.PacketConn semantics allow this
				// (caller is expected to size b for max datagram).
			}
			var src net.Addr
			if ev.HasAddr {
				src = ewpToNetAddr(ev.Address)
			} else {
				src = ewpToNetAddr(p.defaultDst)
			}
			return n, src, nil
		case FrameUDPNew:
			err := fmt.Errorf("ewp/v3: unexpected UDP_NEW on existing packet connection")
			_ = p.stream.Close()
			return 0, nil, err
		case FrameUDPEnd:
			if ev.GlobalID == p.globalID {
				p.openedMu.Lock()
				p.remoteEnded = true
				p.openedMu.Unlock()
				return 0, nil, io.EOF
			}
			continue
		case FramePing, FramePong, FramePaddingOnly,
			FrameUDPProbeReq, FrameUDPProbeResp:
			continue
		default:
			err := fmt.Errorf("ewp/v3: unexpected record type %d on packet connection", ev.Type)
			_ = p.stream.Close()
			return 0, nil, err
		}
	}
}

func (p *packetConn) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.openedMu.Lock()
		defer p.openedMu.Unlock()
		p.closed = true
		p.sendEndBestEffort()
		p.closeErr = p.stream.Close()
		if p.underlying != nil {
			if err := p.underlying.Close(); err != nil && p.closeErr == nil {
				p.closeErr = err
			}
		}
	})
	return p.closeErr
}

func (p *packetConn) LocalAddr() net.Addr {
	if p == nil {
		return nil
	}
	if p.underlying != nil {
		return p.underlying.LocalAddr()
	}
	if p.stream != nil {
		if info, ok := p.stream.tr.(MessageTransportInfo); ok {
			return info.LocalAddr()
		}
	}
	return nil
}

func (p *packetConn) SetDeadline(t time.Time) error {
	if p == nil || p.isClosed() {
		return ErrPacketConnClosed
	}
	if p.underlying != nil {
		return p.underlying.SetDeadline(t)
	}
	if p.stream != nil {
		if setter, ok := p.stream.tr.(MessageTransportDeadline); ok {
			return setter.SetDeadline(t)
		}
	}
	return ErrV3DeadlineUnsupported
}

func (p *packetConn) SetReadDeadline(t time.Time) error {
	if p == nil || p.isClosed() {
		return ErrPacketConnClosed
	}
	if p.underlying != nil {
		return p.underlying.SetReadDeadline(t)
	}
	if p.stream != nil {
		if setter, ok := p.stream.tr.(MessageTransportReadDeadline); ok {
			return setter.SetReadDeadline(t)
		}
		if setter, ok := p.stream.tr.(MessageTransportDeadline); ok {
			return setter.SetDeadline(t)
		}
	}
	return ErrV3DeadlineUnsupported
}

func (p *packetConn) SetWriteDeadline(t time.Time) error {
	if p == nil || p.isClosed() {
		return ErrPacketConnClosed
	}
	if p.underlying != nil {
		return p.underlying.SetWriteDeadline(t)
	}
	if p.stream != nil {
		if setter, ok := p.stream.tr.(MessageTransportWriteDeadline); ok {
			return setter.SetWriteDeadline(t)
		}
		if setter, ok := p.stream.tr.(MessageTransportDeadline); ok {
			return setter.SetDeadline(t)
		}
	}
	return ErrV3DeadlineUnsupported
}

func hasV3Address(a Address) bool {
	return a.IsDomain() || a.Addr.IsValid()
}

func (p *packetConn) sendEndBestEffort() {
	if p == nil || !p.opened || p.stream == nil || p.stream.tr == nil {
		return
	}
	deadline := p.runtime.nowTime().Add(100 * time.Millisecond)
	if p.underlying != nil {
		_ = p.underlying.SetWriteDeadline(deadline)
		_ = p.stream.SendUDPEnd(p.globalID)
		_ = p.underlying.SetWriteDeadline(time.Time{})
		return
	}
	if setter, ok := p.stream.tr.(MessageTransportWriteDeadline); ok {
		_ = setter.SetWriteDeadline(deadline)
		_ = p.stream.SendUDPEnd(p.globalID)
		_ = setter.SetWriteDeadline(time.Time{})
		return
	}
	if setter, ok := p.stream.tr.(MessageTransportDeadline); ok {
		_ = setter.SetDeadline(deadline)
		_ = p.stream.SendUDPEnd(p.globalID)
		_ = setter.SetDeadline(time.Time{})
		return
	}

	// A carrier without deadline methods can still be bounded by its required
	// Close contract. Keep UDP_END best-effort without allowing a blocked send
	// to make PacketConn.Close wait indefinitely.
	done := make(chan struct{})
	go func() {
		_ = p.stream.SendUDPEnd(p.globalID)
		close(done)
	}()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		_ = p.stream.abortTransport()
		<-done
	}
}

func (p *packetConn) isClosed() bool {
	if p == nil {
		return true
	}
	p.openedMu.Lock()
	closed := p.closed
	p.openedMu.Unlock()
	return closed
}

// ----------------------------------------------------------------------
// Address conversion helpers (net.Addr ↔ ewp.Address).
// ----------------------------------------------------------------------

// FqdnAddr is a net.Addr representation for FQDN destinations that the
// stdlib net package cannot natively express.
type FqdnAddr struct {
	Fqdn string
	Port uint16
}

func (a FqdnAddr) Network() string { return "udp" }
func (a FqdnAddr) String() string  { return fmt.Sprintf("%s:%d", a.Fqdn, a.Port) }

func addrToEWP(addr net.Addr) (Address, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		ap, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return Address{}, fmt.Errorf("ewp/v3: invalid UDP IP: %v", a.IP)
		}
		return Address{Addr: netip.AddrPortFrom(ap.Unmap(), uint16(a.Port))}, nil
	case *net.TCPAddr:
		ap, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return Address{}, fmt.Errorf("ewp/v3: invalid TCP IP: %v", a.IP)
		}
		return Address{Addr: netip.AddrPortFrom(ap.Unmap(), uint16(a.Port))}, nil
	case FqdnAddr:
		return fqdnToEWP(a)
	case *FqdnAddr:
		if a == nil {
			return Address{}, errors.New("ewp/v3: nil FQDN address")
		}
		return fqdnToEWP(*a)
	default:
		return Address{}, fmt.Errorf("ewp/v3: unsupported net.Addr type %T", addr)
	}
}

func fqdnToEWP(a FqdnAddr) (Address, error) {
	if len(a.Fqdn) == 0 || len(a.Fqdn) > MaxDomainLen {
		return Address{}, ErrDomainLen
	}
	if !validDomain(a.Fqdn) {
		return Address{}, ErrDomainSyntax
	}
	return Address{Domain: a.Fqdn, Port: a.Port}, nil
}

func ewpToNetAddr(a Address) net.Addr {
	if a.Domain != "" {
		return FqdnAddr{Fqdn: a.Domain, Port: a.Port}
	}
	if a.Addr.IsValid() {
		return net.UDPAddrFromAddrPort(a.Addr)
	}
	return nil
}

// ErrPacketConnClosed is returned by Read/Write after Close.
var ErrPacketConnClosed = errors.New("ewp/v3: packet connection closed")
