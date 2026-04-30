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
// Concurrency: WriteTo and Close are goroutine-safe. ReadFrom must be
// called from a single goroutine (matching SecureStream's contract).
type packetConn struct {
	stream     *SecureStream
	underlying net.Conn
	globalID   [8]byte
	defaultDst Address

	// isServer is true on the server side: WriteTo always emits
	// UDP_DATA (never UDP_NEW) and the constructor pre-marks opened.
	isServer bool

	// pendingFirst is a payload pulled out of UDP_NEW by the server-side
	// constructor; the first ReadFrom returns it before reading from
	// the wire.
	pendingFirst    []byte
	pendingFirstSrc Address

	openedMu sync.Mutex
	opened   bool

	closeOnce sync.Once
	closeErr  error
}

// newClientPacketConn builds a client-side packet conn. globalID is
// freshly generated and the first WriteTo will emit UDP_NEW.
func newClientPacketConn(stream *SecureStream, underlying net.Conn, dst Address) *packetConn {
	return &packetConn{
		stream:     stream,
		underlying: underlying,
		globalID:   NewGlobalID(),
		defaultDst: dst,
	}
}

// newServerPacketConn builds a server-side packet conn from an already
// received UDP_NEW frame. globalID, default dst and any initial payload
// come from that frame.
func newServerPacketConn(stream *SecureStream, underlying net.Conn,
	globalID [8]byte, defaultDst Address, initial []byte) *packetConn {
	return &packetConn{
		stream:          stream,
		underlying:      underlying,
		globalID:        globalID,
		defaultDst:      defaultDst,
		isServer:        true,
		opened:          true,
		pendingFirst:    initial,
		pendingFirstSrc: defaultDst,
	}
}

// ensureOpen sends UDP_NEW exactly once. payload may be nil to open
// the sub-session without an initial datagram.
func (p *packetConn) ensureOpen(payload []byte) error {
	p.openedMu.Lock()
	defer p.openedMu.Unlock()
	if p.opened {
		return nil
	}
	if err := p.stream.SendUDPNew(p.globalID, p.defaultDst, payload); err != nil {
		return err
	}
	p.opened = true
	return nil
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
	if !p.isServer && !p.opened {
		if err := p.ensureOpen(b); err == nil {
			// Initial datagram piggy-backed on UDP_NEW.
			return len(b), nil
		} else {
			return 0, err
		}
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
	if p.pendingFirst != nil {
		first := p.pendingFirst
		src := p.pendingFirstSrc
		p.pendingFirst = nil
		n := copy(b, first)
		return n, ewpToNetAddr(src), nil
	}
	for {
		ev, err := p.stream.Recv()
		if err != nil {
			return 0, nil, err
		}
		switch ev.Type {
		case FrameUDPData, FrameUDPNew:
			if ev.GlobalID != p.globalID {
				// Foreign sub-session in the same SecureStream — should
				// not happen for a single PacketConn but skip safely.
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
		case FrameUDPEnd:
			if ev.GlobalID == p.globalID {
				return 0, nil, io.EOF
			}
			continue
		case FramePing, FramePong, FramePaddingOnly,
			FrameUDPProbeReq, FrameUDPProbeResp:
			continue
		default:
			return 0, nil, fmt.Errorf("ewp: unexpected frame type %d on packet conn", ev.Type)
		}
	}
}

func (p *packetConn) Close() error {
	p.closeOnce.Do(func() {
		// Best-effort UDP_END: ignore errors (peer may have closed)
		// and bound the attempt with a short deadline so a dead peer
		// can't hang Close indefinitely.
		if p.opened && p.underlying != nil {
			_ = p.underlying.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			_ = p.stream.SendUDPEnd(p.globalID)
			_ = p.underlying.SetWriteDeadline(time.Time{})
		}
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
	if p.underlying != nil {
		return p.underlying.LocalAddr()
	}
	return nil
}

func (p *packetConn) SetDeadline(t time.Time) error {
	if p.underlying != nil {
		return p.underlying.SetDeadline(t)
	}
	return nil
}

func (p *packetConn) SetReadDeadline(t time.Time) error {
	if p.underlying != nil {
		return p.underlying.SetReadDeadline(t)
	}
	return nil
}

func (p *packetConn) SetWriteDeadline(t time.Time) error {
	if p.underlying != nil {
		return p.underlying.SetWriteDeadline(t)
	}
	return nil
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
			return Address{}, fmt.Errorf("ewp: invalid UDP IP: %v", a.IP)
		}
		return Address{Addr: netip.AddrPortFrom(ap.Unmap(), uint16(a.Port))}, nil
	case *net.TCPAddr:
		ap, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return Address{}, fmt.Errorf("ewp: invalid TCP IP: %v", a.IP)
		}
		return Address{Addr: netip.AddrPortFrom(ap.Unmap(), uint16(a.Port))}, nil
	case FqdnAddr:
		if len(a.Fqdn) > MaxDomainLen {
			return Address{}, ErrDomainLen
		}
		return Address{Domain: a.Fqdn, Port: a.Port}, nil
	default:
		return Address{}, fmt.Errorf("ewp: unsupported net.Addr type %T", addr)
	}
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
var ErrPacketConnClosed = errors.New("ewp: packet conn closed")
