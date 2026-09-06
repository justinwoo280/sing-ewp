package ewp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Client is the high-level legacy EWP v2 client.
//
// Deprecated: Use ClientV21. The legacy UUID-only handshake does not
// authenticate the server and must not be used for new deployments.
//
// One Client = one configured user (UUID + protocol parameters). It is
// safe to share across goroutines: each Dial call performs an
// independent handshake on its own underlying connection.
//
// The Client does NOT manage the underlying transport (TLS, WebSocket,
// gRPC, etc.). The caller is responsible for establishing a net.Conn
// to the EWP server (typically a TLS connection produced by the
// chosen transport layer) and passing it to DialConn / DialPacketConn.
type Client struct {
	uuid [UUIDLen]byte
}

// NewClient parses a UUID string ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
// or 32 hex digits) and returns a ready Client.
//
// Deprecated: Use NewClientV21 with the pinned server static public key.
func NewClient(uuidStr string) (*Client, error) {
	u, err := ParseUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	return &Client{uuid: u}, nil
}

// UUID returns the configured user UUID (as a 16-byte array).
func (c *Client) UUID() [UUIDLen]byte { return c.uuid }

// DialConn performs the EWP v2 handshake over conn (a byte-stream
// transport, typically a TLS connection) requesting a TCP tunnel to
// dst on the server side. On success it returns a net.Conn whose
// Read/Write transparently encrypt/decrypt application data.
//
// The returned net.Conn owns conn: closing the returned conn closes
// the underlying transport. Closing the returned conn is idempotent.
//
// Concurrency: the returned net.Conn allows concurrent Write but
// requires single-goroutine Read (matching SecureStream's contract).
func (c *Client) DialConn(ctx context.Context, conn net.Conn, dst Address) (net.Conn, error) {
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

// DialPacketConn performs the EWP v2 handshake over conn requesting a
// UDP tunnel anchored at dst. The returned net.PacketConn lets the
// caller send/receive UDP datagrams to arbitrary destinations through
// the tunnel; dst is the initial advertised target and may be
// overridden per-packet via WriteTo.
//
// The returned PacketConn owns conn.
func (c *Client) DialPacketConn(ctx context.Context, conn net.Conn, dst Address) (net.PacketConn, error) {
	tr := NewLengthFramer(conn)
	stream, err := c.handshake(ctx, tr, CommandUDP, dst)
	if err != nil {
		return nil, err
	}
	return newClientPacketConn(stream, conn, dst), nil
}

// handshake runs WriteClientHello + ReadServerHello and returns the
// post-handshake SecureStream. It applies DefaultHandshakeTimeout unless ctx
// has an earlier deadline, and cancellation closes the transport.
func (c *Client) handshake(ctx context.Context, tr MessageTransport, cmd Command, dst Address) (*SecureStream, error) {
	hctx, finish := beginHandshake(ctx, tr)
	defer finish()

	state, err := WriteClientHello(func(msg []byte) error {
		return sendMessageContext(hctx, tr, msg)
	}, c.uuid, cmd, dst)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp: write ClientHello: %w", err)
	}
	shBytes, err := readMessageContext(hctx, tr)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp: read ServerHello: %w", err)
	}
	res, err := state.ReadServerHello(shBytes)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp: process ServerHello: %w", err)
	}
	stream, err := NewClientSecureStream(tr, res.Keys)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("ewp: build SecureStream: %w", err)
	}
	return stream, nil
}

// deadlineSetter is the interface satisfied by net.Conn-backed
// MessageTransports (and net.Conn itself).
type deadlineSetter interface {
	SetDeadline(t time.Time) error
}

// ----------------------------------------------------------------------
// streamConn: net.Conn adapter on top of *SecureStream (TCP mode).
// ----------------------------------------------------------------------

type streamConn struct {
	*SecureStream
	underlying net.Conn

	// shaper, when non-nil, reshapes the send timeline (coalescing +
	// idle cover traffic) so the on-wire burst/timing pattern no
	// longer mirrors the inner protocol. Writes go through it; it
	// still funnels every frame through SecureStream so all bytes stay
	// padded + AEAD-sealed. Nil means writes go straight to
	// SecureStream.SendTCPData for callers that opt out.
	shaper *StreamShaper

	readMu  sync.Mutex
	readBuf []byte // unread portion of last decoded TCP DATA payload

	closeOnce sync.Once
	closeErr  error
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		ev, err := c.SecureStream.Recv()
		if err != nil {
			return 0, err
		}
		switch ev.Type {
		case FrameTCPData:
			if len(ev.Payload) == 0 {
				continue // empty frame is legal but uninteresting
			}
			c.readBuf = ev.Payload
		case FramePaddingOnly, FramePing, FramePong:
			// Cover and keepalive frames have no application payload;
			// just drop them and read another frame.
			continue
		default:
			// In TCP mode any other frame type (UDP, probe...) is a
			// protocol violation from the peer.
			err := fmt.Errorf("ewp: unexpected frame type %d in TCP stream", ev.Type)
			_ = c.SecureStream.Close()
			return 0, err
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.shaper != nil {
		// The shaper copies p and owns chunking/coalescing; it always
		// accepts the whole buffer.
		if err := c.shaper.WriteTCP(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	// Chunk to MaxFrameSize-margin so that AEAD overhead + meta does
	// not push a single frame past the wire limit.
	const maxPayload = MaxFrameSize - 256
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		if err := c.SecureStream.SendTCPData(chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() {
		if c.shaper != nil {
			// Stop scheduling writes and close the stream before waiting for a
			// cover send. A non-reading peer must not make Close block forever.
			if err := c.shaper.Close(); err != nil && c.closeErr == nil {
				c.closeErr = err
			}
		}
		if err := c.SecureStream.Close(); err != nil && c.closeErr == nil {
			c.closeErr = err
		}
		if c.underlying != nil {
			if err := c.underlying.Close(); err != nil && c.closeErr == nil {
				c.closeErr = err
			}
		}
	})
	return c.closeErr
}

func (c *streamConn) LocalAddr() net.Addr {
	if c.underlying != nil {
		return c.underlying.LocalAddr()
	}
	return nil
}

func (c *streamConn) RemoteAddr() net.Addr {
	if c.underlying != nil {
		return c.underlying.RemoteAddr()
	}
	return nil
}

func (c *streamConn) SetDeadline(t time.Time) error {
	if c.underlying != nil {
		return c.underlying.SetDeadline(t)
	}
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	if c.underlying != nil {
		return c.underlying.SetReadDeadline(t)
	}
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	if c.underlying != nil {
		return c.underlying.SetWriteDeadline(t)
	}
	return nil
}

// ----------------------------------------------------------------------
// LengthFramer: net.Conn → MessageTransport (4-byte big-endian length
// prefix). Use this when the underlying transport is a byte stream
// without intrinsic message boundaries (raw TCP, TLS, h2 stream).
// ----------------------------------------------------------------------

// LengthFramer wraps a net.Conn so it satisfies MessageTransport via a
// simple uint32 big-endian length prefix per message.
type LengthFramer struct {
	c       net.Conn
	writeMu sync.Mutex
	readMu  sync.Mutex
	readBuf []byte // reusable scratch
}

// NewLengthFramer builds a LengthFramer around c. The framer takes
// shared ownership of c; closing the framer closes c.
func NewLengthFramer(c net.Conn) *LengthFramer {
	return &LengthFramer{c: c}
}

// SendMessage writes a length prefix followed by msg. Concurrent calls
// are serialised internally.
//
// The length prefix is 3 bytes big-endian (max payload 16 MiB), down
// from v2.0's 4-byte prefix. The motivation is purely traffic-analysis:
// v2.0's 4-byte prefix had its high two bytes ALWAYS zero (because
// MaxFrameSize ≤ 65536), giving a free 2-byte DPI fingerprint at the
// start of every EWP record. The 3-byte prefix uses every byte for
// real entropy.
func (f *LengthFramer) SendMessage(msg []byte) error {
	if len(msg) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()

	// Header + body in ONE contiguous write. On message-framed
	// transports (gRPC, where every Write becomes one stream Hunk) a
	// split header/body would otherwise emit two independent records.
	frame := make([]byte, 3+len(msg))
	frame[0] = byte(len(msg) >> 16)
	frame[1] = byte(len(msg) >> 8)
	frame[2] = byte(len(msg))
	copy(frame[3:], msg)
	if _, err := f.c.Write(frame); err != nil {
		return err
	}
	return f.flush()
}

// flusher is implemented by transports that BUFFER writes and only push
// them onto the wire on an explicit flush. Plain TCP/TLS conns do NOT
// implement it (a Write is already on the wire), so flush() is a no-op
// there. Batching transports — gRPC streams, XHTTP stream-up (chunked
// HTTP/2 request body), h2/h3 response writers — DO buffer, and without
// a flush the EWP handshake (a strict synchronous ClientHello/
// ServerHello round-trip) DEADLOCKS: the ClientHello never leaves the
// local send buffer, both peers block on read, and the stream
// eventually tears down, surfacing on the client as
// "read ServerHello: EOF".
type flusher interface{ Flush() error }

// httpFlusher matches net/http's http.Flusher (Flush() with no return),
// as exposed by h2/h3 response writers and by transport conns that wrap
// them.
type httpFlusher interface{ Flush() }

// flush pushes any transport-buffered bytes onto the wire. It is a
// no-op on transports that do not buffer (plain TCP/TLS).
func (f *LengthFramer) flush() error {
	switch v := f.c.(type) {
	case flusher:
		return v.Flush()
	case httpFlusher:
		v.Flush()
	}
	return nil
}

// ReadMessage reads one length-prefixed message. Concurrent calls are
// serialised internally; callers SHOULD invoke ReadMessage from a
// single goroutine to match SecureStream's contract.
func (f *LengthFramer) ReadMessage() ([]byte, error) {
	f.readMu.Lock()
	defer f.readMu.Unlock()
	var hdr [3]byte
	if _, err := io.ReadFull(f.c, hdr[:]); err != nil {
		return nil, err
	}
	n := uint32(hdr[0])<<16 | uint32(hdr[1])<<8 | uint32(hdr[2])
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	if cap(f.readBuf) < int(n) {
		f.readBuf = make([]byte, n)
	} else {
		f.readBuf = f.readBuf[:n]
	}
	if _, err := io.ReadFull(f.c, f.readBuf); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, f.readBuf)
	return out, nil
}

// Close closes the underlying connection.
func (f *LengthFramer) Close() error {
	return f.c.Close()
}

// SetDeadline forwards to the underlying connection so handshake
// deadlines work.
func (f *LengthFramer) SetDeadline(t time.Time) error {
	return f.c.SetDeadline(t)
}

// ----------------------------------------------------------------------
// UUID parsing helper.
// ----------------------------------------------------------------------

// ParseUUID accepts either the canonical hyphenated form
// ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx") or 32 contiguous hex digits.
func ParseUUID(s string) ([UUIDLen]byte, error) {
	var out [UUIDLen]byte
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return out, errors.New("ewp: UUID must be 32 hex digits (with or without hyphens)")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, fmt.Errorf("ewp: invalid UUID hex: %w", err)
	}
	copy(out[:], b)
	return out, nil
}
