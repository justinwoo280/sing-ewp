package ewp

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// Regression tests for the batching-transport handshake deadlock.
//
// EWP's handshake (ClientHello -> ServerHello) is a strict synchronous
// round-trip driven by LengthFramer. On a plain TCP/TLS conn a Write is
// already on the wire, so it just works. On a BUFFERING transport —
// gRPC streams, XHTTP stream-up (chunked HTTP/2 request body) — a Write
// only queues bytes; they are not pushed until an explicit flush. Before
// the fix, LengthFramer.SendMessage never flushed, so the ClientHello
// stayed in the send buffer, both peers blocked on read, and the client
// eventually observed "read ServerHello: EOF" (or a read timeout).
//
// The fix: SendMessage writes header+body in one Write and then flushes
// the underlying conn if it implements Flush() error / Flush(). These
// tests pin that behaviour:
//
//   - a buffering conn that DOES implement Flush()  -> handshake succeeds
//   - a buffering conn WITHOUT any Flush            -> still deadlocks
//     (documents the intrinsic limit: an unflushable batching transport
//     cannot carry the synchronous handshake)

// bufConn is one end of an in-memory duplex stream that BUFFERS writes:
// bytes written are delivered to the peer only on Flush() (never on
// Write). This models gRPC / XHTTP stream-up send batching.
type bufConn struct {
	mu      sync.Mutex
	pending []byte
	peer    *bufConn
	closed  bool

	deliver  chan []byte
	leftover []byte

	dmu      sync.Mutex
	deadline time.Time
}

func newBufPair() (*bufConn, *bufConn) {
	a := &bufConn{deliver: make(chan []byte, 64)}
	b := &bufConn{deliver: make(chan []byte, 64)}
	a.peer = b
	b.peer = a
	return a, b
}

func (c *bufConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	c.pending = append(c.pending, p...)
	return len(p), nil
}

// Flush delivers buffered bytes to the peer. This is the method
// SendMessage must call for the handshake to progress.
func (c *bufConn) Flush() error {
	c.mu.Lock()
	data := c.pending
	c.pending = nil
	peer := c.peer
	closed := c.closed
	c.mu.Unlock()
	if closed || len(data) == 0 {
		return nil
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	select {
	case peer.deliver <- cp:
	default:
	}
	return nil
}

func (c *bufConn) Read(p []byte) (int, error) {
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}
	c.dmu.Lock()
	dl := c.deadline
	c.dmu.Unlock()

	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case chunk, ok := <-c.deliver:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, chunk)
		if n < len(chunk) {
			c.leftover = chunk[n:]
		}
		return n, nil
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *bufConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	peer := c.peer
	c.mu.Unlock()
	close(c.deliver)
	if peer != nil {
		peer.mu.Lock()
		if !peer.closed {
			peer.closed = true
			close(peer.deliver)
		}
		peer.mu.Unlock()
	}
	return nil
}

func (c *bufConn) LocalAddr() net.Addr  { return bufAddr{} }
func (c *bufConn) RemoteAddr() net.Addr { return bufAddr{} }
func (c *bufConn) SetDeadline(t time.Time) error {
	c.dmu.Lock()
	c.deadline = t
	c.dmu.Unlock()
	return nil
}
func (c *bufConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *bufConn) SetWriteDeadline(t time.Time) error { return nil }

type bufAddr struct{}

func (bufAddr) Network() string { return "buf" }
func (bufAddr) String() string  { return "buf" }

// opaqueConn wraps *bufConn but exposes ONLY the net.Conn surface (no
// Flush), modelling an unflushable batching transport — the intrinsic
// worst case where the handshake cannot be rescued.
type opaqueConn struct{ c *bufConn }

func (o opaqueConn) Read(p []byte) (int, error)         { return o.c.Read(p) }
func (o opaqueConn) Write(p []byte) (int, error)        { return o.c.Write(p) }
func (o opaqueConn) Close() error                       { return o.c.Close() }
func (o opaqueConn) LocalAddr() net.Addr                { return bufAddr{} }
func (o opaqueConn) RemoteAddr() net.Addr               { return bufAddr{} }
func (o opaqueConn) SetDeadline(t time.Time) error      { return o.c.SetDeadline(t) }
func (o opaqueConn) SetReadDeadline(t time.Time) error  { return o.c.SetReadDeadline(t) }
func (o opaqueConn) SetWriteDeadline(t time.Time) error { return nil }

func runV21Handshake(t *testing.T, clientConn net.Conn, serverConn net.Conn) error {
	t.Helper()
	priv, pub, err := GenerateServerStaticKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "11111111-2222-3333-4444-555555555555"

	svc, err := NewServiceV21(&echoTCPHandler{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddUser(uuid); err != nil {
		t.Fatal(err)
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = svc.HandleConn(ctx, serverConn)
	}()

	client, err := NewClientV21(uuid, pub)
	if err != nil {
		t.Fatal(err)
	}

	_ = clientConn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := client.DialConn(ctx, clientConn, Address{Domain: "example.com", Port: 443})
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// TestFlush_BatchingTransportWithFlush_Succeeds: the fix must flush the
// buffered ClientHello/ServerHello so the handshake completes even
// though Write alone never delivers.
func TestFlush_BatchingTransportWithFlush_Succeeds(t *testing.T) {
	c, s := newBufPair()
	if err := runV21Handshake(t, c, s); err != nil {
		t.Fatalf("handshake over flushable batching transport should succeed, got: %v", err)
	}
}

// TestFlush_UnflushableTransport_StillDeadlocks documents the intrinsic
// limit: a batching transport with no Flush cannot carry the synchronous
// handshake. (Not a regression — a property of such transports.)
func TestFlush_UnflushableTransport_StillDeadlocks(t *testing.T) {
	c, s := newBufPair()
	err := runV21Handshake(t, opaqueConn{c}, s)
	if err == nil {
		t.Fatalf("expected handshake to fail on an unflushable batching transport")
	}
	t.Logf("as expected, unflushable batching transport fails: %v", err)
}
