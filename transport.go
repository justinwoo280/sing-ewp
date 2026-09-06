package ewp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// LengthFramer turns a byte stream into the message transport used by EWP/v3.
// The four-byte length is framing only; the v3 records carry their own
// authenticated opaque length inside the framed message.
type LengthFramer struct {
	c       net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewLengthFramer(c net.Conn) *LengthFramer {
	return &LengthFramer{c: c}
}

func (f *LengthFramer) SendMessage(message []byte) error {
	if f == nil || f.c == nil {
		return io.ErrClosedPipe
	}
	if len(message) > MaxV3MessageSize {
		return ErrV3MessageTooLarge
	}
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(message)))
	if err := writeFull(f.c, header[:]); err != nil {
		return err
	}
	return writeFull(f.c, message)
}

func (f *LengthFramer) ReadMessage() ([]byte, error) {
	if f == nil || f.c == nil {
		return nil, io.ErrClosedPipe
	}
	f.readMu.Lock()
	defer f.readMu.Unlock()
	var header [4]byte
	if _, err := io.ReadFull(f.c, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > MaxV3MessageSize {
		return nil, ErrV3MessageTooLarge
	}
	message := make([]byte, int(length))
	if _, err := io.ReadFull(f.c, message); err != nil {
		return nil, err
	}
	return message, nil
}

func (f *LengthFramer) Close() error {
	if f == nil || f.c == nil {
		return nil
	}
	return f.c.Close()
}

func (f *LengthFramer) SetDeadline(deadline time.Time) error {
	if f == nil || f.c == nil {
		return io.ErrClosedPipe
	}
	return f.c.SetDeadline(deadline)
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

type streamConn struct {
	*SecureStream
	underlying net.Conn

	readMu    sync.Mutex
	readBuf   []byte
	closeOnce sync.Once
	closeErr  error
	onClose   func()
}

func (c *streamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readBuf) == 0 {
		event, err := c.SecureStream.Recv()
		if err != nil {
			return 0, err
		}
		switch event.Type {
		case FrameTCPData:
			if len(event.Payload) != 0 {
				c.readBuf = event.Payload
			}
		case FramePaddingOnly, FramePing, FramePong:
		default:
			_ = c.SecureStream.Close()
			return 0, fmt.Errorf("ewp/v3: unexpected record type %d on TCP stream", event.Type)
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
		c.closeErr = c.SecureStream.Close()
		if c.underlying != nil {
			if err := c.underlying.Close(); err != nil && c.closeErr == nil {
				c.closeErr = err
			}
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
}

func (c *streamConn) LocalAddr() net.Addr {
	if c.underlying != nil {
		return c.underlying.LocalAddr()
	}
	if c.SecureStream != nil {
		if info, ok := c.SecureStream.tr.(MessageTransportInfo); ok {
			return info.LocalAddr()
		}
	}
	return nil
}

func (c *streamConn) RemoteAddr() net.Addr {
	if c.underlying != nil {
		return c.underlying.RemoteAddr()
	}
	if c.SecureStream != nil {
		if info, ok := c.SecureStream.tr.(MessageTransportInfo); ok {
			return info.RemoteAddr()
		}
	}
	return nil
}

func (c *streamConn) SetDeadline(deadline time.Time) error {
	if c.underlying != nil {
		return c.underlying.SetDeadline(deadline)
	}
	if c.SecureStream != nil {
		if setter, ok := c.SecureStream.tr.(MessageTransportDeadline); ok {
			return setter.SetDeadline(deadline)
		}
	}
	return ErrV3DeadlineUnsupported
}

func (c *streamConn) SetReadDeadline(deadline time.Time) error {
	if c.underlying != nil {
		return c.underlying.SetReadDeadline(deadline)
	}
	if c.SecureStream != nil {
		if setter, ok := c.SecureStream.tr.(MessageTransportReadDeadline); ok {
			return setter.SetReadDeadline(deadline)
		}
		if setter, ok := c.SecureStream.tr.(MessageTransportDeadline); ok {
			return setter.SetDeadline(deadline)
		}
	}
	return ErrV3DeadlineUnsupported
}

func (c *streamConn) SetWriteDeadline(deadline time.Time) error {
	if c.underlying != nil {
		return c.underlying.SetWriteDeadline(deadline)
	}
	if c.SecureStream != nil {
		if setter, ok := c.SecureStream.tr.(MessageTransportWriteDeadline); ok {
			return setter.SetWriteDeadline(deadline)
		}
		if setter, ok := c.SecureStream.tr.(MessageTransportDeadline); ok {
			return setter.SetDeadline(deadline)
		}
	}
	return ErrV3DeadlineUnsupported
}

func beginV3Handshake(ctx context.Context, tr MessageTransport) (context.Context, func()) {
	return beginHandshake(ctx, tr)
}

func contextErrV3(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func sendV3MessageContext(ctx context.Context, tr MessageTransport, message []byte) error {
	if len(message) > MaxV3MessageSize {
		return ErrV3MessageTooLarge
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextErrV3(ctx); err != nil {
		return err
	}
	if contextTransport, ok := tr.(ContextMessageTransport); ok {
		return contextTransport.SendMessageContext(ctx, message)
	}
	result := make(chan error, 1)
	go func() { result <- tr.SendMessage(message) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		_ = tr.Close()
		return ctx.Err()
	}
}

func readV3MessageContext(ctx context.Context, tr MessageTransport) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextErrV3(ctx); err != nil {
		return nil, err
	}
	if contextTransport, ok := tr.(ContextMessageTransport); ok {
		message, err := contextTransport.ReadMessageContext(ctx)
		if err != nil {
			return nil, err
		}
		if len(message) > MaxV3MessageSize {
			return nil, ErrV3MessageTooLarge
		}
		return message, nil
	}
	result := make(chan struct {
		message []byte
		err     error
	}, 1)
	go func() {
		message, err := tr.ReadMessage()
		result <- struct {
			message []byte
			err     error
		}{message: message, err: err}
	}()
	select {
	case value := <-result:
		if len(value.message) > MaxV3MessageSize {
			return nil, ErrV3MessageTooLarge
		}
		return value.message, value.err
	case <-ctx.Done():
		_ = tr.Close()
		return nil, ctx.Err()
	}
}

var errNilV3Transport = errors.New("ewp/v3: nil message transport")
