package ewp

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type deadlineSetter interface {
	SetDeadline(time.Time) error
}

// DefaultHandshakeTimeout bounds a handshake when the caller does not
// provide a shorter deadline. A handshake must not be able to hold an
// unauthenticated connection open indefinitely.
const (
	DefaultHandshakeTimeout   = 30 * time.Second
	DefaultClientInitTimeout  = 5 * time.Second
	DefaultHelloRetryTimeout  = 5 * time.Second
	DefaultClientHelloTimeout = 10 * time.Second
	DefaultServerHelloTimeout = 10 * time.Second
	DefaultFinishedTimeout    = 10 * time.Second
)

func withV3StageDeadline(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, timeout)
}

func readV3MessageStage(parent context.Context, tr MessageTransport, timeout time.Duration) ([]byte, error) {
	ctx, cancel := withV3StageDeadline(parent, timeout)
	defer cancel()
	return readV3MessageContext(ctx, tr)
}

func sendV3MessageStage(parent context.Context, tr MessageTransport, message []byte, timeout time.Duration) error {
	ctx, cancel := withV3StageDeadline(parent, timeout)
	defer cancel()
	return sendV3MessageContext(ctx, tr, message)
}

func consumeV3HandshakeBytes(remaining *int, size int) error {
	if remaining == nil || size < 0 || size > *remaining {
		return ErrV3MessageTooLarge
	}
	*remaining -= size
	return nil
}

type handshakeGuard struct {
	tr       MessageTransport
	cancel   context.CancelFunc
	done     chan struct{}
	finished atomic.Bool
	once     sync.Once
}

// beginHandshake applies a finite deadline and makes context cancellation
// effective even for transports that do not expose SetDeadline. The transport
// contract requires Close to interrupt an in-flight ReadMessage/SendMessage.
func beginHandshake(ctx context.Context, tr MessageTransport) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	hctx, cancel := context.WithTimeout(ctx, DefaultHandshakeTimeout)
	g := &handshakeGuard{
		tr:     tr,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	if dc, ok := tr.(deadlineSetter); ok {
		if deadline, ok := hctx.Deadline(); ok {
			_ = dc.SetDeadline(deadline)
		}
	}

	go func() {
		select {
		case <-hctx.Done():
			if !g.finished.Load() {
				_ = tr.Close()
			}
		case <-g.done:
		}
	}()

	finish := func() {
		g.once.Do(func() {
			g.finished.Store(true)
			close(g.done)
			cancel()
			if dc, ok := tr.(deadlineSetter); ok {
				_ = dc.SetDeadline(time.Time{})
			}
		})
	}
	return hctx, finish
}

func watchV3TransportContext(ctx context.Context, tr MessageTransport) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
			if tr != nil {
				_ = tr.Close()
			}
		case <-stop:
		}
	}()
	return func() {
		once.Do(func() { close(stop) })
	}
}

type messageResult struct {
	msg []byte
	err error
}

// readMessageContext returns on context cancellation and closes the
// transport. The result channel is buffered so the reader goroutine can exit
// if Close races with a successful read.
func readMessageContext(ctx context.Context, tr MessageTransport) ([]byte, error) {
	resultCh := make(chan messageResult, 1)
	go func() {
		msg, err := tr.ReadMessage()
		if err == nil && len(msg) > MaxV3MessageSize {
			err = ErrV3MessageTooLarge
			msg = nil
		}
		resultCh <- messageResult{msg: msg, err: err}
	}()
	select {
	case result := <-resultCh:
		return result.msg, result.err
	case <-ctx.Done():
		_ = tr.Close()
		return nil, ctx.Err()
	}
}

// sendMessageContext gives the one-shot handshake response the same
// cancellation behavior as the handshake read path.
func sendMessageContext(ctx context.Context, tr MessageTransport, msg []byte) error {
	if len(msg) > MaxV3MessageSize {
		return ErrV3MessageTooLarge
	}
	resultCh := make(chan error, 1)
	go func() { resultCh <- tr.SendMessage(msg) }()
	select {
	case err := <-resultCh:
		return err
	case <-ctx.Done():
		_ = tr.Close()
		return ctx.Err()
	}
}
