package ewp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type v3ContextTransport struct {
	readCh      chan []byte
	writeCh     chan []byte
	closed      chan struct{}
	readStarted chan struct{}
	sendStarted chan struct{}

	closeOnce        sync.Once
	readStartOnce    sync.Once
	sendStartOnce    sync.Once
	closeCalls       atomic.Int32
	legacyReadCalls  atomic.Int32
	legacySendCalls  atomic.Int32
	contextReadCalls atomic.Int32
	contextSendCalls atomic.Int32
}

func newV3ContextTransport() *v3ContextTransport {
	return &v3ContextTransport{
		readCh:      make(chan []byte),
		writeCh:     make(chan []byte),
		closed:      make(chan struct{}),
		readStarted: make(chan struct{}),
		sendStarted: make(chan struct{}),
	}
}

func (t *v3ContextTransport) SendMessage([]byte) error {
	t.legacySendCalls.Add(1)
	return errors.New("legacy send path used")
}

func (t *v3ContextTransport) ReadMessage() ([]byte, error) {
	t.legacyReadCalls.Add(1)
	select {
	case message := <-t.readCh:
		return message, nil
	case <-t.closed:
		return nil, errors.New("closed")
	}
}

func (t *v3ContextTransport) Close() error {
	t.closeOnce.Do(func() {
		t.closeCalls.Add(1)
		close(t.closed)
	})
	return nil
}

func (t *v3ContextTransport) SendMessageContext(ctx context.Context, message []byte) error {
	t.contextSendCalls.Add(1)
	t.sendStartOnce.Do(func() { close(t.sendStarted) })
	select {
	case t.writeCh <- append([]byte(nil), message...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closed:
		return errors.New("closed")
	}
}

func (t *v3ContextTransport) ReadMessageContext(ctx context.Context) ([]byte, error) {
	t.contextReadCalls.Add(1)
	t.readStartOnce.Do(func() { close(t.readStarted) })
	select {
	case message := <-t.readCh:
		return message, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closed:
		return nil, errors.New("closed")
	}
}

func TestV3ContextMessageTransportMethodsArePreferred(t *testing.T) {
	transport := newV3ContextTransport()
	ctx, cancel := context.WithCancel(context.Background())
	readDone := make(chan error, 1)
	go func() {
		_, err := readV3MessageContext(ctx, transport)
		readDone <- err
	}()
	select {
	case <-transport.readStarted:
	case <-time.After(time.Second):
		t.Fatal("context-aware read did not start")
	}
	cancel()
	select {
	case err := <-readDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context-aware read did not return")
	}
	if got := transport.contextReadCalls.Load(); got != 1 {
		t.Fatalf("context read calls = %d, want 1", got)
	}
	if got := transport.legacyReadCalls.Load(); got != 0 {
		t.Fatalf("legacy read calls = %d, want 0", got)
	}
	if got := transport.closeCalls.Load(); got != 0 {
		t.Fatalf("transport close calls = %d, want 0", got)
	}

	sendCtx, sendCancel := context.WithCancel(context.Background())
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- sendV3MessageContext(sendCtx, transport, []byte("cancelled"))
	}()
	select {
	case <-transport.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("context-aware send did not start")
	}
	sendCancel()
	select {
	case err := <-sendDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("send error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context-aware send did not return")
	}
	if got := transport.contextSendCalls.Load(); got != 1 {
		t.Fatalf("context send calls = %d, want 1", got)
	}
	if got := transport.legacySendCalls.Load(); got != 0 {
		t.Fatalf("legacy send calls = %d, want 0", got)
	}
}
