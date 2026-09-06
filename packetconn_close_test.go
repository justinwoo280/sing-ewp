package ewp

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// backpressureTransport simulates a peer that never reads: every SendMessage
// blocks until Close interrupts it (TCP back-pressure analogue).
type backpressureTransport struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newBackpressureTransport() *backpressureTransport {
	return &backpressureTransport{closed: make(chan struct{})}
}

func (b *backpressureTransport) SendMessage([]byte) error {
	<-b.closed
	return errors.New("transport closed")
}

func (b *backpressureTransport) ReadMessage() ([]byte, error) {
	<-b.closed
	return nil, errors.New("transport closed")
}

func (b *backpressureTransport) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

// TestPacketConnCloseDoesNotHangOnBlockedPeer proves Close returns within
// roughly the 100 ms best-effort budget even when the peer never reads and
// SendUDPEnd would otherwise block forever (v3 sendEndBestEffort backport).
func TestPacketConnCloseDoesNotHangOnBlockedPeer(t *testing.T) {
	tr := newBackpressureTransport()
	key := hardRandKey()
	prefix := hardRandPrefix()
	send, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	stream := &SecureStream{tr: tr, version: protocolVersionV22, send: send}

	pc := newClientPacketConn(stream, nil, Address{Domain: "udp.example", Port: 53})
	// Mark the sub-session opened so Close attempts the UDP_END send.
	pc.openedMu.Lock()
	pc.opened = true
	pc.openedMu.Unlock()

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- pc.Close() }()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if elapsed > 2*time.Second {
			t.Fatalf("Close took %v; best-effort bound broken", elapsed)
		}
		t.Logf("Close returned in %v (err=%v)", elapsed, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung on a blocked peer (deadlock)")
	}
}
