package ewp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type v3UDPDispatchResult struct {
	id      [8]byte
	payload string
	source  Address
}

type v3UDPDispatchHandler struct {
	results chan v3UDPDispatchResult
}

func (h *v3UDPDispatchHandler) NewConnection(context.Context, net.Conn, Metadata) error {
	return errors.New("v3 test: unexpected TCP dispatch")
}

func (h *v3UDPDispatchHandler) NewPacketConnection(_ context.Context, conn net.PacketConn, _ Metadata) error {
	packetConn, ok := conn.(*v3UDPPacketSession)
	if !ok {
		return errors.New("v3 test: unexpected packet session type")
	}
	buffer := make([]byte, 128)
	n, source, err := packetConn.ReadFrom(buffer)
	if err != nil {
		return err
	}
	h.results <- v3UDPDispatchResult{id: packetConn.globalID, payload: string(buffer[:n]), source: mustAddressFromNetAddr(source)}
	return nil
}

func mustAddressFromNetAddr(addr net.Addr) Address {
	result, err := addrToEWP(addr)
	if err != nil {
		return Address{}
	}
	return result
}

type v3BlockingUDPDispatchHandler struct{}

func (v3BlockingUDPDispatchHandler) NewConnection(context.Context, net.Conn, Metadata) error {
	return errors.New("v3 test: unexpected TCP dispatch")
}

func (v3BlockingUDPDispatchHandler) NewPacketConnection(ctx context.Context, conn net.PacketConn, _ Metadata) error {
	if _, ok := conn.(*v3UDPPacketSession); !ok {
		return errors.New("v3 test: unexpected packet session type")
	}
	<-ctx.Done()
	return nil
}

type v3ContextUDPDispatchHandler struct {
	started chan struct{}
	stopped chan struct{}
}

func (h *v3ContextUDPDispatchHandler) NewConnection(context.Context, net.Conn, Metadata) error {
	return errors.New("v3 test: unexpected TCP dispatch")
}

func (h *v3ContextUDPDispatchHandler) NewPacketConnection(ctx context.Context, conn net.PacketConn, _ Metadata) error {
	close(h.started)
	<-ctx.Done()
	close(h.stopped)
	return nil
}

type v3BlockingWriteTransport struct {
	closed  chan struct{}
	started chan struct{}
	once    sync.Once
}

func newV3BlockingWriteTransport() *v3BlockingWriteTransport {
	return &v3BlockingWriteTransport{closed: make(chan struct{}), started: make(chan struct{})}
}

func (t *v3BlockingWriteTransport) SendMessage([]byte) error {
	select {
	case <-t.started:
	default:
		close(t.started)
	}
	<-t.closed
	return io.ErrClosedPipe
}

func (t *v3BlockingWriteTransport) ReadMessage() ([]byte, error) {
	<-t.closed
	return nil, io.ErrClosedPipe
}

func (t *v3BlockingWriteTransport) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

func TestV3UDPDispatcherMultiplexesIndependentHandlers(t *testing.T) {
	clientTransport, serverTransport := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(clientTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(serverTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	handler := &v3UDPDispatchHandler{results: make(chan v3UDPDispatchResult, 2)}
	dispatcher := newV3UDPDispatcher(context.Background(), server, nil, handler, Metadata{Destination: Address{Domain: "anchor.example", Port: 53}}, newV3Runtime(time.Unix(1_700_000_000, 0)))
	done := make(chan error, 1)
	go func() { done <- dispatcher.run() }()

	firstID := [8]byte{1}
	secondID := [8]byte{2}
	firstTarget := Address{Domain: "one.example", Port: 1001}
	secondTarget := Address{Domain: "two.example", Port: 1002}
	if err := client.SendUDPNew(firstID, firstTarget, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := client.SendUDPNew(secondID, secondTarget, []byte("two")); err != nil {
		t.Fatal(err)
	}

	results := make(map[[8]byte]v3UDPDispatchResult)
	for len(results) < 2 {
		select {
		case result := <-handler.results:
			results[result.id] = result
		case <-time.After(time.Second):
			t.Fatal("not all UDP sub-session handlers were dispatched")
		}
	}
	if results[firstID].payload != "one" || results[firstID].source != firstTarget {
		t.Fatalf("first session result = %#v", results[firstID])
	}
	if results[secondID].payload != "two" || results[secondID].source != secondTarget {
		t.Fatalf("second session result = %#v", results[secondID])
	}

	_ = client.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("dispatcher error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop after carrier close")
	}
}

func TestV3UDPDispatcherRejectsDuplicateAndUnknownIDs(t *testing.T) {
	clientTransport, serverTransport := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(clientTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(serverTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	handler := &v3UDPDispatchHandler{results: make(chan v3UDPDispatchResult, 1)}
	dispatcher := newV3UDPDispatcher(context.Background(), server, nil, handler, Metadata{}, newV3Runtime(time.Unix(1_700_000_000, 0)))
	done := make(chan error, 1)
	go func() { done <- dispatcher.run() }()

	gid := [8]byte{0x41}
	target := Address{Domain: "duplicate.example", Port: 1001}
	if err := client.SendUDPNew(gid, target, []byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.results:
	case <-time.After(time.Second):
		t.Fatal("initial UDP sub-session was not dispatched")
	}
	if err := client.SendUDPNew(gid, target, []byte("duplicate")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrV3State) {
			t.Fatalf("duplicate UDP_NEW error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("duplicate UDP_NEW was not rejected")
	}

	clientTransport, serverTransport = newV3DuplexPair()
	client, err = NewClientSecureStreamV3(clientTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewServerSecureStreamV3(serverTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher = newV3UDPDispatcher(context.Background(), server, nil, handler, Metadata{}, newV3Runtime(time.Unix(1_700_000_000, 0)))
	done = make(chan error, 1)
	go func() { done <- dispatcher.run() }()
	unknownID := [8]byte{0x42}
	if err := client.SendUDPData(unknownID, target, []byte("unknown")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrV3State) {
			t.Fatalf("unknown UDP_DATA error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unknown UDP_DATA was not rejected")
	}
}

func TestV3UDPDispatcherClosesOnlyFullSubSessionQueue(t *testing.T) {
	clientTransport, serverTransport := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(clientTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(serverTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newV3UDPDispatcher(context.Background(), server, nil, v3BlockingUDPDispatchHandler{}, Metadata{}, newV3Runtime(time.Unix(1_700_000_000, 0)))
	blockedID := [8]byte{0x51}
	target := Address{Domain: "backpressure.example", Port: 1001}
	if err := dispatcher.open(&Event{Type: FrameUDPNew, GlobalID: blockedID, Address: target, HasAddr: true, Payload: []byte("initial")}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxV3UDPQueuePackets-1; i++ {
		if err := dispatcher.deliver(&Event{Type: FrameUDPData, GlobalID: blockedID, Address: target, HasAddr: true, Payload: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := dispatcher.deliver(&Event{Type: FrameUDPData, GlobalID: blockedID, Address: target, HasAddr: true, Payload: []byte("overflow")}); err != nil {
		t.Fatal(err)
	}
	dispatcher.mu.Lock()
	_, stillOpen := dispatcher.sessions[blockedID]
	_, tombstoned := dispatcher.ended[blockedID]
	dispatcher.mu.Unlock()
	if stillOpen || !tombstoned {
		t.Fatalf("full queue state: stillOpen=%v tombstoned=%v", stillOpen, tombstoned)
	}
	dispatcher.shutdown()
	_ = client.Close()
}

func TestV3UDPDispatcherContextCancellationClosesCarrier(t *testing.T) {
	clientTransport, serverTransport := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(clientTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(serverTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	handler := &v3ContextUDPDispatchHandler{started: make(chan struct{}), stopped: make(chan struct{})}
	dispatcher := newV3UDPDispatcher(ctx, server, nil, handler, Metadata{}, newV3Runtime(time.Unix(1_700_000_000, 0)))
	done := make(chan error, 1)
	go func() { done <- dispatcher.run() }()
	if err := dispatcher.open(&Event{Type: FrameUDPNew, GlobalID: [8]byte{0x61}, Address: Address{Domain: "cancel.example", Port: 53}, HasAddr: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("UDP handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.EOF) {
			t.Fatalf("dispatcher cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop after context cancellation")
	}
	select {
	case <-handler.stopped:
	case <-time.After(time.Second):
		t.Fatal("UDP handler did not stop after context cancellation")
	}
	_ = client.Close()
}

func TestV3UDPPacketSessionReadAfterClose(t *testing.T) {
	newSession := func() *v3UDPPacketSession {
		return &v3UDPPacketSession{
			queue:         make(chan v3UDPDatagram, 1),
			deadlineCh:    make(chan struct{}),
			done:          make(chan struct{}),
			closeComplete: make(chan struct{}),
		}
	}

	local := newSession()
	if !local.enqueue(&Event{GlobalID: local.globalID, Payload: []byte("queued")}) {
		t.Fatal("failed to queue local test datagram")
	}
	if err := local.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := local.ReadFrom(make([]byte, 32)); !errors.Is(err, ErrPacketConnClosed) {
		t.Fatalf("local close read error = %v", err)
	}

	remote := newSession()
	if !remote.enqueue(&Event{GlobalID: remote.globalID, Payload: []byte("queued")}) {
		t.Fatal("failed to queue remote test datagram")
	}
	remote.remoteClose()
	if _, _, err := remote.ReadFrom(make([]byte, 32)); !errors.Is(err, io.EOF) {
		t.Fatalf("remote close read error = %v", err)
	}
}

func TestV3UDPPacketSessionDeadlineUpdateUnblocksRead(t *testing.T) {
	session := &v3UDPPacketSession{
		queue:         make(chan v3UDPDatagram, 1),
		done:          make(chan struct{}),
		closeComplete: make(chan struct{}),
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := session.ReadFrom(make([]byte, 32))
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := session.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if _, ok := err.(v3PacketDeadlineError); !ok {
			t.Fatalf("updated deadline error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read did not observe updated deadline")
	}
}

func TestV3UDPPacketSessionWriteDeadlineAbortsBlockedCarrier(t *testing.T) {
	transport := newV3BlockingWriteTransport()
	stream, err := NewClientSecureStreamV3(transport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	session := &v3UDPPacketSession{
		stream:        stream,
		globalID:      [8]byte{0x71},
		defaultDst:    Address{Domain: "write-deadline.example", Port: 53},
		deadlineCh:    make(chan struct{}),
		done:          make(chan struct{}),
		closeComplete: make(chan struct{}),
	}
	if err := session.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := session.WriteToAddress([]byte("blocked"), session.defaultDst)
		result <- err
	}()
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("blocked write did not start")
	}
	select {
	case err := <-result:
		if _, ok := err.(v3PacketDeadlineError); !ok {
			t.Fatalf("write deadline error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write did not honor deadline")
	}
	session.remoteClose()
}

func TestV3SecureStreamRejectsZeroUDPGlobalID(t *testing.T) {
	left, right := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(left, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(right, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	target := Address{Domain: "zero.example", Port: 1}
	if err := client.SendUDPNew([8]byte{}, target, []byte("zero")); !errors.Is(err, ErrV3State) {
		t.Fatalf("zero UDP_NEW error = %v", err)
	}
	if err := client.SendUDPData([8]byte{}, target, []byte("zero")); !errors.Is(err, ErrV3State) {
		t.Fatalf("zero UDP_DATA error = %v", err)
	}
	if err := client.SendUDPEnd([8]byte{}); !errors.Is(err, ErrV3State) {
		t.Fatalf("zero UDP_END error = %v", err)
	}
	_ = client.Close()
	_ = server.Close()
}
