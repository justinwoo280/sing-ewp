package ewp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestSecurity_ReplayCacheRejectsTooShortPublicWindow(t *testing.T) {
	c := NewReplayCache(time.Millisecond)
	defer c.Close()
	var uuid [UUIDLen]byte
	var nonce [HandshakeNonce]byte
	if !c.MarkSeenOrReject(uuid, nonce) {
		t.Fatal("first sight must be admitted")
	}
	if c.MarkSeenOrReject(uuid, nonce) {
		t.Fatal("replay must remain rejected")
	}
}

func TestSecurity_FrameRejectsCounterExhaustion(t *testing.T) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	enc, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	enc.counter = ^uint64(0)
	if err := EncodeFrame(io.Discard, enc, FrameTCPData, nil, []byte("x"), 0); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("want counter exhaustion, got %v", err)
	}
}

func TestSecurity_SecureStreamRejectsTrailingBytes(t *testing.T) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	enc, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := EncodeFrame(&wire, enc, FrameTCPData, nil, []byte("payload"), 0); err != nil {
		t.Fatal(err)
	}
	msg := append(append([]byte(nil), wire.Bytes()...), 0x7f)
	tr := &singleMessageTransport{msg: msg}
	stream := &SecureStream{tr: tr, recv: dec}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("trailing bytes must be rejected")
	}
}

func TestSecurity_SecureStreamCloseWipesFrameKeys(t *testing.T) {
	var key [AEADKeyLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	var prefix [NoncePrefixLen]byte
	stream, err := NewClientSecureStream(noopTransport{}, SessionKeys{
		C2SKey: key, S2CKey: key, C2SNonce: prefix, S2CNonce: prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if stream.send != nil || stream.recv != nil {
		t.Fatal("Close must drop frame AEAD references")
	}
}

func TestSecurity_SecureStreamSendFailureWipesFrameKeys(t *testing.T) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	stream, err := NewClientSecureStream(securityFailingSendTransport{}, SessionKeys{
		C2SKey: key, S2CKey: key, C2SNonce: prefix, S2CNonce: prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendTCPData([]byte("payload")); err == nil {
		t.Fatal("send failure must be returned")
	}
	if stream.send != nil || stream.recv != nil {
		t.Fatal("send failure must drop both frame AEAD references")
	}
}

func TestSecurity_SecureStreamConcurrentTerminationDoesNotDeadlock(t *testing.T) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	tr := &securityBlockingReadFailingSendTransport{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	stream, err := NewClientSecureStream(tr, SessionKeys{
		C2SKey: key, S2CKey: key, C2SNonce: prefix, S2CNonce: prefix,
	})
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		readDone <- err
	}()
	select {
	case <-tr.readStarted:
	case <-time.After(time.Second):
		t.Fatal("Recv did not enter transport read")
	}
	if err := stream.SendTCPData([]byte("payload")); err == nil {
		t.Fatal("send failure must be returned")
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Recv unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent send and receive termination deadlocked")
	}
	if stream.send != nil || stream.recv != nil {
		t.Fatal("concurrent termination must drop both frame AEAD references")
	}
}

func TestSecurity_SecureStreamRejectsTrailingUDPMeta(t *testing.T) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	enc, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	var globalID [8]byte
	meta, err := buildUDPMeta(globalID, Address{Domain: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	meta = append(meta, 0x7f)
	var wire bytes.Buffer
	if err := EncodeFrame(&wire, enc, FrameUDPNew, meta, nil, 0); err != nil {
		t.Fatal(err)
	}
	stream := &SecureStream{tr: &singleMessageTransport{msg: wire.Bytes()}, recv: dec}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("trailing UDP metadata must be rejected")
	}
}

func TestSecurity_StreamConnClosesOnUDPFrame(t *testing.T) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	enc, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	var globalID [8]byte
	meta, err := buildUDPMeta(globalID, Address{Domain: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := EncodeFrame(&wire, enc, FrameUDPData, meta, []byte("payload"), 0); err != nil {
		t.Fatal(err)
	}
	stream := &SecureStream{tr: &singleMessageTransport{msg: wire.Bytes()}, recv: dec}
	conn := &streamConn{SecureStream: stream}
	if _, err := conn.Read(make([]byte, 32)); err == nil {
		t.Fatal("TCP stream must reject UDP frame")
	}
	if !stream.closed.Load() || stream.recv != nil {
		t.Fatal("mode violation must close and wipe the stream")
	}
}

func TestSecurity_PacketConnClosesOnRepeatedUDPNew(t *testing.T) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	enc, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	tr := &singleMessageTransport{}
	stream := &SecureStream{tr: tr, recv: dec}
	p := newClientPacketConn(stream, nil, Address{Domain: "example.com", Port: 443})
	meta, err := buildUDPMeta(p.globalID, Address{Domain: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := EncodeFrame(&wire, enc, FrameUDPNew, meta, []byte("payload"), 0); err != nil {
		t.Fatal(err)
	}
	tr.msg = wire.Bytes()
	if _, _, err := p.ReadFrom(make([]byte, 32)); err == nil {
		t.Fatal("packet conn must reject a repeated UDP_NEW")
	}
	if !stream.closed.Load() || stream.recv != nil {
		t.Fatal("mode violation must close and wipe the stream")
	}
}

func TestSecurity_PacketConnConcurrentFirstWrites(t *testing.T) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	send, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	tr := &securityCaptureTransport{}
	stream := &SecureStream{tr: tr, send: send}
	p := newClientPacketConn(stream, nil, Address{Domain: "example.com", Port: 443})
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n, err := p.WriteToAddress([]byte{byte(i)}, Address{Domain: "example.com", Port: 443})
			if err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			results <- n
		}(i)
	}
	wg.Wait()
	close(results)
	for n := range results {
		if n != 1 {
			t.Fatalf("write returned %d bytes", n)
		}
	}
	tr.mu.Lock()
	msgs := append([][]byte(nil), tr.msgs...)
	tr.mu.Unlock()
	if len(msgs) != 2 {
		t.Fatalf("got %d frames, want UDP_NEW plus UDP_DATA", len(msgs))
	}
	var newCount, dataCount int
	for i, msg := range msgs {
		frame, err := DecodeFrame(bytes.NewReader(msg), dec)
		if err != nil {
			t.Fatalf("decode frame %d: %v", i, err)
		}
		switch frame.Type {
		case FrameUDPNew:
			newCount++
		case FrameUDPData:
			dataCount++
		default:
			t.Fatalf("unexpected frame type %v", frame.Type)
		}
	}
	if newCount != 1 || dataCount != 1 {
		t.Fatalf("got UDP_NEW=%d UDP_DATA=%d, want one of each", newCount, dataCount)
	}
}

func TestSecurity_HandshakeCancellationClosesTransport(t *testing.T) {
	tr := &blockingTransport{closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	state := make(chan struct{})
	go func() {
		_, _ = readMessageContext(ctx, tr)
		close(state)
	}()
	cancel()
	select {
	case <-state:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt handshake read")
	}
	select {
	case <-tr.closed:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not close transport")
	}
}

func TestSecurity_AddressRejectsControlCharacters(t *testing.T) {
	for _, domain := range []string{"bad\r\nX", "bad\x1b[31m", "bad\x00name"} {
		if _, err := (Address{Domain: domain, Port: 443}).Append(nil); err == nil {
			t.Fatalf("domain %q with control characters must be rejected", domain)
		}
	}
}

type singleMessageTransport struct {
	msg  []byte
	used bool
}

func (t *singleMessageTransport) SendMessage([]byte) error { return nil }
func (t *singleMessageTransport) ReadMessage() ([]byte, error) {
	if t.used {
		return nil, io.EOF
	}
	t.used = true
	return t.msg, nil
}
func (t *singleMessageTransport) Close() error { return nil }

type noopTransport struct{}

func (noopTransport) SendMessage([]byte) error     { return nil }
func (noopTransport) ReadMessage() ([]byte, error) { return nil, io.EOF }
func (noopTransport) Close() error                 { return nil }

type securityFailingSendTransport struct{}

func (securityFailingSendTransport) SendMessage([]byte) error { return io.ErrClosedPipe }
func (securityFailingSendTransport) ReadMessage() ([]byte, error) {
	return nil, io.EOF
}
func (securityFailingSendTransport) Close() error { return nil }

type securityBlockingReadFailingSendTransport struct {
	readStarted chan struct{}
	closed      chan struct{}
	once        sync.Once
}

func (t *securityBlockingReadFailingSendTransport) SendMessage([]byte) error {
	return io.ErrClosedPipe
}
func (t *securityBlockingReadFailingSendTransport) ReadMessage() ([]byte, error) {
	close(t.readStarted)
	<-t.closed
	return nil, io.ErrClosedPipe
}
func (t *securityBlockingReadFailingSendTransport) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

type securityCaptureTransport struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (t *securityCaptureTransport) SendMessage(msg []byte) error {
	t.mu.Lock()
	t.msgs = append(t.msgs, append([]byte(nil), msg...))
	t.mu.Unlock()
	return nil
}
func (t *securityCaptureTransport) ReadMessage() ([]byte, error) { return nil, io.EOF }
func (t *securityCaptureTransport) Close() error                 { return nil }

type blockingTransport struct {
	closed chan struct{}
	once   sync.Once
}

func (t *blockingTransport) SendMessage([]byte) error { return nil }
func (t *blockingTransport) ReadMessage() ([]byte, error) {
	<-t.closed
	return nil, io.ErrClosedPipe
}
func (t *blockingTransport) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}
