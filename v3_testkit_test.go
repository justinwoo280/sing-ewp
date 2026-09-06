package ewp

import (
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type v3Fixture struct {
	listener   V3ListenerContext
	identity   ServerSigningIdentity
	material   V3PreKeyMaterial
	provider   *MemoryPreKeyProvider
	credential ClientCredential
	principal  V3Principal
}

func newV3Fixture(t *testing.T) *v3Fixture {
	t.Helper()
	identity, err := GenerateServerSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listener := V3ListenerContext{
		Version:         V3ProtocolVersion,
		Suite:           V3SuiteX25519MLKEM768ChaCha20Poly1305,
		ServerID:        "test-server",
		DeploymentScope: "test-scope",
	}
	var preKeyID PreKeyID
	for i := range preKeyID {
		preKeyID[i] = byte(i + 1)
	}
	now := time.Now()
	material, err := GenerateV3PreKeyMaterial(listener, identity, preKeyID, 1, 7, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewMemoryPreKeyProvider(material)
	if err != nil {
		t.Fatal(err)
	}
	var principalID PrincipalID
	for i := range principalID {
		principalID[i] = byte(0xa0 + i)
	}
	var kAuth [V3KAuthLen]byte
	for i := range kAuth {
		kAuth[i] = byte(0x30 + i)
	}
	principal := V3Principal{ID: principalID, KAuth: kAuth, Listener: listener, RouteEpoch: 7}
	if err := provider.AddPrincipal(principal); err != nil {
		t.Fatal(err)
	}
	return &v3Fixture{
		listener:   listener,
		identity:   identity,
		material:   material,
		provider:   provider,
		credential: ClientCredential{Principal: principalID, KAuth: kAuth, Listener: listener, RouteEpoch: 7},
		principal:  principal,
	}
}

func (f *v3Fixture) newClient(t *testing.T) *ClientV3 {
	t.Helper()
	client, err := NewClientV3(f.credential, f.identity.Public, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (f *v3Fixture) newService(t *testing.T, handler Handler, admission AdmissionController) *ServiceV3 {
	t.Helper()
	if admission == nil {
		var err error
		admission, err = NewV3AdmissionController(64, 64, 16, 16, 16, 4)
		if err != nil {
			t.Fatal(err)
		}
	}
	service, err := NewServiceV3(handler, f.listener, f.identity, f.provider, admission)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type v3EchoHandler struct {
	called chan Metadata
}

func (h *v3EchoHandler) NewConnection(_ context.Context, conn net.Conn, metadata Metadata) error {
	if h.called != nil {
		h.called <- metadata
	}
	defer conn.Close()
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf[:n])
	return err
}

func (h *v3EchoHandler) NewPacketConnection(_ context.Context, conn net.PacketConn, _ Metadata) error {
	_ = conn.Close()
	return errors.New("v3 test: unexpected packet handler")
}

type v3UDPEchoHandler struct {
	called chan Metadata
}

func (h *v3UDPEchoHandler) NewConnection(_ context.Context, conn net.Conn, _ Metadata) error {
	_ = conn.Close()
	return errors.New("v3 test: unexpected stream handler")
}

func (h *v3UDPEchoHandler) NewPacketConnection(_ context.Context, conn net.PacketConn, metadata Metadata) error {
	if h.called != nil {
		h.called <- metadata
	}
	defer conn.Close()
	buf := make([]byte, 2048)
	n, source, err := conn.ReadFrom(buf)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(buf[:n], source)
	return err
}

type v3AsyncRouteHandler struct {
	dispatched chan Metadata
}

func (h *v3AsyncRouteHandler) NewConnection(_ context.Context, conn net.Conn, metadata Metadata) error {
	// sing-box style handoff: dispatch asynchronously and return immediately.
	go func() {
		defer conn.Close()
		buf := make([]byte, 2048)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	h.dispatched <- metadata
	return nil
}

func (h *v3AsyncRouteHandler) NewPacketConnection(context.Context, net.PacketConn, Metadata) error {
	return errors.New("v3 test: unexpected packet handler")
}

type v3FailHandler struct{}

func (v3FailHandler) NewConnection(context.Context, net.Conn, Metadata) error {
	return errors.New("v3 test: handler rejected connection")
}

func (v3FailHandler) NewPacketConnection(context.Context, net.PacketConn, Metadata) error {
	return errors.New("v3 test: handler rejected packet connection")
}

type v3ContextBlockingHandler struct {
	started chan struct{}
	stopped chan struct{}
}

type v3FailServerFinishedTransport struct {
	*v3DuplexTransport
	fail bool
}

func (t *v3FailServerFinishedTransport) SendMessage(message []byte) error {
	if t.fail {
		if _, err := ParseV3ServerFinished(message); err == nil {
			t.fail = false
			return errors.New("v3 test: injected ServerFinished write failure")
		}
	}
	return t.v3DuplexTransport.SendMessage(message)
}

func (h *v3ContextBlockingHandler) NewConnection(ctx context.Context, _ net.Conn, _ Metadata) error {
	close(h.started)
	<-ctx.Done()
	close(h.stopped)
	return nil
}

func (h *v3ContextBlockingHandler) NewPacketConnection(context.Context, net.PacketConn, Metadata) error {
	return errors.New("v3 test: unexpected packet handler")
}

type v3CountingAdmission struct {
	allowInit   atomic.Bool
	allowHello  atomic.Bool
	initCalls   atomic.Int32
	helloCalls  atomic.Int32
	kemCalls    atomic.Int32
	initActive  atomic.Int32
	helloActive atomic.Int32
}

func (a *v3CountingAdmission) AllowInit(SourceBinding) bool {
	a.initCalls.Add(1)
	return a.allowInit.Load()
}

func (a *v3CountingAdmission) AllowClientHello(SourceBinding, PrincipalID) bool {
	a.helloCalls.Add(1)
	return a.allowHello.Load()
}

func (a *v3CountingAdmission) AcquireInit(ctx context.Context, source SourceBinding) (func(), error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if !a.AllowInit(source) {
		return nil, ErrV3Admission
	}
	a.initActive.Add(1)
	var once sync.Once
	return func() { once.Do(func() { a.initActive.Add(-1) }) }, nil
}

func (a *v3CountingAdmission) ReserveClientHello(ctx context.Context, source SourceBinding, principal PrincipalID) (func(), error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if !a.AllowClientHello(source, principal) {
		return nil, ErrV3Admission
	}
	a.helloActive.Add(1)
	var once sync.Once
	return func() { once.Do(func() { a.helloActive.Add(-1) }) }, nil
}

func (a *v3CountingAdmission) AcquireKEM(context.Context) (func(), error) {
	a.kemCalls.Add(1)
	return func() {}, nil
}

type v3CountingPreKeyProvider struct {
	inner  *MemoryPreKeyProvider
	claims atomic.Int32
}

func (p *v3CountingPreKeyProvider) CurrentBundles(ctx context.Context, listener V3ListenerContext) ([]V3PreKeyBundle, error) {
	return p.inner.CurrentBundles(ctx, listener)
}

func (p *v3CountingPreKeyProvider) LookupRouteTag(ctx context.Context, listener V3ListenerContext, tag RouteTag, epoch uint64) (V3Principal, bool) {
	return p.inner.LookupRouteTag(ctx, listener, tag, epoch)
}

func (p *v3CountingPreKeyProvider) ClaimAndBurn(ctx context.Context, listener V3ListenerContext, claim V3PreKeyClaim) (V3ConsumedPreKey, error) {
	p.claims.Add(1)
	return p.inner.ClaimAndBurn(ctx, listener, claim)
}

type v3DuplexTransport struct {
	readCh  <-chan []byte
	writeCh chan<- []byte
	close   func()
	sendMu  *sync.RWMutex
}

func (t *v3DuplexTransport) SendMessage(message []byte) (err error) {
	if t.sendMu != nil {
		t.sendMu.RLock()
		defer t.sendMu.RUnlock()
	}
	defer func() {
		if recover() != nil {
			err = io.ErrClosedPipe
		}
	}()
	if message == nil {
		message = []byte{}
	}
	select {
	case t.writeCh <- append([]byte(nil), message...):
		return nil
	default:
		return io.ErrShortWrite
	}
}

func (t *v3DuplexTransport) ReadMessage() ([]byte, error) {
	message, ok := <-t.readCh
	if !ok {
		return nil, io.EOF
	}
	return append([]byte(nil), message...), nil
}

func (t *v3DuplexTransport) Close() error {
	if t.close != nil {
		t.close()
	}
	return nil
}

func newV3DuplexPair() (*v3DuplexTransport, *v3DuplexTransport) {
	leftToRight := make(chan []byte, 16)
	rightToLeft := make(chan []byte, 16)
	sendMu := new(sync.RWMutex)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			sendMu.Lock()
			defer sendMu.Unlock()
			close(leftToRight)
			close(rightToLeft)
		})
	}
	return &v3DuplexTransport{readCh: rightToLeft, writeCh: leftToRight, close: closeBoth, sendMu: sendMu},
		&v3DuplexTransport{readCh: leftToRight, writeCh: rightToLeft, close: closeBoth, sendMu: sendMu}
}

type v3AddressedDuplexTransport struct {
	*v3DuplexTransport
	local  net.Addr
	remote net.Addr
}

func (t *v3AddressedDuplexTransport) LocalAddr() net.Addr  { return t.local }
func (t *v3AddressedDuplexTransport) RemoteAddr() net.Addr { return t.remote }
func (t *v3AddressedDuplexTransport) SetDeadline(time.Time) error {
	return nil
}
func (t *v3AddressedDuplexTransport) SetReadDeadline(time.Time) error {
	return nil
}
func (t *v3AddressedDuplexTransport) SetWriteDeadline(time.Time) error {
	return nil
}

func newV3AddressedDuplexPair() (*v3AddressedDuplexTransport, *v3AddressedDuplexTransport) {
	left, right := newV3DuplexPair()
	leftAddr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 41000}
	rightAddr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 443}
	return &v3AddressedDuplexTransport{v3DuplexTransport: left, local: leftAddr, remote: rightAddr},
		&v3AddressedDuplexTransport{v3DuplexTransport: right, local: rightAddr, remote: leftAddr}
}

func newV3Runtime(now time.Time) v3Runtime {
	return v3Runtime{now: func() time.Time { return now }, random: crand.Reader}
}
