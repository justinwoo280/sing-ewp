package ewp

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

type Metadata struct {
	PrincipalID PrincipalID
	Destination Address
	Source      net.Addr
}

type Handler interface {
	NewConnection(context.Context, net.Conn, Metadata) error
	NewPacketConnection(context.Context, net.PacketConn, Metadata) error
}

type ClientV3 struct {
	credential     ClientCredential
	serverIdentity Ed25519PublicKey
	bundles        PreKeyResolver

	mu                sync.Mutex
	hasGeneration     bool
	highestGeneration uint64
	usedPreKeys       map[PreKeyID]struct{}
	runtime           v3Runtime
}

func NewClientV3(credential ClientCredential, serverIdentity Ed25519PublicKey, bundles PreKeyResolver) (*ClientV3, error) {
	return newClientV3(credential, serverIdentity, bundles, productionV3Runtime())
}

func newClientV3(credential ClientCredential, serverIdentity Ed25519PublicKey, bundles PreKeyResolver, runtime v3Runtime) (*ClientV3, error) {
	if err := credential.validate(); err != nil {
		return nil, err
	}
	if isZeroEd25519PublicKey(serverIdentity) {
		return nil, ErrV3Identity
	}
	if bundles == nil {
		return nil, ErrV3PreKey
	}
	return &ClientV3{credential: credential, serverIdentity: serverIdentity, bundles: bundles, usedPreKeys: make(map[PreKeyID]struct{}), runtime: runtime}, nil
}

func (c *ClientV3) Credential() ClientCredential {
	if c == nil {
		return ClientCredential{}
	}
	return c.credential
}

func (c *ClientV3) selectBundle(ctx context.Context) (V3PreKeyBundle, error) {
	if c == nil || c.bundles == nil {
		return V3PreKeyBundle{}, ErrV3PreKey
	}
	bundles, err := c.bundles.CurrentBundles(ctx, c.credential.Listener)
	if err != nil {
		return V3PreKeyBundle{}, err
	}
	var highest uint64
	found := false
	for _, bundle := range bundles {
		if bundle.Version != c.credential.Listener.Version || bundle.Suite != c.credential.Listener.Suite ||
			bundle.ServerID != c.credential.Listener.ServerID || bundle.DeploymentScope != c.credential.Listener.DeploymentScope ||
			bundle.RouteEpoch != c.credential.RouteEpoch || !bundle.ValidAt(c.runtime.nowTime()) {
			continue
		}
		if err := bundle.Verify(c.serverIdentity); err != nil {
			continue
		}
		if !found || bundle.BundleGeneration > highest {
			highest = bundle.BundleGeneration
			found = true
		}
	}
	if !found {
		return V3PreKeyBundle{}, ErrV3PreKey
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.usedPreKeys == nil {
		c.usedPreKeys = make(map[PreKeyID]struct{})
	}
	currentIDs := make(map[PreKeyID]struct{}, len(bundles))
	for _, bundle := range bundles {
		currentIDs[bundle.PreKeyID] = struct{}{}
	}
	for id := range c.usedPreKeys {
		if _, present := currentIDs[id]; !present {
			delete(c.usedPreKeys, id)
		}
	}
	if c.hasGeneration && highest < c.highestGeneration {
		return V3PreKeyBundle{}, ErrV3PreKey
	}
	var selected V3PreKeyBundle
	for _, bundle := range bundles {
		if bundle.BundleGeneration != highest {
			continue
		}
		if _, used := c.usedPreKeys[bundle.PreKeyID]; used {
			continue
		}
		selected = bundle
		break
	}
	if selected.PreKeyID.isZero() {
		return V3PreKeyBundle{}, ErrV3PreKey
	}
	if len(c.usedPreKeys) >= MaxV3PreKeys {
		return V3PreKeyBundle{}, ErrV3PreKey
	}
	if !c.hasGeneration || highest > c.highestGeneration {
		c.highestGeneration = highest
		c.hasGeneration = true
	}
	c.usedPreKeys[selected.PreKeyID] = struct{}{}
	return selected, nil
}

func (c *ClientV3) DialConn(ctx context.Context, conn net.Conn, destination Address) (net.Conn, error) {
	if c == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, ErrV3State
	}
	if conn == nil {
		return nil, errors.New("ewp/v3: nil connection")
	}
	return c.dialMessageTransport(ctx, NewLengthFramer(conn), conn, destination)
}

// DialMessageTransport performs the v3 TCP handshake over a carrier that
// already preserves message boundaries. The returned net.Conn owns tr.
func (c *ClientV3) DialMessageTransport(ctx context.Context, tr MessageTransport, destination Address) (net.Conn, error) {
	if c == nil {
		if tr != nil {
			_ = tr.Close()
		}
		return nil, ErrV3State
	}
	return c.dialMessageTransport(ctx, tr, nil, destination)
}

func (c *ClientV3) dialMessageTransport(ctx context.Context, tr MessageTransport, underlying net.Conn, destination Address) (net.Conn, error) {
	stream, err := c.dialSecureStream(ctx, tr, CommandTCP, destination)
	if err != nil {
		return nil, err
	}
	return &streamConn{SecureStream: stream, underlying: underlying}, nil
}

func (c *ClientV3) DialPacketConn(ctx context.Context, conn net.Conn, destination Address) (net.PacketConn, error) {
	if c == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, ErrV3State
	}
	if conn == nil {
		return nil, errors.New("ewp/v3: nil connection")
	}
	return c.dialPacketMessageTransport(ctx, NewLengthFramer(conn), conn, destination)
}

// DialPacketMessageTransport performs the v3 UDP handshake over a carrier
// that already preserves message boundaries. The returned net.PacketConn
// owns tr and retains v2.1-style per-packet target addressing.
func (c *ClientV3) DialPacketMessageTransport(ctx context.Context, tr MessageTransport, destination Address) (net.PacketConn, error) {
	if c == nil {
		if tr != nil {
			_ = tr.Close()
		}
		return nil, ErrV3State
	}
	return c.dialPacketMessageTransport(ctx, tr, nil, destination)
}

func (c *ClientV3) dialPacketMessageTransport(ctx context.Context, tr MessageTransport, underlying net.Conn, destination Address) (net.PacketConn, error) {
	stream, err := c.dialSecureStream(ctx, tr, CommandUDP, destination)
	if err != nil {
		return nil, err
	}
	return newClientPacketConnWithRuntime(stream, underlying, destination, c.runtime), nil
}

func (c *ClientV3) dialSecureStream(ctx context.Context, tr MessageTransport, command Command, destination Address) (*SecureStream, error) {
	if c == nil {
		if tr != nil {
			_ = tr.Close()
		}
		return nil, ErrV3State
	}
	if tr == nil {
		return nil, errNilV3Transport
	}
	keys, _, err := c.handshakeWithDestination(ctx, tr, command, destination)
	if err != nil {
		return nil, err
	}
	stream, err := newClientSecureStreamV3WithRuntime(tr, keys, c.runtime)
	zeroV3SessionKeys(&keys)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	return stream, nil
}

func (c *ClientV3) handshake(ctx context.Context, tr MessageTransport) (V3SessionKeys, V3ClientHelloPlaintext, error) {
	return c.handshakeWithDestination(ctx, tr, CommandTCP, Address{})
}

func (c *ClientV3) handshakeWithDestination(ctx context.Context, tr MessageTransport, command Command, destination Address) (V3SessionKeys, V3ClientHelloPlaintext, error) {
	if c == nil {
		if tr != nil {
			_ = tr.Close()
		}
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, ErrV3State
	}
	hctx, finish := beginV3Handshake(ctx, tr)
	defer finish()
	remainingHandshakeBytes := MaxV3HandshakeBytes
	bundle, err := c.selectBundle(hctx)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	state, initBytes, err := startV3ClientHandshakeWithRuntime(c.credential, c.serverIdentity, bundle, command, destination, c.runtime)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	defer state.destroy()
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(initBytes)); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	if err := sendV3MessageStage(hctx, tr, initBytes, DefaultClientInitTimeout); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	retryBytes, err := readV3MessageStage(hctx, tr, DefaultHelloRetryTimeout)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(retryBytes)); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	retry, err := ParseV3HelloRetry(retryBytes)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	helloBytes, err := state.buildClientHello(retry)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(helloBytes)); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	if err := sendV3MessageStage(hctx, tr, helloBytes, DefaultClientHelloTimeout); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	serverHelloBytes, err := readV3MessageStage(hctx, tr, DefaultServerHelloTimeout)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(serverHelloBytes)); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	result, pending, clientFinishedBytes, err := state.completeServerHello(serverHelloBytes)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	defer clearPendingSecrets(&pending)
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(clientFinishedBytes)); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	if err := sendV3MessageStage(hctx, tr, clientFinishedBytes, DefaultFinishedTimeout); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	serverFinishedBytes, err := readV3MessageStage(hctx, tr, DefaultFinishedTimeout)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(serverFinishedBytes)); err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	tClientFinished := v3Hash("ewp/v3/client-finished", pending.TServerHello[:], clientFinishedBytes)
	tServerFinished, err := verifyV3ServerFinished(c.credential.Listener, pending, serverFinishedBytes, tClientFinished)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	keys, err := deriveV3ClientSession(pending, tServerFinished)
	if err != nil {
		_ = tr.Close()
		return V3SessionKeys{}, V3ClientHelloPlaintext{}, err
	}
	return keys, result.Plaintext, nil
}

type ServiceV3 struct {
	handler         Handler
	listener        V3ListenerContext
	identity        ServerSigningIdentity
	prekeys         PreKeyProvider
	resolver        CredentialResolver
	admission       AdmissionController
	admissionLeaser V3AdmissionLeaser
	cookieKeys      V3CookieKeys
	closed          atomic.Bool
	runtime         v3Runtime
	activeMu        sync.Mutex
	active          map[*activeV3Transport]struct{}
}

type activeV3Transport struct {
	tr     MessageTransport
	cancel context.CancelFunc
}

func NewServiceV3(handler Handler, listener V3ListenerContext, identity ServerSigningIdentity, prekeys PreKeyProvider, admission AdmissionController) (*ServiceV3, error) {
	cookieKeys, err := NewV3CookieKeys()
	if err != nil {
		return nil, err
	}
	return newServiceV3(handler, listener, identity, prekeys, admission, cookieKeys)
}

func NewServiceV3WithCookieKeys(handler Handler, listener V3ListenerContext, identity ServerSigningIdentity, prekeys PreKeyProvider, admission AdmissionController, cookieKeys V3CookieKeys) (*ServiceV3, error) {
	return newServiceV3(handler, listener, identity, prekeys, admission, cookieKeys)
}

func newServiceV3(handler Handler, listener V3ListenerContext, identity ServerSigningIdentity, prekeys PreKeyProvider, admission AdmissionController, cookieKeys V3CookieKeys) (*ServiceV3, error) {
	return newServiceV3WithRuntime(handler, listener, identity, prekeys, admission, cookieKeys, productionV3Runtime())
}

func newServiceV3WithRuntime(handler Handler, listener V3ListenerContext, identity ServerSigningIdentity, prekeys PreKeyProvider, admission AdmissionController, cookieKeys V3CookieKeys, runtime v3Runtime) (*ServiceV3, error) {
	if handler == nil {
		return nil, errors.New("ewp/v3: nil handler")
	}
	if err := listener.validate(); err != nil {
		return nil, err
	}
	if err := identity.validate(); err != nil {
		return nil, err
	}
	if prekeys == nil || admission == nil {
		return nil, ErrV3State
	}
	admissionLeaser, ok := admission.(V3AdmissionLeaser)
	if !ok || admissionLeaser == nil {
		return nil, ErrV3Admission
	}
	resolver := CredentialResolver(prekeys)
	if err := cookieKeys.validate(); err != nil {
		return nil, err
	}
	if cookieKeys.runtime.now == nil {
		cookieKeys.runtime = runtime
	}
	return &ServiceV3{handler: handler, listener: listener, identity: identity, prekeys: prekeys, resolver: resolver, admission: admission, admissionLeaser: admissionLeaser, cookieKeys: cookieKeys, runtime: runtime, active: make(map[*activeV3Transport]struct{})}, nil
}

func (s *ServiceV3) RotateCookieKeys() error {
	if s == nil || s.closed.Load() {
		return ErrV3State
	}
	return s.cookieKeys.Rotate()
}

func (s *ServiceV3) acquireInit(ctx context.Context, source SourceBinding) (func(), error) {
	return s.admissionLeaser.AcquireInit(ctx, source)
}

func (s *ServiceV3) reserveClientHello(ctx context.Context, source SourceBinding, principal PrincipalID) (func(), error) {
	return s.admissionLeaser.ReserveClientHello(ctx, source, principal)
}

func (s *ServiceV3) Close() error {
	if s != nil {
		if s.closed.Swap(true) {
			return nil
		}
		s.activeMu.Lock()
		transports := make([]MessageTransport, 0, len(s.active))
		for active := range s.active {
			if active != nil && active.tr != nil {
				if active.cancel != nil {
					active.cancel()
				}
				transports = append(transports, active.tr)
			}
		}
		s.activeMu.Unlock()
		for _, tr := range transports {
			_ = tr.Close()
		}
	}
	return nil
}

func (s *ServiceV3) HandleConn(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return errors.New("ewp/v3: nil connection")
	}
	source := SourceBindingFromAddr(conn.RemoteAddr())
	if len(source) == 0 {
		_ = conn.Close()
		return ErrV3Source
	}
	return s.handleTransport(ctx, NewLengthFramer(conn), conn, source)
}

func (s *ServiceV3) HandleMessageTransport(ctx context.Context, tr MessageTransport, underlying net.Conn) error {
	if underlying == nil {
		if tr != nil {
			_ = tr.Close()
		}
		return ErrV3Source
	}
	source := SourceBindingFromAddr(underlying.RemoteAddr())
	if len(source) == 0 {
		if tr != nil {
			_ = tr.Close()
		}
		_ = underlying.Close()
		return ErrV3Source
	}
	return s.handleTransport(ctx, tr, underlying, source)
}

// HandleMessageTransportWithSource is for transports whose trusted outer
// layer supplies a source token instead of a net.Conn peer address.
func (s *ServiceV3) HandleMessageTransportWithSource(ctx context.Context, tr MessageTransport, source SourceBinding) error {
	if len(source) == 0 || len(source) > V3MaxSourceLen {
		if tr != nil {
			_ = tr.Close()
		}
		return ErrV3Source
	}
	return s.handleTransport(ctx, tr, nil, source)
}

func (s *ServiceV3) handleTransport(ctx context.Context, tr MessageTransport, underlying net.Conn, source SourceBinding) error {
	if s == nil || s.closed.Load() {
		if tr != nil {
			_ = tr.Close()
		}
		return ErrV3State
	}
	if tr == nil {
		if underlying != nil {
			_ = underlying.Close()
		}
		return errNilV3Transport
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer tr.Close()
	appCtx, appCancel := context.WithCancel(ctx)
	active := &activeV3Transport{tr: tr, cancel: appCancel}
	s.activeMu.Lock()
	if s.closed.Load() {
		s.activeMu.Unlock()
		appCancel()
		return ErrV3State
	}
	s.active[active] = struct{}{}
	s.activeMu.Unlock()
	defer func() {
		appCancel()
		s.activeMu.Lock()
		delete(s.active, active)
		s.activeMu.Unlock()
	}()
	if len(source) == 0 || len(source) > V3MaxSourceLen {
		return ErrV3Source
	}
	stopWatch := watchV3TransportContext(appCtx, tr)
	defer stopWatch()
	hctx, finish := beginV3Handshake(appCtx, tr)
	defer finish()
	remainingHandshakeBytes := MaxV3HandshakeBytes
	releaseInit, err := s.acquireInit(hctx, source)
	if err != nil {
		return err
	}
	releaseInit = onceV3Release(releaseInit)
	defer releaseInit()
	initBytes, err := readV3MessageStage(hctx, tr, DefaultClientInitTimeout)
	if err != nil {
		return err
	}
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(initBytes)); err != nil {
		return err
	}
	init, err := ParseV3ClientInit(initBytes)
	if err != nil || init.Version != s.listener.Version || init.Suite != s.listener.Suite || init.ServerID != s.listener.ServerID || init.DeploymentScope != s.listener.DeploymentScope {
		return ErrV3Admission
	}
	retry, err := s.cookieKeys.mintAt(s.listener, init, source, s.runtime.nowTime(), s.runtime.reader())
	if err != nil {
		return err
	}
	retryBytes := retry.wireBytes()
	if len(retryBytes) == 0 {
		return ErrV3Malformed
	}
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(retryBytes)); err != nil {
		return err
	}
	if err := sendV3MessageStage(hctx, tr, retryBytes, DefaultHelloRetryTimeout); err != nil {
		return err
	}
	helloBytes, err := readV3MessageStage(hctx, tr, DefaultClientHelloTimeout)
	if err != nil {
		return err
	}
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(helloBytes)); err != nil {
		return err
	}
	releaseInit()
	serverHelloCtx, cancelServerHello := withV3StageDeadline(hctx, DefaultServerHelloTimeout)
	pending, serverHelloBytes, err := s.makeServerHello(serverHelloCtx, init, initBytes, retry, source, helloBytes)
	if err != nil {
		cancelServerHello()
		return err
	}
	defer clearPendingSecrets(&pending)
	releaseHello := onceV3Release(pending.admissionRelease)
	defer releaseHello()
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(serverHelloBytes)); err != nil {
		cancelServerHello()
		return err
	}
	if err := sendV3MessageContext(serverHelloCtx, tr, serverHelloBytes); err != nil {
		cancelServerHello()
		return err
	}
	cancelServerHello()
	releaseHello()
	clientFinishedBytes, err := readV3MessageStage(hctx, tr, DefaultFinishedTimeout)
	if err != nil {
		return err
	}
	if err := consumeV3HandshakeBytes(&remainingHandshakeBytes, len(clientFinishedBytes)); err != nil {
		return err
	}
	clientFinished, err := ParseV3ClientFinished(clientFinishedBytes)
	if err != nil {
		return err
	}
	if clientFinished.Version != pending.Listener.Version || clientFinished.Suite != pending.Listener.Suite || clientFinished.HandshakeID != pending.HandshakeID {
		return ErrV3Finished
	}
	tClientFinished, err := v3VerifyClientFinished(pending, clientFinishedBytes)
	if err != nil {
		return err
	}
	serverFinishedBytes, err := buildV3ServerFinished(pending, tClientFinished)
	if err != nil {
		return err
	}
	if err := sendV3MessageStage(hctx, tr, serverFinishedBytes, DefaultFinishedTimeout); err != nil {
		return err
	}
	tServerFinished := v3Hash("ewp/v3/server-finished", tClientFinished[:], serverFinishedBytes)
	keys, err := deriveV3ClientSession(pending, tServerFinished)
	if err != nil {
		return err
	}
	finish()
	meta := Metadata{PrincipalID: pending.Principal, Destination: pending.Destination}
	if underlying != nil {
		meta.Source = underlying.RemoteAddr()
	} else if info, ok := tr.(MessageTransportInfo); ok {
		meta.Source = info.RemoteAddr()
	}
	stream, err := newServerSecureStreamV3WithRuntime(tr, keys, s.runtime)
	zeroV3SessionKeys(&keys)
	if err != nil {
		return err
	}
	switch pending.Command {
	case CommandTCP:
		// Hosts such as sing-box dispatch the connection asynchronously and
		// return from the handler immediately. Wait until the connection is
		// actually closed (or the service is shut down) before the deferred
		// carrier cleanup runs, so the handoff is not torn down underneath
		// the host. A handler that returns an error still closes the carrier
		// immediately.
		connClosed := make(chan struct{})
		conn := &streamConn{
			SecureStream: stream,
			underlying:   underlying,
			onClose:      func() { close(connClosed) },
		}
		if err := s.handler.NewConnection(appCtx, conn, meta); err != nil {
			// Tear down the stream before the carrier so the client observes
			// the rejection instead of racing the deferred carrier close.
			_ = stream.Close()
			return err
		}
		select {
		case <-connClosed:
		case <-appCtx.Done():
		}
		return nil
	case CommandUDP:
		return newV3UDPDispatcher(appCtx, stream, underlying, s.handler, meta, s.runtime).run()
	default:
		_ = stream.Close()
		return ErrCommand
	}
}
