package ewp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	maxV3UDPSubSessions  = 1024
	maxV3UDPQueuePackets = 64
	maxV3UDPQueueBytes   = 1 << 20
)

var errV3UDPQueueFull = errors.New("ewp/v3: UDP sub-session queue full")

type v3UDPDispatcher struct {
	stream     *SecureStream
	underlying net.Conn
	handler    Handler
	meta       Metadata
	runtime    v3Runtime
	ctx        context.Context
	cancel     context.CancelFunc

	mu       sync.Mutex
	sessions map[[8]byte]*v3UDPPacketSession
	ended    map[[8]byte]struct{}
	wg       sync.WaitGroup
}

type v3UDPDatagram struct {
	payload []byte
	source  Address
}

// v3UDPPacketSession is a session-local net.PacketConn view. It never calls
// SecureStream.Recv; the carrier dispatcher owns the only receive loop.
type v3UDPPacketSession struct {
	dispatcher *v3UDPDispatcher
	stream     *SecureStream
	underlying net.Conn
	globalID   [8]byte
	defaultDst Address
	runtime    v3Runtime
	cancel     context.CancelFunc
	writeMu    sync.Mutex

	queueMu    sync.Mutex
	queue      chan v3UDPDatagram
	queueBytes int

	stateMu       sync.Mutex
	closed        bool
	remoteClosed  bool
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineCh    chan struct{}
	done          chan struct{}
	closeOnce     sync.Once
	closeComplete chan struct{}
	closeErr      error
}

func newV3UDPDispatcher(ctx context.Context, stream *SecureStream, underlying net.Conn, handler Handler, meta Metadata, runtime v3Runtime) *v3UDPDispatcher {
	if ctx == nil {
		ctx = context.Background()
	}
	childCtx, cancel := context.WithCancel(ctx)
	return &v3UDPDispatcher{
		stream:     stream,
		underlying: underlying,
		handler:    handler,
		meta:       meta,
		runtime:    runtime,
		ctx:        childCtx,
		cancel:     cancel,
		sessions:   make(map[[8]byte]*v3UDPPacketSession),
		ended:      make(map[[8]byte]struct{}),
	}
}

func (d *v3UDPDispatcher) run() error {
	if d == nil || d.stream == nil || d.handler == nil {
		return ErrV3State
	}
	ctx := d.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = d.stream.Close()
		case <-stopWatch:
		}
	}()
	defer close(stopWatch)
	defer d.shutdown()
	for {
		event, err := d.stream.Recv()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return err
		}
		switch event.Type {
		case FrameUDPNew:
			if err := d.open(event); err != nil {
				return err
			}
		case FrameUDPData:
			if err := d.deliver(event); err != nil {
				return err
			}
		case FrameUDPEnd:
			if err := d.end(event.GlobalID); err != nil {
				return err
			}
		case FramePing, FramePong, FramePaddingOnly,
			FrameUDPProbeReq, FrameUDPProbeResp:
			// These are carrier-level records for the current dispatcher.
			// Probe policy is deliberately left to the outer integration.
		default:
			return fmt.Errorf("ewp/v3: unexpected record type %d in UDP dispatcher", event.Type)
		}
	}
}

func (d *v3UDPDispatcher) open(event *Event) error {
	if event == nil || event.GlobalID == ([8]byte{}) || !event.HasAddr {
		return ErrV3State
	}
	if d == nil || d.ctx == nil || d.ctx.Err() != nil {
		return ErrV3State
	}
	d.mu.Lock()
	if _, exists := d.sessions[event.GlobalID]; exists {
		d.mu.Unlock()
		return ErrV3State
	}
	if _, ended := d.ended[event.GlobalID]; ended {
		d.mu.Unlock()
		return ErrV3State
	}
	if len(d.sessions) >= maxV3UDPSubSessions {
		d.mu.Unlock()
		return ErrV3State
	}
	if len(d.ended) >= maxV3UDPSubSessions*2 {
		d.mu.Unlock()
		return ErrV3State
	}
	sessionCtx, cancel := context.WithCancel(d.ctx)
	session := &v3UDPPacketSession{
		dispatcher:    d,
		stream:        d.stream,
		underlying:    d.underlying,
		globalID:      event.GlobalID,
		defaultDst:    event.Address,
		runtime:       d.runtime,
		cancel:        cancel,
		queue:         make(chan v3UDPDatagram, maxV3UDPQueuePackets),
		deadlineCh:    make(chan struct{}),
		done:          make(chan struct{}),
		closeComplete: make(chan struct{}),
	}
	d.sessions[event.GlobalID] = session
	d.mu.Unlock()

	if !session.enqueue(event) {
		_ = session.Close()
		return errV3UDPQueueFull
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer cancel()
		_ = d.handler.NewPacketConnection(sessionCtx, session, d.meta)
		_ = session.Close()
	}()
	return nil
}

func (d *v3UDPDispatcher) deliver(event *Event) error {
	if event == nil || event.GlobalID == ([8]byte{}) {
		return ErrV3State
	}
	d.mu.Lock()
	session := d.sessions[event.GlobalID]
	_, ended := d.ended[event.GlobalID]
	d.mu.Unlock()
	if session == nil {
		if ended {
			return nil
		}
		return ErrV3State
	}
	if !session.enqueue(event) {
		_ = session.Close()
	}
	return nil
}

func (d *v3UDPDispatcher) end(globalID [8]byte) error {
	if globalID == ([8]byte{}) {
		return ErrV3State
	}
	d.mu.Lock()
	session := d.sessions[globalID]
	_, ended := d.ended[globalID]
	d.mu.Unlock()
	if session == nil {
		if ended {
			return nil
		}
		return ErrV3State
	}
	session.remoteClose()
	return nil
}

func (d *v3UDPDispatcher) remove(session *v3UDPPacketSession) {
	if d == nil || session == nil {
		return
	}
	d.mu.Lock()
	if current, ok := d.sessions[session.globalID]; ok && current == session {
		delete(d.sessions, session.globalID)
		d.ended[session.globalID] = struct{}{}
	}
	d.mu.Unlock()
}

func (d *v3UDPDispatcher) shutdown() {
	if d == nil {
		return
	}
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Lock()
	sessions := make([]*v3UDPPacketSession, 0, len(d.sessions))
	for _, session := range d.sessions {
		sessions = append(sessions, session)
	}
	d.mu.Unlock()
	for _, session := range sessions {
		session.remoteClose()
	}
	if d.stream != nil {
		_ = d.stream.Close()
	}
	d.wg.Wait()
}

func (p *v3UDPPacketSession) enqueue(event *Event) bool {
	if p == nil || event == nil || event.GlobalID != p.globalID {
		return false
	}
	source := p.defaultDst
	if event.HasAddr {
		source = event.Address
	}
	if len(event.Payload) > MaxFrameSize || len(event.Payload) > maxV3UDPQueueBytes {
		return false
	}
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	if p.isClosed() || p.queueBytes+len(event.Payload) > maxV3UDPQueueBytes {
		return false
	}
	payload := append([]byte(nil), event.Payload...)
	select {
	case p.queue <- v3UDPDatagram{payload: payload, source: source}:
		p.queueBytes += len(payload)
		return true
	default:
		return false
	}
}

func (p *v3UDPPacketSession) WriteTo(payload []byte, addr net.Addr) (int, error) {
	target, err := addrToEWP(addr)
	if err != nil {
		return 0, err
	}
	return p.WriteToAddress(payload, target)
}

func (p *v3UDPPacketSession) WriteToAddress(payload []byte, target Address) (int, error) {
	if p == nil {
		return 0, ErrPacketConnClosed
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.isClosed() {
		return 0, ErrPacketConnClosed
	}
	if p.stream == nil {
		return 0, ErrPacketConnClosed
	}
	p.stateMu.Lock()
	deadline := p.writeDeadline
	p.stateMu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, v3PacketDeadlineError{}
	}
	if !hasV3Address(target) {
		target = p.defaultDst
	}
	if !hasV3Address(target) {
		return 0, ErrV3State
	}
	if err := p.sendUDPData(target, payload, deadline); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (p *v3UDPPacketSession) sendUDPData(target Address, payload []byte, deadline time.Time) error {
	if deadline.IsZero() {
		return p.stream.SendUDPData(p.globalID, target, payload)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return v3PacketDeadlineError{}
	}
	result := make(chan error, 1)
	go func() {
		result <- p.stream.SendUDPData(p.globalID, target, payload)
	}()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		// A record counter is consumed before the carrier write. A timed-out
		// write therefore aborts the carrier rather than attempting a retry.
		_ = p.stream.Close()
		<-result
		return v3PacketDeadlineError{}
	}
}

func (p *v3UDPPacketSession) ReadFrom(payload []byte) (int, net.Addr, error) {
	if p == nil {
		return 0, nil, ErrPacketConnClosed
	}
	for {
		if err := p.readClosedError(); err != nil {
			return 0, nil, err
		}
		p.stateMu.Lock()
		deadline := p.readDeadline
		if p.deadlineCh == nil {
			p.deadlineCh = make(chan struct{})
		}
		deadlineCh := p.deadlineCh
		p.stateMu.Unlock()
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, nil, v3PacketDeadlineError{}
			}
			timer = time.NewTimer(remaining)
			timerC = timer.C
		}
		select {
		case datagram := <-p.queue:
			if timer != nil {
				timer.Stop()
			}
			p.queueMu.Lock()
			p.queueBytes -= len(datagram.payload)
			if p.queueBytes < 0 {
				p.queueBytes = 0
			}
			p.queueMu.Unlock()
			if err := p.readClosedError(); err != nil {
				return 0, nil, err
			}
			return copy(payload, datagram.payload), ewpToNetAddr(datagram.source), nil
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, p.readClosedError()
		case <-deadlineCh:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timerC:
			return 0, nil, v3PacketDeadlineError{}
		}
	}
}

func (p *v3UDPPacketSession) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.markClosed(false)
		locked := p.lockWriteForClose()
		if locked {
			if err := p.sendEndBestEffort(); err != nil {
				p.closeErr = err
			}
		}
		p.writeMu.Unlock()
		close(p.closeComplete)
	})
	<-p.closeComplete
	return p.closeErr
}

func (p *v3UDPPacketSession) remoteClose() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		p.markClosed(true)
		go func() {
			p.lockWriteForClose()
			p.writeMu.Unlock()
			close(p.closeComplete)
		}()
	})
}

func (p *v3UDPPacketSession) lockWriteForClose() bool {
	acquired := make(chan struct{})
	go func() {
		p.writeMu.Lock()
		close(acquired)
	}()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-acquired:
		return true
	case <-timer.C:
		// A blocked write is a carrier-level failure. Closing the stream
		// interrupts it so session teardown cannot deadlock.
		if p.stream != nil {
			_ = p.stream.Close()
		}
		<-acquired
		return false
	}
}

func (p *v3UDPPacketSession) markClosed(remote bool) {
	p.stateMu.Lock()
	if !p.closed {
		p.closed = true
		p.remoteClosed = remote
		close(p.done)
	}
	p.stateMu.Unlock()
	if p.cancel != nil {
		p.cancel()
	}
	if p.dispatcher != nil {
		p.dispatcher.remove(p)
	}
}

func (p *v3UDPPacketSession) sendEndBestEffort() error {
	if p.stream == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- p.stream.SendUDPEnd(p.globalID)
	}()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		// A blocked write is a carrier-level failure. Closing the stream is
		// the only operation guaranteed to interrupt it.
		_ = p.stream.Close()
		return <-done
	}
}

func (p *v3UDPPacketSession) isClosed() bool {
	p.stateMu.Lock()
	closed := p.closed
	p.stateMu.Unlock()
	return closed
}

func (p *v3UDPPacketSession) readClosedError() error {
	p.stateMu.Lock()
	closed := p.closed
	remote := p.remoteClosed
	p.stateMu.Unlock()
	if !closed {
		return nil
	}
	if remote {
		return io.EOF
	}
	return ErrPacketConnClosed
}

func (p *v3UDPPacketSession) LocalAddr() net.Addr {
	if p.underlying != nil {
		return p.underlying.LocalAddr()
	}
	if p.stream != nil {
		if info, ok := p.stream.tr.(MessageTransportInfo); ok {
			return info.LocalAddr()
		}
	}
	return nil
}

func (p *v3UDPPacketSession) SetDeadline(deadline time.Time) error {
	p.stateMu.Lock()
	p.readDeadline = deadline
	p.writeDeadline = deadline
	p.notifyDeadlineChangeLocked()
	p.stateMu.Unlock()
	return nil
}

func (p *v3UDPPacketSession) SetReadDeadline(deadline time.Time) error {
	p.stateMu.Lock()
	p.readDeadline = deadline
	p.notifyDeadlineChangeLocked()
	p.stateMu.Unlock()
	return nil
}

func (p *v3UDPPacketSession) SetWriteDeadline(deadline time.Time) error {
	p.stateMu.Lock()
	p.writeDeadline = deadline
	p.notifyDeadlineChangeLocked()
	p.stateMu.Unlock()
	return nil
}

func (p *v3UDPPacketSession) notifyDeadlineChangeLocked() {
	if p.deadlineCh == nil {
		p.deadlineCh = make(chan struct{})
		return
	}
	close(p.deadlineCh)
	p.deadlineCh = make(chan struct{})
}

type v3PacketDeadlineError struct{}

func (v3PacketDeadlineError) Error() string   { return "ewp/v3: packet deadline exceeded" }
func (v3PacketDeadlineError) Timeout() bool   { return true }
func (v3PacketDeadlineError) Temporary() bool { return true }

var _ net.PacketConn = (*v3UDPPacketSession)(nil)
