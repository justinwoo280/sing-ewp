package ewp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MessageTransport is the message-oriented boundary below the v3 protocol.
// Implementations must preserve message boundaries and Close must interrupt a
// blocked read or write.
type MessageTransport interface {
	SendMessage([]byte) error
	ReadMessage() ([]byte, error)
	Close() error
}

// ContextMessageTransport is an optional stronger transport contract. The
// base MessageTransport methods remain the compatibility boundary, while
// these methods let carriers such as gRPC or XHTTP cancel an in-flight
// operation without relying on a transport-wide close.
type ContextMessageTransport interface {
	MessageTransport
	SendMessageContext(context.Context, []byte) error
	ReadMessageContext(context.Context) ([]byte, error)
}

// MessageTransportInfo is an optional address surface used by high-level
// net.Conn and net.PacketConn adapters when the carrier is not a net.Conn.
type MessageTransportInfo interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// MessageTransportDeadline and its directional variants are optional
// deadline surfaces for high-level adapters. Handshake cancellation still
// works through ContextMessageTransport or the mandatory Close contract.
type MessageTransportDeadline interface {
	SetDeadline(time.Time) error
}

// MessageTransportReadDeadline is an optional read-only deadline surface for
// high-level net.Conn and net.PacketConn adapters.
type MessageTransportReadDeadline interface {
	SetReadDeadline(time.Time) error
}

// MessageTransportWriteDeadline is an optional write-only deadline surface
// for high-level net.Conn and net.PacketConn adapters.
type MessageTransportWriteDeadline interface {
	SetWriteDeadline(time.Time) error
}

type SecureStream struct {
	tr     MessageTransport
	send   *FrameAEAD
	recv   *FrameAEAD
	random io.Reader

	writeMu sync.Mutex
	recvMu  sync.Mutex

	closed    atomic.Bool
	closeOnce sync.Once

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	frmIn    atomic.Uint64
	frmOut   atomic.Uint64
}

func NewClientSecureStreamV3(tr MessageTransport, keys V3SessionKeys) (*SecureStream, error) {
	return newClientSecureStreamV3WithRuntime(tr, keys, productionV3Runtime())
}

func newClientSecureStreamV3WithRuntime(tr MessageTransport, keys V3SessionKeys, runtime v3Runtime) (*SecureStream, error) {
	defer zeroV3SessionKeys(&keys)
	if tr == nil {
		return nil, errors.New("ewp/v3: nil message transport")
	}
	send, err := newFrameAEAD(keys.C2SKey, keys.C2SNonce, keys.C2SUpdateSecret, v3RecordContext{
		listener:   keys.listener,
		transcript: keys.TrafficTranscript,
		sender:     v3RoleClient,
		receiver:   v3RoleServer,
		direction:  v3DirectionC2S,
	})
	if err != nil {
		return nil, err
	}
	recv, err := newFrameAEAD(keys.S2CKey, keys.S2CNonce, keys.S2CUpdateSecret, v3RecordContext{
		listener:   keys.listener,
		transcript: keys.TrafficTranscript,
		sender:     v3RoleServer,
		receiver:   v3RoleClient,
		direction:  v3DirectionS2C,
	})
	if err != nil {
		send.wipe()
		return nil, err
	}
	return &SecureStream{tr: tr, send: send, recv: recv, random: runtime.reader()}, nil
}

func NewServerSecureStreamV3(tr MessageTransport, keys V3SessionKeys) (*SecureStream, error) {
	return newServerSecureStreamV3WithRuntime(tr, keys, productionV3Runtime())
}

func newServerSecureStreamV3WithRuntime(tr MessageTransport, keys V3SessionKeys, runtime v3Runtime) (*SecureStream, error) {
	defer zeroV3SessionKeys(&keys)
	if tr == nil {
		return nil, errors.New("ewp/v3: nil message transport")
	}
	send, err := newFrameAEAD(keys.S2CKey, keys.S2CNonce, keys.S2CUpdateSecret, v3RecordContext{
		listener:   keys.listener,
		transcript: keys.TrafficTranscript,
		sender:     v3RoleServer,
		receiver:   v3RoleClient,
		direction:  v3DirectionS2C,
	})
	if err != nil {
		return nil, err
	}
	recv, err := newFrameAEAD(keys.C2SKey, keys.C2SNonce, keys.C2SUpdateSecret, v3RecordContext{
		listener:   keys.listener,
		transcript: keys.TrafficTranscript,
		sender:     v3RoleClient,
		receiver:   v3RoleServer,
		direction:  v3DirectionC2S,
	})
	if err != nil {
		send.wipe()
		return nil, err
	}
	return &SecureStream{tr: tr, send: send, recv: recv, random: runtime.reader()}, nil
}

func (s *SecureStream) sendFrame(t FrameType, meta, payload []byte, requestedPad int) (err error) {
	if s == nil || s.closed.Load() {
		return io.ErrClosedPipe
	}
	s.writeMu.Lock()
	wipeRecv := false
	defer func() {
		s.writeMu.Unlock()
		if wipeRecv {
			s.recvMu.Lock()
			s.wipeRecvLocked()
			s.recvMu.Unlock()
		}
	}()
	if s.closed.Load() || s.send == nil {
		return io.ErrClosedPipe
	}
	padLen := selectRecordPad(meta, payload, requestedPad, int(s.frmOut.Load()), s.random)
	wire, err := encodeRecordBytesWithReader(s.send, t, meta, payload, padLen, s.random)
	if err != nil {
		return fmt.Errorf("ewp/v3: encode %s: %w", frameTypeName(t), err)
	}
	if err := s.tr.SendMessage(wire); err != nil {
		s.abortTransport()
		s.wipeSendLocked()
		wipeRecv = true
		return fmt.Errorf("ewp/v3: send record: %w", err)
	}
	s.bytesOut.Add(uint64(len(wire)))
	s.frmOut.Add(1)
	return nil
}

func selectRecordPad(meta, payload []byte, requested, phase int, random ...io.Reader) int {
	raw := recordOuterLengthSize + recordInnerHeaderSize + len(meta) + len(payload) + 16
	if requested < 0 {
		return suggestStreamPadRecord(raw, phase, random...)
	}
	if requested > MaxFramePad {
		return requested
	}
	extra := suggestStreamPadRecord(raw+requested, phase, random...)
	if extra > MaxFramePad-requested {
		extra = MaxFramePad - requested
	}
	return requested + extra
}

func (s *SecureStream) SendTCPData(payload []byte) error {
	return s.sendFrame(FrameTCPData, nil, payload, -1)
}

func (s *SecureStream) SendUDPNew(globalID [8]byte, target Address, payload []byte) error {
	if globalID == ([8]byte{}) || !hasV3Address(target) {
		return ErrV3State
	}
	meta, err := buildUDPMeta(globalID, target)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameUDPNew, meta, payload, -1)
}

func (s *SecureStream) SendUDPData(globalID [8]byte, target Address, payload []byte) error {
	if globalID == ([8]byte{}) {
		return ErrV3State
	}
	meta, err := buildUDPMeta(globalID, target)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameUDPData, meta, payload, -1)
}

func (s *SecureStream) SendUDPEnd(globalID [8]byte) error {
	if globalID == ([8]byte{}) {
		return ErrV3State
	}
	return s.sendFrame(FrameUDPEnd, globalID[:], nil, -1)
}

func (s *SecureStream) SendProbeReq(globalID [8]byte) error {
	if globalID == ([8]byte{}) {
		return ErrV3State
	}
	return s.sendFrame(FrameUDPProbeReq, globalID[:], nil, -1)
}

func (s *SecureStream) SendProbeResp(globalID [8]byte, observed Address) error {
	if globalID == ([8]byte{}) {
		return ErrV3State
	}
	meta, err := buildUDPMeta(globalID, observed)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameUDPProbeResp, meta, nil, -1)
}

func (s *SecureStream) SendPing(cookie []byte) error {
	return s.sendFrame(FramePing, nil, cookie, -1)
}

func (s *SecureStream) SendPong(cookie []byte) error {
	return s.sendFrame(FramePong, nil, cookie, -1)
}

func (s *SecureStream) SendCoverPad(padLen int) error {
	return s.sendFrame(FramePaddingOnly, nil, nil, padLen)
}

const recordRekeyLabel = "ewp/v3/key-update"

func (s *SecureStream) Rekey() (err error) {
	if s == nil || s.closed.Load() {
		return io.ErrClosedPipe
	}
	s.writeMu.Lock()
	wipeRecv := false
	defer func() {
		s.writeMu.Unlock()
		if wipeRecv {
			s.recvMu.Lock()
			s.wipeRecvLocked()
			s.recvMu.Unlock()
		}
	}()
	if s.send == nil || s.send.aead == nil {
		return io.ErrClosedPipe
	}
	priorCounter := s.send.counter
	newSecret, newKey, newPrefix, err := deriveFrameRekey(s.send)
	if err != nil {
		return err
	}
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], priorCounter)
	wire, err := encodeRecordBytesWithReader(s.send, FrameRekeyReq, nil, counterBytes[:], selectRecordPad(nil, counterBytes[:], 0, int(s.frmOut.Load()), s.random), s.random)
	if err != nil {
		zero(newSecret[:])
		zero(newKey[:])
		zero(newPrefix[:])
		return fmt.Errorf("ewp/v3: encode key update: %w", err)
	}
	if err := s.tr.SendMessage(wire); err != nil {
		zero(newSecret[:])
		zero(newKey[:])
		zero(newPrefix[:])
		s.abortTransport()
		s.wipeSendLocked()
		wipeRecv = true
		return fmt.Errorf("ewp/v3: send key update: %w", err)
	}
	s.bytesOut.Add(uint64(len(wire)))
	s.frmOut.Add(1)
	// Preserve the authenticated context and advance to the next epoch.
	next, err := newFrameAEAD(newKey, newPrefix, newSecret, s.send.context)
	if err != nil {
		zero(newSecret[:])
		zero(newKey[:])
		zero(newPrefix[:])
		s.abortTransport()
		s.wipeSendLocked()
		wipeRecv = true
		return err
	}
	next.epoch = s.send.epoch + 1
	old := s.send
	s.send = next
	old.wipe()
	zero(newSecret[:])
	zero(newKey[:])
	zero(newPrefix[:])
	return nil
}

type Event struct {
	Type     FrameType
	GlobalID [8]byte
	Address  Address
	HasAddr  bool
	Payload  []byte
}

func (s *SecureStream) Recv() (*Event, error) {
	if s == nil {
		return nil, io.ErrClosedPipe
	}
	s.recvMu.Lock()
	event, err := s.recvLocked()
	s.recvMu.Unlock()
	if err != nil {
		s.abortAndWipe()
	}
	return event, err
}

func (s *SecureStream) recvLocked() (event *Event, returnErr error) {
	for {
		if s.closed.Load() {
			return nil, io.ErrClosedPipe
		}
		wire, err := s.tr.ReadMessage()
		if err != nil {
			return nil, err
		}
		frame, consumed, err := decodeRecordBytes(wire, s.recv)
		if err != nil {
			return nil, fmt.Errorf("ewp/v3: decode record: %w", err)
		}
		if consumed != len(wire) {
			return nil, errors.New("ewp/v3: trailing bytes after record")
		}
		s.bytesIn.Add(uint64(len(wire)))
		s.frmIn.Add(1)
		if frame.Type == FrameRekeyReq {
			if len(frame.Payload) != CounterLen {
				return nil, errors.New("ewp/v3: invalid key update payload")
			}
			announced := binary.BigEndian.Uint64(frame.Payload)
			if announced == ^uint64(0) || announced+1 != s.recv.counter {
				return nil, ErrCounterMismatch
			}
			newSecret, newKey, newPrefix, err := deriveFrameRekey(s.recv)
			if err != nil {
				return nil, err
			}
			next, err := newFrameAEAD(newKey, newPrefix, newSecret, s.recv.context)
			if err != nil {
				zero(newSecret[:])
				zero(newKey[:])
				zero(newPrefix[:])
				return nil, err
			}
			next.epoch = s.recv.epoch + 1
			old := s.recv
			s.recv = next
			old.wipe()
			zero(newSecret[:])
			zero(newKey[:])
			zero(newPrefix[:])
			continue
		}

		event = &Event{Type: frame.Type, Payload: frame.Payload}
		switch frame.Type {
		case FrameUDPNew, FrameUDPData, FrameUDPProbeResp:
			gid, addr, hasAddr, err := parseUDPMeta(frame.Meta)
			if err != nil {
				return nil, err
			}
			if gid == ([8]byte{}) {
				return nil, ErrV3State
			}
			event.GlobalID, event.Address, event.HasAddr = gid, addr, hasAddr
		case FrameUDPEnd, FrameUDPProbeReq:
			if len(frame.Meta) != 8 {
				return nil, errors.New("ewp/v3: invalid UDP control metadata")
			}
			copy(event.GlobalID[:], frame.Meta)
			if event.GlobalID == ([8]byte{}) {
				return nil, ErrV3State
			}
		case FrameTCPData, FramePing, FramePong, FramePaddingOnly, FrameRekeyResp:
		default:
			return nil, ErrFrameType
		}
		return event, nil
	}
}

func (s *SecureStream) abortAndWipe() {
	s.abortTransport()
	s.writeMu.Lock()
	s.wipeSendLocked()
	s.writeMu.Unlock()
	s.recvMu.Lock()
	s.wipeRecvLocked()
	s.recvMu.Unlock()
}

func (s *SecureStream) Close() error {
	if s == nil {
		return nil
	}
	err := s.abortTransport()
	s.writeMu.Lock()
	s.wipeSendLocked()
	s.writeMu.Unlock()
	s.recvMu.Lock()
	s.wipeRecvLocked()
	s.recvMu.Unlock()
	return err
}

func (s *SecureStream) abortTransport() (err error) {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.tr != nil {
			err = s.tr.Close()
		}
	})
	return err
}

func (s *SecureStream) wipeSendLocked() {
	if s.send != nil {
		s.send.wipe()
		s.send = nil
	}
}

func (s *SecureStream) wipeRecvLocked() {
	if s.recv != nil {
		s.recv.wipe()
		s.recv = nil
	}
}

func (s *SecureStream) Stats() (bytesIn, bytesOut, framesIn, framesOut uint64) {
	return s.bytesIn.Load(), s.bytesOut.Load(), s.frmIn.Load(), s.frmOut.Load()
}

func buildUDPMeta(globalID [8]byte, target Address) ([]byte, error) {
	out := make([]byte, 8, 8+target.EncodedLen())
	copy(out, globalID[:])
	if target.IsDomain() || target.Addr.IsValid() {
		var err error
		out, err = target.Append(out)
		if err != nil {
			return nil, err
		}
	}
	if len(out) > MaxMetaLen {
		return nil, ErrMetaTooLarge
	}
	return out, nil
}

func parseUDPMeta(meta []byte) (gid [8]byte, addr Address, hasAddr bool, err error) {
	if len(meta) < 8 {
		return gid, addr, false, errors.New("ewp/v3: UDP metadata is truncated")
	}
	copy(gid[:], meta[:8])
	if len(meta) == 8 {
		return gid, addr, false, nil
	}
	addr, consumed, err := DecodeAddress(meta[8:])
	if err != nil {
		return gid, Address{}, false, err
	}
	if consumed != len(meta)-8 {
		return gid, Address{}, false, errors.New("ewp/v3: trailing UDP address")
	}
	return gid, addr, true, nil
}

func frameTypeName(t FrameType) string {
	switch t {
	case FrameTCPData:
		return "TCP_DATA"
	case FrameUDPData:
		return "UDP_DATA"
	case FrameUDPNew:
		return "UDP_NEW"
	case FrameUDPEnd:
		return "UDP_END"
	case FrameUDPProbeReq:
		return "UDP_PROBE_REQ"
	case FrameUDPProbeResp:
		return "UDP_PROBE_RESP"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameRekeyReq:
		return "REKEY_REQ"
	case FrameRekeyResp:
		return "REKEY_RESP"
	case FramePaddingOnly:
		return "PADDING_ONLY"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(t))
	}
}
