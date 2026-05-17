package ewp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// MessageTransport is the narrow interface required of an outer
// transport. WS / gRPC / H3 / xhttp implementations satisfy this with
// trivial wrappers; transports MUST deliver messages atomically and
// MUST NOT split or coalesce them.
type MessageTransport interface {
	SendMessage(b []byte) error
	ReadMessage() ([]byte, error)
	Close() error
}

// SecureStream is the post-handshake bidirectional encrypted channel.
//
// One SecureStream = one outer transport connection. UDP sub-sessions
// (identified by 8-byte GlobalID) multiplex inside it.
//
// Concurrency model:
//   - Send / SendUDP / SendUDPNew / SendUDPEnd / SendProbeReq / SendProbeResp
//     are safe for concurrent calls (serialised internally by writeMu).
//   - Recv MUST be called from a single goroutine (it advances the
//     receive AEAD counter; concurrent calls would race on counter).
//   - Close is idempotent and safe from any goroutine; it interrupts
//     any in-flight Recv by closing the underlying transport.
type SecureStream struct {
	tr MessageTransport

	writeMu sync.Mutex
	send    *FrameAEAD
	recv    *FrameAEAD

	// sendBuf is a reusable scratch buffer for EncodeFrameAppend.
	// Protected by writeMu.
	sendBuf []byte

	// lastSendNs is the unix-nano timestamp of the last APPLICATION
	// send (i.e. not a cover frame). Used by the cover-traffic loop
	// to decide whether to emit.
	lastSendNs atomic.Int64

	// Cover-traffic goroutine state.
	coverStarted atomic.Bool
	coverStop    chan struct{}

	closeOnce sync.Once
	closed    atomic.Bool

	// Counters exposed for tests / metrics.
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	frmIn    atomic.Uint64
	frmOut   atomic.Uint64
}

// NewClientSecureStream wraps the post-handshake state on the client
// side. send is the c2s FrameAEAD (uses keys.C2SKey/C2SNonce); recv is
// the s2c side.
func NewClientSecureStream(tr MessageTransport, keys SessionKeys) (*SecureStream, error) {
	send, err := NewFrameAEAD(keys.C2SKey, keys.C2SNonce)
	if err != nil {
		return nil, err
	}
	recv, err := NewFrameAEAD(keys.S2CKey, keys.S2CNonce)
	if err != nil {
		return nil, err
	}
	return &SecureStream{tr: tr, send: send, recv: recv}, nil
}

// NewServerSecureStream wraps the post-handshake state on the server
// side. The send/recv directions are mirrored versus the client.
func NewServerSecureStream(tr MessageTransport, keys SessionKeys) (*SecureStream, error) {
	send, err := NewFrameAEAD(keys.S2CKey, keys.S2CNonce)
	if err != nil {
		return nil, err
	}
	recv, err := NewFrameAEAD(keys.C2SKey, keys.C2SNonce)
	if err != nil {
		return nil, err
	}
	return &SecureStream{tr: tr, send: send, recv: recv}, nil
}

// ----------------------------------------------------------------------
// Sending
// ----------------------------------------------------------------------

// sendFrame is the single chokepoint through which every outbound
// frame passes. It serialises encoding + transport SendMessage so
// the AEAD counter and the wire ordering stay consistent.
//
// padLen < 0 -> bucket-aware padding (see padding_policy.go).
// padLen >= 0 -> exact pad length requested by caller (used by tests
// and by the SendCoverPad API).
func (s *SecureStream) sendFrame(t FrameType, meta, payload []byte, padLen int) error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Determine padding policy.
	rawWire := frameHeaderSize + len(meta) + len(payload) + aeadTagLen
	if padLen < 0 {
		phaseIdx := int(s.frmOut.Load())
		padLen = suggestStreamPad(rawWire, phaseIdx)
	}

	// Reuse the per-stream send buffer; grow if needed.
	total := rawWire + padLen
	if cap(s.sendBuf) < total {
		s.sendBuf = make([]byte, 0, total)
	}
	wireBuf, err := EncodeFrameAppend(s.sendBuf[:0], s.send, t, meta, payload, padLen)
	if err != nil {
		return fmt.Errorf("ewp/v2: encode %s frame: %w", frameTypeName(t), err)
	}
	s.sendBuf = wireBuf

	if err := s.tr.SendMessage(wireBuf); err != nil {
		s.closeUnderlying()
		return fmt.Errorf("ewp/v2: transport send: %w", err)
	}
	s.bytesOut.Add(uint64(len(wireBuf)))
	s.frmOut.Add(1)
	if t != FramePaddingOnly {
		s.lastSendNs.Store(time.Now().UnixNano())
	}
	return nil
}

// reshape thresholds. Payloads larger than reshapeThreshold are split
// into chunks whose size is drawn uniformly from [reshapeMin, reshapeMax].
// This destroys the "streaming download = repeated near-MaxFrameSize
// frames" length signature.
const (
	reshapeThreshold = 8192
	reshapeMin       = 4096
	reshapeMax       = 12288
)

// SendTCPData sends a chunk of TCP payload bytes. Large payloads are
// reshaped (split with randomised chunk sizes) before each piece is
// wrapped in its own frame, then padded by the bucket policy.
func (s *SecureStream) SendTCPData(payload []byte) error {
	if len(payload) <= reshapeThreshold {
		return s.sendFrame(FrameTCPData, nil, payload, -1)
	}
	for len(payload) > 0 {
		chunk := len(payload)
		if chunk > reshapeMax {
			chunk = reshapeMin + secureRandIntn(reshapeMax-reshapeMin+1)
		}
		if chunk > len(payload) {
			chunk = len(payload)
		}
		if err := s.sendFrame(FrameTCPData, nil, payload[:chunk], -1); err != nil {
			return err
		}
		payload = payload[chunk:]
	}
	return nil
}

// SendUDPNew opens a new UDP sub-session and optionally sends an
// initial datagram. globalID is generated by the caller (typically via
// NewGlobalID).
func (s *SecureStream) SendUDPNew(globalID [8]byte, target Address, initial []byte) error {
	meta, err := buildUDPMeta(globalID, target)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameUDPNew, meta, initial, -1)
}

// SendUDPData sends a datagram on an existing sub-session.
//
// If target is the zero Address, no per-frame target is included
// (server uses the default target recorded at UDP_NEW). Otherwise the
// target is used for THIS frame only and does not change the
// sub-session default (per spec §5.2).
func (s *SecureStream) SendUDPData(globalID [8]byte, target Address, payload []byte) error {
	meta, err := buildUDPMeta(globalID, target)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameUDPData, meta, payload, -1)
}

// SendUDPEnd terminates a sub-session.
func (s *SecureStream) SendUDPEnd(globalID [8]byte) error {
	meta := make([]byte, 8)
	copy(meta, globalID[:])
	return s.sendFrame(FrameUDPEnd, meta, nil, -1)
}

// SendProbeReq asks the peer for the externally-visible mapping of a
// sub-session.
func (s *SecureStream) SendProbeReq(globalID [8]byte) error {
	meta := make([]byte, 8)
	copy(meta, globalID[:])
	return s.sendFrame(FrameUDPProbeReq, meta, nil, -1)
}

// SendProbeResp answers a probe with the observed external Address.
func (s *SecureStream) SendProbeResp(globalID [8]byte, observed Address) error {
	meta, err := buildUDPMeta(globalID, observed)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameUDPProbeResp, meta, nil, -1)
}

// SendPing sends a ping frame with the supplied cookie.
func (s *SecureStream) SendPing(cookie []byte) error {
	return s.sendFrame(FramePing, nil, cookie, -1)
}

// SendPong echoes a ping cookie.
func (s *SecureStream) SendPong(cookie []byte) error {
	return s.sendFrame(FramePong, nil, cookie, -1)
}

// SendCoverPad emits a frame that carries no application meaning, only
// random bytes for cover. padLen is clamped to the spec maximum.
//
// If padLen < 0 the bucket policy chooses a reasonable size.
func (s *SecureStream) SendCoverPad(padLen int) error {
	return s.sendFrame(FramePaddingOnly, nil, nil, padLen)
}

// CoverConfig parameterises automatic cover traffic. A zero value
// disables it. See StartCoverTraffic.
type CoverConfig struct {
	// Interval is the base tick period. A cover frame is considered
	// for emission on every tick.
	Interval time.Duration
	// IdleAfter is the minimum time the stream must have been silent
	// (no application send) before a cover frame is emitted.
	IdleAfter time.Duration
	// JitterFrac in [0,1] randomises Interval by +/- JitterFrac
	// (cryptographic). 0.5 means ticks land in [0.5*I, 1.5*I].
	JitterFrac float64
}

// DefaultCoverConfig is a starting point: emit a cover frame after
// ~500ms of application silence, with 50% jitter on the cadence.
var DefaultCoverConfig = CoverConfig{
	Interval:   500 * time.Millisecond,
	IdleAfter:  500 * time.Millisecond,
	JitterFrac: 0.5,
}

// StartCoverTraffic starts a background goroutine that periodically
// emits a FramePaddingOnly frame if no application data has been sent
// recently. The goroutine exits on SecureStream.Close.
//
// Calling StartCoverTraffic more than once is a no-op for subsequent
// calls.
func (s *SecureStream) StartCoverTraffic(cfg CoverConfig) {
	if cfg.Interval <= 0 || cfg.IdleAfter <= 0 {
		return
	}
	if !s.coverStarted.CompareAndSwap(false, true) {
		return
	}
	s.coverStop = make(chan struct{})
	go s.coverLoop(cfg)
}

func (s *SecureStream) coverLoop(cfg CoverConfig) {
	nextDelay := func() time.Duration {
		if cfg.JitterFrac <= 0 {
			return cfg.Interval
		}
		spanNs := int(float64(cfg.Interval) * cfg.JitterFrac * 2)
		if spanNs < 1 {
			return cfg.Interval
		}
		offset := time.Duration(secureRandIntn(spanNs)) - time.Duration(spanNs/2)
		return cfg.Interval + offset
	}
	t := time.NewTimer(nextDelay())
	defer t.Stop()
	for {
		select {
		case <-s.coverStop:
			return
		case <-t.C:
		}
		if s.closed.Load() {
			return
		}
		last := time.Unix(0, s.lastSendNs.Load())
		if time.Since(last) >= cfg.IdleAfter {
			_ = s.SendCoverPad(-1)
		}
		t.Reset(nextDelay())
	}
}

// ----------------------------------------------------------------------
// Receiving
// ----------------------------------------------------------------------

// Event is one decoded inbound frame plus its parsed meta.
type Event struct {
	Type     FrameType
	GlobalID [8]byte // valid for UDP_NEW / UDP_DATA / UDP_END / UDP_PROBE_*
	Address  Address // valid for UDP_NEW / UDP_DATA (real remote) / UDP_PROBE_RESP (observed)
	HasAddr  bool
	Payload  []byte
}

// Recv reads, decrypts and parses one frame. The returned Event's
// Payload slice is owned by the caller.
//
// On any error other than io.EOF the SecureStream is left in a
// terminal state and subsequent Recv calls will return io.ErrClosedPipe.
func (s *SecureStream) Recv() (*Event, error) {
	if s.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	wire, err := s.tr.ReadMessage()
	if err != nil {
		s.closeUnderlying()
		return nil, err
	}
	df, err := DecodeFrame(bytes.NewReader(wire), s.recv)
	if err != nil {
		s.closeUnderlying()
		return nil, fmt.Errorf("ewp/v2: decode frame: %w", err)
	}
	s.bytesIn.Add(uint64(len(wire)))
	s.frmIn.Add(1)

	ev := &Event{Type: df.Type, Payload: df.Payload}
	switch df.Type {
	case FrameUDPNew, FrameUDPData, FrameUDPProbeResp:
		gid, addr, hasAddr, err := parseUDPMeta(df.Meta)
		if err != nil {
			s.closeUnderlying()
			return nil, fmt.Errorf("ewp/v2: parse UDP meta: %w", err)
		}
		ev.GlobalID = gid
		ev.Address = addr
		ev.HasAddr = hasAddr
	case FrameUDPEnd, FrameUDPProbeReq:
		if len(df.Meta) < 8 {
			s.closeUnderlying()
			return nil, errors.New("ewp/v2: UDP_END/PROBE_REQ meta too short")
		}
		copy(ev.GlobalID[:], df.Meta[:8])
	case FrameTCPData, FramePing, FramePong, FramePaddingOnly,
		FrameRekeyReq, FrameRekeyResp:
		// no meta parsing required
	default:
		// FrameType.Valid() in DecodeFrame should already reject this.
		s.closeUnderlying()
		return nil, ErrFrameType
	}
	return ev, nil
}

// ----------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------

// Close terminates the SecureStream and closes the underlying transport.
// Idempotent.
func (s *SecureStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.coverStop != nil {
			close(s.coverStop)
		}
		err = s.tr.Close()
	})
	return err
}

func (s *SecureStream) closeUnderlying() {
	_ = s.Close()
}

// Stats returns lightweight observability counters.
func (s *SecureStream) Stats() (bytesIn, bytesOut, framesIn, framesOut uint64) {
	return s.bytesIn.Load(), s.bytesOut.Load(), s.frmIn.Load(), s.frmOut.Load()
}

// ----------------------------------------------------------------------
// Meta helpers
// ----------------------------------------------------------------------

// buildUDPMeta constructs an 8-byte GlobalID plus optional Address.
//
// A zero-valued Address (no domain, no valid Addr) yields "globalID
// only" — used for UDP_DATA frames that want the sub-session default
// target.
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

// parseUDPMeta inverts buildUDPMeta. hasAddr reports whether an
// Address was present after the GlobalID.
func parseUDPMeta(meta []byte) (gid [8]byte, addr Address, hasAddr bool, err error) {
	if len(meta) < 8 {
		err = errors.New("ewp/v2: UDP meta too short")
		return
	}
	copy(gid[:], meta[:8])
	if len(meta) == 8 {
		return
	}
	a, _, derr := DecodeAddress(meta[8:])
	if derr != nil {
		err = derr
		return
	}
	addr = a
	hasAddr = true
	return
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
