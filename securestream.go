package ewp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// rekeyHKDFExpand fills out using HKDF-Expand under prk and the given
// info. Panics on the (cryptographically impossible) short-read case
// because the byte budget here is fixed and well below SHA-256's
// output limit.
func rekeyHKDFExpand(prk, info, out []byte) {
	r := hkdf.Expand(sha256.New, prk, info)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("ewp/v2: rekey HKDF: " + err.Error())
	}
}

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
//   - Recv calls are serialized internally; callers should still use one
//     reader for predictable application ordering.
//   - Close is idempotent and safe from any goroutine; it interrupts
//     any in-flight Recv by closing the underlying transport.
type SecureStream struct {
	tr MessageTransport

	// version selects the record codec and rekey domain. The zero value keeps
	// legacy streams on the existing clear-header codec for compatibility.
	version protocolVersion

	writeMu sync.Mutex
	recvMu  sync.Mutex
	send    *FrameAEAD
	recv    *FrameAEAD

	// scheme is the per-connection opening-phase refragmentation plan for
	// TCP data frames (opening_scheme.go). nil for legacy-record streams
	// and for streams constructed directly in tests; only the v2.2 opaque
	// record constructors install one. Consumed positions are send-side
	// only, guarded by writeMu.
	scheme *openingScheme

	// ticketStore/ticketKey (client side, v2.3.1): when ticketStore is
	// non-nil, FrameTicket events are captured into it under ticketKey by
	// the application read loops (streamConn.Read, packetConn.ReadFrom).
	ticketStore V23TicketStore
	ticketKey   string

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
	if keys.version == protocolVersionV22 {
		return nil, ErrProtocolVersion
	}
	return newClientSecureStream(tr, keys, protocolVersionLegacy)
}

// NewClientSecureStreamV22 builds an opaque-record v2.2 stream. Its keys must
// come from the v2.2 handshake/session derivation; this constructor never
// attempts the v2.1 frame codec as a fallback.
func NewClientSecureStreamV22(tr MessageTransport, keys SessionKeys) (*SecureStream, error) {
	if keys.version != protocolVersionV22 {
		return nil, ErrProtocolVersion
	}
	return newClientSecureStream(tr, keys, protocolVersionV22)
}

func newClientSecureStream(tr MessageTransport, keys SessionKeys, version protocolVersion) (*SecureStream, error) {
	send, err := NewFrameAEAD(keys.C2SKey, keys.C2SNonce)
	if err != nil {
		return nil, err
	}
	recv, err := NewFrameAEAD(keys.S2CKey, keys.S2CNonce)
	if err != nil {
		return nil, err
	}
	return &SecureStream{tr: tr, version: version, send: send, recv: recv, scheme: schemeForVersion(version)}, nil
}

// NewServerSecureStream wraps the post-handshake state on the server
// side. The send/recv directions are mirrored versus the client.
func NewServerSecureStream(tr MessageTransport, keys SessionKeys) (*SecureStream, error) {
	if keys.version == protocolVersionV22 {
		return nil, ErrProtocolVersion
	}
	return newServerSecureStream(tr, keys, protocolVersionLegacy)
}

// NewServerSecureStreamV22 builds an opaque-record v2.2 stream. Its keys must
// come from the v2.2 handshake/session derivation; this constructor never
// attempts the v2.1 frame codec as a fallback.
func NewServerSecureStreamV22(tr MessageTransport, keys SessionKeys) (*SecureStream, error) {
	if keys.version != protocolVersionV22 {
		return nil, ErrProtocolVersion
	}
	return newServerSecureStream(tr, keys, protocolVersionV22)
}

func newServerSecureStream(tr MessageTransport, keys SessionKeys, version protocolVersion) (*SecureStream, error) {
	send, err := NewFrameAEAD(keys.S2CKey, keys.S2CNonce)
	if err != nil {
		return nil, err
	}
	recv, err := NewFrameAEAD(keys.C2SKey, keys.C2SNonce)
	if err != nil {
		return nil, err
	}
	return &SecureStream{tr: tr, version: version, send: send, recv: recv, scheme: schemeForVersion(version)}, nil
}

// schemeForVersion installs an opening-phase refragmentation scheme on
// opaque-record (v2.2/v2.3) streams only. Legacy streams keep their
// historical padding behaviour.
func schemeForVersion(version protocolVersion) *openingScheme {
	if version == protocolVersionV22 {
		return newOpeningScheme()
	}
	return nil
}

// ----------------------------------------------------------------------
// Sending
// ----------------------------------------------------------------------

// sendFrame is the single chokepoint through which every outbound
// frame passes. It serialises EncodeFrame + transport SendMessage so
// the AEAD counter and the wire ordering stay consistent.
//
// padLen < 0 -> a bucket-based pad length is chosen automatically.
// The chosen pad lifts the wire frame size onto the next entry of a
// fixed TLS-record-shaped ladder, with a random bucket-up jump (so
// the payload-to-wire mapping is non-monotonic) and a small jitter
// inside each bucket (so the wire-size histogram is not a discrete
// set of spikes). See padding_policy.go.
func (s *SecureStream) sendFrame(t FrameType, meta, payload []byte, padLen int) (err error) {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() || s.send == nil {
		return io.ErrClosedPipe
	}
	return s.sendFrameLocked(t, meta, payload, padLen, false)
}

// sendFrameLocked encodes and sends one frame. The caller must hold writeMu
// and have verified the stream is open. When exactPad is false the pad length
// is chosen by the bucket policy (selectRecordPad); when true, padLen is used
// verbatim (opening-phase refragmentation, which computes exact pads itself).
// On transport-send failure the stream is aborted and both directions wiped,
// matching the historical sendFrame behaviour.
func (s *SecureStream) sendFrameLocked(t FrameType, meta, payload []byte, padLen int, exactPad bool) error {
	if !exactPad {
		padLen = s.selectRecordPad(meta, payload, padLen)
	}

	var buf bytes.Buffer
	buf.Grow(frameHeaderSize + len(meta) + len(payload) + 16 + 2 + padLen)
	if err := s.encodeRecord(&buf, t, meta, payload, padLen); err != nil {
		return fmt.Errorf("ewp/v2: encode %s frame: %w", frameTypeName(t), err)
	}
	wire := buf.Bytes()
	if err := s.tr.SendMessage(wire); err != nil {
		s.abortTransport()
		s.wipeSendLocked()
		s.recvMu.Lock()
		s.wipeRecvLocked()
		s.recvMu.Unlock()
		return fmt.Errorf("ewp/v2: transport send: %w", err)
	}
	s.bytesOut.Add(uint64(len(wire)))
	s.frmOut.Add(1)
	return nil
}

// sendTCPRefragmented sends payload as a sequence of records whose WIRE sizes
// exactly match the per-connection opening scheme (see opening_scheme.go):
// oversized writes are split across scheme-sized records and undersized
// writes are padded up to the scheme target. This hides the size of the
// opening application writes (typically an inner handshake) far more strongly
// than payload-relative bucket padding can, because a large first write no
// longer maps to a recognisably large frame.
//
// "c"-semantics (AnyTLS): refragmentation stops as soon as the application's
// bytes are on the wire — no padding-only records are invented to complete
// the scheme. If the payload outlives the scheme, the remainder is sent
// through the normal steady-state bucket policy.
//
// The whole sequence is emitted under a single writeMu hold so concurrent
// senders (cover frames, ping, another Write) cannot interleave into the
// middle of the scheme.
func (s *SecureStream) sendTCPRefragmented(payload []byte) error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() || s.send == nil {
		return io.ErrClosedPipe
	}

	p := payload
	for s.scheme.active() {
		if len(p) == 0 && !s.scheme.forceCurrent() {
			break // "c" position: stop as soon as the payload is sent
		}
		target, _ := s.scheme.next()
		if len(p) == 0 {
			// Forced position with no payload left: complete the opening
			// silhouette with a pure chaff record at the exact target size,
			// so frame count does not leak the write size.
			pad := target - v22RecordOverhead
			if pad > MaxFramePad {
				pad = MaxFramePad
			}
			if pad < 0 {
				break
			}
			if err := s.sendFrameLocked(FramePaddingOnly, nil, nil, pad, true); err != nil {
				return err
			}
			continue
		}
		maxChunk := target - v22RecordOverhead
		if maxChunk < 1 {
			maxChunk = 1
		}
		chunk := len(p)
		if chunk > maxChunk {
			chunk = maxChunk
		}
		pad := target - (chunk + v22RecordOverhead)
		if pad > MaxFramePad {
			// Payload ran out with the scheme target still far away.
			// Clamp instead of emitting scheme-completing chaff (this can
			// only happen on a "c" position, since forced positions are
			// small enough to be reached with chaff).
			pad = MaxFramePad
		}
		if pad < 0 {
			pad = 0
		}
		if err := s.sendFrameLocked(FrameTCPData, nil, p[:chunk], pad, true); err != nil {
			return err
		}
		p = p[chunk:]
	}
	// Scheme exhausted (or never active for this frame): steady-state path,
	// chunked exactly like the streamConn caller does.
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxFrameSize-256 {
			chunk = chunk[:MaxFrameSize-256]
		}
		if err := s.sendFrameLocked(FrameTCPData, nil, chunk, -1, false); err != nil {
			return err
		}
		p = p[len(chunk):]
	}
	return nil
}

// wipeSendLocked and wipeRecvLocked clear the frame contexts while their
// respective mutex is held.
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

func (s *SecureStream) usesV22Records() bool {
	return s.version == protocolVersionV22
}

func (s *SecureStream) recordRawWireLen(meta, payload []byte) int {
	if s.usesV22Records() {
		return v22OuterLengthSize + v22InnerHeaderSize + len(meta) + len(payload) + chacha20poly1305.Overhead
	}
	return frameHeaderSize + len(meta) + len(payload) + chacha20poly1305.Overhead
}

func (s *SecureStream) selectRecordPad(meta, payload []byte, requested int) int {
	rawWireLen := s.recordRawWireLen(meta, payload)
	phaseIdx := int(s.frmOut.Load())
	if !s.usesV22Records() {
		if requested < 0 {
			return suggestStreamPad(rawWireLen, phaseIdx)
		}
		return requested
	}
	if requested < 0 {
		return suggestStreamPadV22(rawWireLen, phaseIdx)
	}
	if requested > MaxFramePad {
		return requested
	}
	// Explicit cover padding is a minimum. Add bucket padding so its visible
	// record length follows the same v2.2 distribution as application frames.
	extra := suggestStreamPadV22(rawWireLen+requested, phaseIdx)
	if extra > MaxFramePad-requested {
		extra = MaxFramePad - requested
	}
	return requested + extra
}

func (s *SecureStream) encodeRecord(w io.Writer, t FrameType, meta, payload []byte, padLen int) error {
	if s.usesV22Records() {
		return encodeFrameV22WithPad(w, s.send, t, meta, payload, padLen)
	}
	return EncodeFrame(w, s.send, t, meta, payload, padLen)
}

func (s *SecureStream) decodeRecord(r io.Reader) (*DecodedFrame, error) {
	if s.usesV22Records() {
		return DecodeFrameV22(r, s.recv)
	}
	return DecodeFrame(r, s.recv)
}

// SendTCPData sends a chunk of TCP payload bytes. On opaque-record
// (v2.2/v2.3) streams with an active opening scheme, the chunk is
// refragmented to exact scheme wire sizes; otherwise it is sent as a
// single bucket-padded frame.
func (s *SecureStream) SendTCPData(payload []byte) error {
	if len(payload) > 0 && s.usesV22Records() && s.scheme.active() {
		return s.sendTCPRefragmented(payload)
	}
	return s.sendFrame(FrameTCPData, nil, payload, -1)
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
func (s *SecureStream) SendCoverPad(padLen int) error {
	return s.sendFrame(FramePaddingOnly, nil, nil, padLen)
}

// SendTicket emits a v2.3.1 resumption ticket on the data plane. Servers
// call this right after a successful handshake for clients that set the
// ClientInit resumption capability flag; the payload is opaque to the
// record layer.
func (s *SecureStream) SendTicket(ticket []byte) error {
	if len(ticket) == 0 || len(ticket) > V23TicketMaxLen {
		return ErrFrameTooLarge
	}
	return s.sendFrame(FrameTicket, nil, ticket, -1)
}

// captureTicket stores a FrameTicket event's payload into the client-side
// ticket store, if one is installed. Called from the application read
// loops; unknown/empty payloads are ignored.
func (s *SecureStream) captureTicket(ev *Event) {
	if s.ticketStore == nil || s.ticketKey == "" || ev == nil {
		return
	}
	if ev.Type != FrameTicket || len(ev.Payload) == 0 {
		return
	}
	s.ticketStore.Put(s.ticketKey, ev.Payload)
}

// ----------------------------------------------------------------------
// Rekey evolves a fresh per-direction key from the current key plus the
// running counter. It provides backward secrecy for prior epochs: an attacker
// who later compromises the new key cannot derive pre-rekey keys from the
// one-way HKDF chain. It does not provide post-compromise recovery because it
// introduces no fresh shared entropy.
//
// Wire protocol:
//
//	Sender: emit FrameRekeyReq under the OLD send AEAD, then atomically
//	        swap in a NEW send AEAD (key' = HKDF(key, label, counter))
//	        and reset counter=0.
//	Recv:   on FrameRekeyReq, swap the recv AEAD in the same way and
//	        DO NOT surface the frame to the application.
//
// The label includes a fixed string and the pre-rekey counter so the
// derived key is bound to the position in the byte stream where the
// rotation happened; an off-path attacker cannot precompute keys
// without observing the rotation point.
//
// Rekey is single-direction: callers issuing concurrent Rekeys on the
// same direction is a programming error (it is rate-limited by
// writeMu so concurrency is technically safe but the resulting epoch
// drift would be visible only as opaque ErrAEADOpen errors). For
// production use call Rekey at most once per N bytes/frames per
// direction.
// ----------------------------------------------------------------------

// rekeyLabel is the HKDF info string for per-direction key rotation.
// Includes the protocol/version banner so a future major bump can use
// a different label without aliasing.
const rekeyLabel = "ewp/v2 rekey direction"

// Rekey rotates the per-direction send key and emits a FrameRekeyReq
// announcing the rotation to the peer.
//
// After Rekey returns successfully, every subsequent send frame uses
// the new key and the old key material is wiped on a best-effort basis. Call
// Rekey before the current frame counter is exhausted.
func (s *SecureStream) Rekey() (err error) {
	if s.closed.Load() {
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

	preCounter := s.send.counter
	preKey := s.send.key
	prePrefix := s.send.prefix

	// Derive new key + nonce-prefix from (oldKey, label, counter).
	newKey, newPrefix := s.deriveRekey(preKey, prePrefix, preCounter)

	// Encode and send the rekey announce under the OLD AEAD. The
	// payload carries the pre-rekey counter so a recv side that
	// somehow lost a frame can detect the desync (it will compare
	// against its own next-expected counter). Nothing in the payload
	// is secret; the AEAD provides authenticity.
	var counterBE [8]byte
	for i := 7; i >= 0; i-- {
		counterBE[i] = byte(preCounter)
		preCounter >>= 8
	}
	var buf bytes.Buffer
	padLen := s.selectRecordPad(nil, counterBE[:], 0)
	if err := s.encodeRecord(&buf, FrameRekeyReq, nil, counterBE[:], padLen); err != nil {
		return fmt.Errorf("ewp/v2: encode rekey: %w", err)
	}
	if err := s.tr.SendMessage(buf.Bytes()); err != nil {
		s.abortTransport()
		s.wipeSendLocked()
		zero(preKey[:])
		zero(prePrefix[:])
		zero(newKey[:])
		zero(newPrefix[:])
		wipeRecv = true
		return fmt.Errorf("ewp/v2: transport send rekey: %w", err)
	}
	s.bytesOut.Add(uint64(buf.Len()))
	s.frmOut.Add(1)

	// Swap in the new AEAD. Counter resets to 0 under the new key.
	newAEAD, err := NewFrameAEAD(newKey, newPrefix)
	if err != nil {
		s.abortTransport()
		s.wipeSendLocked()
		zero(preKey[:])
		zero(prePrefix[:])
		zero(newKey[:])
		zero(newPrefix[:])
		wipeRecv = true
		return fmt.Errorf("ewp/v2: build rekeyed AEAD: %w", err)
	}
	oldAEAD := s.send
	s.send = newAEAD
	oldAEAD.wipe()
	zero(preKey[:])
	zero(prePrefix[:])
	zero(newKey[:])
	zero(newPrefix[:])
	return nil
}

// Previous and current send keys are intentionally not retained or exposed.

// deriveRekey computes the next-epoch (key, prefix) from the current
// epoch using HKDF-Expand-only (no salt is required because key is
// already a high-entropy uniform secret).
//
// The label embeds the prior counter so an attacker who later learns
// the new key cannot replay a key-rotation event from a different byte
// offset.
func deriveRekey(
	prevKey [AEADKeyLen]byte,
	prevPrefix [NoncePrefixLen]byte,
	priorCounter uint64,
) ([AEADKeyLen]byte, [NoncePrefixLen]byte) {
	return deriveRekeyWithLabel(prevKey, prevPrefix, priorCounter, rekeyLabel)
}

func (s *SecureStream) deriveRekey(
	prevKey [AEADKeyLen]byte,
	prevPrefix [NoncePrefixLen]byte,
	priorCounter uint64,
) ([AEADKeyLen]byte, [NoncePrefixLen]byte) {
	return deriveRekeyWithLabel(prevKey, prevPrefix, priorCounter, suiteForVersion(s.version).rekeyLabel)
}

func deriveRekeyWithLabel(
	prevKey [AEADKeyLen]byte,
	prevPrefix [NoncePrefixLen]byte,
	priorCounter uint64,
	label string,
) ([AEADKeyLen]byte, [NoncePrefixLen]byte) {
	// Use HKDF-Expand directly: PRK = prevKey, info = label || counter.
	info := make([]byte, 0, len(label)+8)
	info = append(info, []byte(label)...)
	for i := 7; i >= 0; i-- {
		info = append(info, byte(priorCounter>>(uint(i)*8)))
	}
	out := make([]byte, AEADKeyLen+NoncePrefixLen)
	rekeyHKDFExpand(prevKey[:], info, out)
	var k [AEADKeyLen]byte
	var p [NoncePrefixLen]byte
	copy(k[:], out[:AEADKeyLen])
	copy(p[:], out[AEADKeyLen:])
	return k, p
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
//
// Recv transparently consumes FrameRekeyReq frames: on receipt the
// recv-direction AEAD is rotated to its next epoch and Recv loops to
// read the next "real" frame. Application code therefore never
// observes a rekey event.
func (s *SecureStream) Recv() (event *Event, returnErr error) {
	s.recvMu.Lock()
	defer func() {
		if returnErr != nil {
			s.abortTransport()
			s.wipeRecvLocked()
		}
		s.recvMu.Unlock()
		if returnErr != nil {
			s.writeMu.Lock()
			s.wipeSendLocked()
			s.writeMu.Unlock()
		}
	}()
	for {
		if s.closed.Load() {
			returnErr = io.ErrClosedPipe
			return nil, returnErr
		}
		wire, err := s.tr.ReadMessage()
		if err != nil {
			returnErr = err
			return nil, returnErr
		}
		reader := bytes.NewReader(wire)
		df, err := s.decodeRecord(reader)
		if err != nil {
			returnErr = fmt.Errorf("ewp/v2: decode frame: %w", err)
			return nil, returnErr
		}
		if reader.Len() != 0 {
			returnErr = errors.New("ewp/v2: trailing bytes after frame")
			return nil, returnErr
		}
		s.bytesIn.Add(uint64(len(wire)))
		s.frmIn.Add(1)

		// Handle protocol-internal frames before parsing application
		// metadata. FrameRekeyReq triggers a recv-side AEAD swap and
		// is hidden from the caller. Note that DecodeFrame has
		// already advanced s.recv.counter for the rekey frame itself
		// (consumed under the OLD AEAD); we then build the NEW AEAD
		// from the OLD key + the counter that DecodeFrame just
		// processed (= the value the wire payload announces, +1
		// pre-advance is fine because deriveRekey takes the prior
		// counter as supplied).
		if df.Type == FrameRekeyReq {
			// Sanity: payload MUST be exactly 8 bytes (the announced
			// pre-rekey counter). Anything else is a wire-format
			// violation.
			if len(df.Payload) != 8 {
				returnErr = fmt.Errorf("ewp/v2: rekey payload len %d, want 8", len(df.Payload))
				return nil, returnErr
			}
			announced := binary.BigEndian.Uint64(df.Payload)
			if announced == ^uint64(0) || announced+1 != s.recv.counter {
				returnErr = ErrCounterMismatch
				return nil, returnErr
			}
			oldKey := s.recv.key
			oldPrefix := s.recv.prefix
			newKey, newPrefix := s.deriveRekey(oldKey, oldPrefix, announced)
			newAEAD, err := NewFrameAEAD(newKey, newPrefix)
			if err != nil {
				returnErr = fmt.Errorf("ewp/v2: build rekeyed recv AEAD: %w", err)
				return nil, returnErr
			}
			oldAEAD := s.recv
			// Swap; subsequent frames decrypt under newAEAD with
			// counter=0.
			s.recv = newAEAD
			oldAEAD.wipe()
			zero(oldKey[:])
			zero(oldPrefix[:])
			zero(newKey[:])
			zero(newPrefix[:])
			continue // read the next real frame
		}

		ev := &Event{Type: df.Type, Payload: df.Payload}
		switch df.Type {
		case FrameUDPNew, FrameUDPData, FrameUDPProbeResp:
			gid, addr, hasAddr, err := parseUDPMeta(df.Meta)
			if err != nil {
				returnErr = fmt.Errorf("ewp/v2: parse UDP meta: %w", err)
				return nil, returnErr
			}
			ev.GlobalID = gid
			ev.Address = addr
			ev.HasAddr = hasAddr
		case FrameUDPEnd, FrameUDPProbeReq:
			if len(df.Meta) != 8 {
				returnErr = errors.New("ewp/v2: UDP_END/PROBE_REQ meta length must be 8")
				return nil, returnErr
			}
			copy(ev.GlobalID[:], df.Meta[:8])
		case FrameTCPData, FramePing, FramePong, FramePaddingOnly,
			FrameRekeyResp, FrameTicket:
			// no meta parsing required
		default:
			// FrameType.Valid() in DecodeFrame should already reject this.
			returnErr = ErrFrameType
			return nil, returnErr
		}
		return ev, nil
	}
}

// ----------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------

// Close terminates the SecureStream and closes the underlying transport.
// Idempotent.
func (s *SecureStream) Close() error {
	err := s.abortTransport()
	s.writeMu.Lock()
	s.wipeSendLocked()
	s.writeMu.Unlock()
	s.recvMu.Lock()
	s.wipeRecvLocked()
	s.recvMu.Unlock()
	return err
}

func (s *SecureStream) abortTransport() error {
	var err error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		err = s.tr.Close()
	})
	return err
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
	a, consumed, derr := DecodeAddress(meta[8:])
	if derr != nil {
		err = derr
		return
	}
	if consumed != len(meta)-8 {
		err = errors.New("ewp/v2: trailing bytes after UDP address")
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
	case FrameTicket:
		return "TICKET"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(t))
	}
}
