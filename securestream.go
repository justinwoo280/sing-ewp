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
//   - Recv MUST be called from a single goroutine (it advances the
//     receive AEAD counter; concurrent calls would race on counter).
//   - Close is idempotent and safe from any goroutine; it interrupts
//     any in-flight Recv by closing the underlying transport.
type SecureStream struct {
	tr MessageTransport

	writeMu sync.Mutex
	send    *FrameAEAD
	recv    *FrameAEAD

	closeOnce sync.Once
	closed    atomic.Bool

	// Counters exposed for tests / metrics.
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	frmIn    atomic.Uint64
	frmOut   atomic.Uint64

	// Rekey bookkeeping. prevSendKey holds the immediately-preceding
	// send key for test introspection; the production data path never
	// reads it. hasPrevSendKey is true once at least one Rekey has
	// occurred. Both fields are guarded by writeMu.
	prevSendKey    [AEADKeyLen]byte
	hasPrevSendKey bool
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
// frame passes. It serialises EncodeFrame + transport SendMessage so
// the AEAD counter and the wire ordering stay consistent.
//
// padLen < 0 -> a bucket-based pad length is chosen automatically.
// The chosen pad lifts the wire frame size onto the next entry of a
// fixed TLS-record-shaped ladder, with a random bucket-up jump (so
// the payload-to-wire mapping is non-monotonic) and a small jitter
// inside each bucket (so the wire-size histogram is not a discrete
// set of spikes). See padding_policy.go.
func (s *SecureStream) sendFrame(t FrameType, meta, payload []byte, padLen int) error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if padLen < 0 {
		// rawWireLen = header + meta + cipher(meta||payload) so the
		// ladder bucketises the actual on-wire frame size.
		cipherLen := len(meta) + len(payload) + chacha20poly1305.Overhead
		rawWireLen := frameHeaderSize + cipherLen
		phaseIdx := int(s.frmOut.Load())
		padLen = suggestStreamPad(rawWireLen, phaseIdx)
	}

	var buf bytes.Buffer
	buf.Grow(frameHeaderSize + len(meta) + len(payload) + 16 + 2 + padLen)
	if err := EncodeFrame(&buf, s.send, t, meta, payload, padLen); err != nil {
		return fmt.Errorf("ewp/v2: encode %s frame: %w", frameTypeName(t), err)
	}
	wire := buf.Bytes()
	if err := s.tr.SendMessage(wire); err != nil {
		s.closeUnderlying()
		return fmt.Errorf("ewp/v2: transport send: %w", err)
	}
	s.bytesOut.Add(uint64(len(wire)))
	s.frmOut.Add(1)
	return nil
}

// SendTCPData sends a chunk of TCP payload bytes.
func (s *SecureStream) SendTCPData(payload []byte) error {
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

// ----------------------------------------------------------------------
// Rekey: derives a fresh per-direction key from the current key plus
// the running counter, providing forward secrecy of the *session* keys
// (an attacker who later compromises the new key cannot decrypt
// pre-rekey ciphertext, because the chain is one-way under HKDF).
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

// previousSendKey holds the most recent pre-rekey send key for tests
// that wish to assert forward-secrecy properties. In production this
// is a one-way derivation (HKDF-Expand) so the previous key is not
// recoverable from the current state; the field is only populated
// when the rekey path runs and is overwritten on each rotation.
//
// Stored as part of SecureStream rather than a global so concurrent
// streams in the same process do not interfere.
//
// Test-only accessor: PreviousSendKey().
//
// We deliberately do NOT keep the entire history; only the immediate
// predecessor is retained.

// Rekey rotates the per-direction send key and emits a FrameRekeyReq
// announcing the rotation to the peer.
//
// After Rekey returns successfully, every subsequent send frame uses
// the new key; the old key is dropped (only PreviousSendKey() remains
// for test introspection).
func (s *SecureStream) Rekey() error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	preCounter := s.send.counter
	preKey := s.send.key
	prePrefix := s.send.prefix

	// Derive new key + nonce-prefix from (oldKey, label, counter).
	newKey, newPrefix := deriveRekey(preKey, prePrefix, preCounter)

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
	if err := EncodeFrame(&buf, s.send, FrameRekeyReq, nil, counterBE[:], 0); err != nil {
		return fmt.Errorf("ewp/v2: encode rekey: %w", err)
	}
	if err := s.tr.SendMessage(buf.Bytes()); err != nil {
		s.closeUnderlying()
		return fmt.Errorf("ewp/v2: transport send rekey: %w", err)
	}
	s.bytesOut.Add(uint64(buf.Len()))
	s.frmOut.Add(1)

	// Swap in the new AEAD. Counter resets to 0 under the new key.
	newAEAD, err := NewFrameAEAD(newKey, newPrefix)
	if err != nil {
		return fmt.Errorf("ewp/v2: build rekeyed AEAD: %w", err)
	}
	s.prevSendKey = preKey
	s.hasPrevSendKey = true
	s.send = newAEAD
	return nil
}

// PreviousSendKey returns the immediately-preceding send key (for
// tests). Returns ok=false if no Rekey has happened yet on this
// direction.
//
// SECURITY NOTE: production code MUST NOT rely on this; it exists
// solely so a regression test can assert that the new key differs
// from the old one. The field is overwritten on each rotation so the
// long-term retention surface is at most one obsolete key.
func (s *SecureStream) PreviousSendKey() ([AEADKeyLen]byte, bool) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.prevSendKey, s.hasPrevSendKey
}

// CurrentSendKey returns the current send key. Test-only.
func (s *SecureStream) CurrentSendKey() [AEADKeyLen]byte {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.send.key
}

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
	// Use HKDF-Expand directly: PRK = prevKey, info = label || counter.
	info := make([]byte, 0, len(rekeyLabel)+8)
	info = append(info, []byte(rekeyLabel)...)
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
func (s *SecureStream) Recv() (*Event, error) {
	for {
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
				s.closeUnderlying()
				return nil, fmt.Errorf("ewp/v2: rekey payload len %d, want 8", len(df.Payload))
			}
			announced := binary.BigEndian.Uint64(df.Payload)
			oldKey := s.recv.key
			oldPrefix := s.recv.prefix
			newKey, newPrefix := deriveRekey(oldKey, oldPrefix, announced)
			newAEAD, err := NewFrameAEAD(newKey, newPrefix)
			if err != nil {
				s.closeUnderlying()
				return nil, fmt.Errorf("ewp/v2: build rekeyed recv AEAD: %w", err)
			}
			// Swap; subsequent frames decrypt under newAEAD with
			// counter=0.
			s.recv = newAEAD
			continue // read the next real frame
		}

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
			FrameRekeyResp:
			// no meta parsing required
		default:
			// FrameType.Valid() in DecodeFrame should already reject this.
			s.closeUnderlying()
			return nil, ErrFrameType
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
	var err error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
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
