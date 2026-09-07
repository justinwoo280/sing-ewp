package ewp

// EWP/v2.3.1 ticket-based resumption — ticket format, minting, verification
// and the server ticket-key store. See EWP_V231_RESUMPTION.md.
//
// A ticket is an AEAD-sealed, server-keyed blob that buys identity
// pre-authorization and an outer-key seed on the NEXT connection. It never
// feeds session-key derivation: every resumption still performs a fresh
// hybrid X25519+ML-KEM-768 exchange (R1), ticket rejection silently falls
// back to the full six-stage handshake (R2), and the blob is useless to
// anyone who does not know the user's UUID (R4), so it may travel in
// cleartext ClientInit.

import (
	crand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// V23TicketVersion is the current ticket plaintext layout version.
	V23TicketVersion = 0x01

	// V23TicketKeyLen is the server ticket-key size (symmetric).
	V23TicketKeyLen = 32
	// V23TicketSeedLen is the outer-key seed carried inside a ticket.
	V23TicketSeedLen = 32
	// V23TicketIDLen is the random per-mint ticket identifier size.
	V23TicketIDLen = 16
	// V23TicketNonceLen is the AEAD nonce prefix carried with the blob.
	V23TicketNonceLen = 12

	// V23TicketPlainMaxLen bounds the sealed plaintext
	// (1+16+1+255+8+8+8+32+16 with a max-length serverID).
	V23TicketPlainMaxLen = 1 + 16 + 1 + 255 + 8 + 8 + 8 + V23TicketSeedLen + V23TicketIDLen
	// V23TicketMaxLen bounds the full wire blob.
	V23TicketMaxLen = V23TicketNonceLen + V23TicketPlainMaxLen + chacha20poly1305.Overhead

	// V23TicketLifetimeS is the default hard validity of one ticket.
	V23TicketLifetimeS = 2 * 3600
	// V23TicketKeyRotateS is the default ticket-key rotation period. It must
	// comfortably exceed V23TicketLifetimeS so the previous slot covers any
	// live ticket's whole lifetime.
	V23TicketKeyRotateS = 24 * 3600
)

// v23TicketAAD binds a ticket to the protocol and the issuing serverID.
func v23TicketAAD(serverID string) []byte {
	return append([]byte("ewp/v2.3.1/ticket"), []byte(serverID)...)
}

// v23TicketPlaintext is the sealed content of a ticket.
type v23TicketPlaintext struct {
	uuid         [UUIDLen]byte
	serverID     string
	routeEpoch   uint64
	issueTime    uint64
	expiryTime   uint64
	outerKeySeed [V23TicketSeedLen]byte
	ticketID     [V23TicketIDLen]byte
}

// v23TicketKeyStore rotates the symmetric ticket key with a current+previous
// two-slot overlap, mirroring v23OuterKeyStore. The key is process-local and
// restart-tolerant: losing it merely sends clients through one full
// handshake.
type v23TicketKeyStore struct {
	mu        sync.Mutex
	current   [V23TicketKeyLen]byte
	previous  [V23TicketKeyLen]byte
	hasPrev   bool
	rotatedAt time.Time
	lifetimeS uint64
	now       func() time.Time
}

func newV23TicketKeyStore() (*v23TicketKeyStore, error) {
	s := &v23TicketKeyStore{lifetimeS: V23TicketKeyRotateS, now: time.Now}
	if _, err := io.ReadFull(crand.Reader, s.current[:]); err != nil {
		return nil, err
	}
	s.rotatedAt = time.Now()
	return s, nil
}

// maybeRotate rotates when the current key is older than lifetimeS.
func (s *v23TicketKeyStore) maybeRotate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.rotatedAt) < time.Duration(s.lifetimeS)*time.Second {
		return
	}
	copy(s.previous[:], s.current[:])
	s.hasPrev = true
	if _, err := io.ReadFull(crand.Reader, s.current[:]); err != nil {
		// Rotation failure keeps the old key rather than killing the server;
		// tickets minted under it just live out the overlap.
		return
	}
	s.rotatedAt = s.now()
}

// mint seals a fresh ticket for (uuid, serverID, routeEpoch) valid for
// lifetimeS seconds.
func (s *v23TicketKeyStore) mint(serverID string, uuid [UUIDLen]byte, routeEpoch, lifetimeS uint64) ([]byte, error) {
	s.maybeRotate()
	s.mu.Lock()
	key := s.current
	s.mu.Unlock()

	var seed [V23TicketSeedLen]byte
	if _, err := io.ReadFull(crand.Reader, seed[:]); err != nil {
		return nil, err
	}
	var id [V23TicketIDLen]byte
	if _, err := io.ReadFull(crand.Reader, id[:]); err != nil {
		return nil, err
	}
	var nonce [V23TicketNonceLen]byte
	if _, err := io.ReadFull(crand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	now := uint64(s.now().Unix())
	plain := make([]byte, 0, 1+16+1+len(serverID)+8+8+8+V23TicketSeedLen+V23TicketIDLen)
	plain = append(plain, V23TicketVersion)
	plain = append(plain, uuid[:]...)
	plain = append(plain, byte(len(serverID)))
	plain = append(plain, serverID...)
	plain = binary.BigEndian.AppendUint64(plain, routeEpoch)
	plain = binary.BigEndian.AppendUint64(plain, now)
	plain = binary.BigEndian.AppendUint64(plain, now+lifetimeS)
	plain = append(plain, seed[:]...)
	plain = append(plain, id[:]...)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, V23TicketNonceLen+len(plain)+chacha20poly1305.Overhead)
	out = append(out, nonce[:]...)
	out = aead.Seal(out, nonce[:], plain, v23TicketAAD(serverID))
	return out, nil
}

var (
	errV23TicketBad    = errors.New("ewp/v2.3.1: invalid ticket")
	errV23TicketExpiry = errors.New("ewp/v2.3.1: ticket expired")
)

// verify opens a ticket against current and previous keys and enforces
// expiry, version and serverID binding. Any failure is a soft rejection:
// the caller falls back to the full handshake (R2).
func (s *v23TicketKeyStore) verify(serverID string, ticket []byte) (*v23TicketPlaintext, error) {
	if len(ticket) < V23TicketNonceLen+1+chacha20poly1305.Overhead || len(ticket) > V23TicketMaxLen {
		return nil, errV23TicketBad
	}
	s.maybeRotate()
	s.mu.Lock()
	keys := [][V23TicketKeyLen]byte{s.current}
	if s.hasPrev {
		keys = append(keys, s.previous)
	}
	s.mu.Unlock()

	var nonce [V23TicketNonceLen]byte
	copy(nonce[:], ticket[:V23TicketNonceLen])
	ct := ticket[V23TicketNonceLen:]

	var plain []byte
	for i := range keys {
		aead, err := chacha20poly1305.New(keys[i][:])
		if err != nil {
			return nil, err
		}
		p, err := aead.Open(nil, nonce[:], ct, v23TicketAAD(serverID))
		if err == nil {
			plain = p
			break
		}
	}
	if plain == nil {
		return nil, errV23TicketBad
	}

	pt, err := parseV23TicketPlaintext(plain)
	if err != nil {
		return nil, err
	}
	if pt.serverID != serverID {
		return nil, errV23TicketBad
	}
	if uint64(s.now().Unix()) >= pt.expiryTime {
		return nil, errV23TicketExpiry
	}
	return pt, nil
}

func parseV23TicketPlaintext(b []byte) (*v23TicketPlaintext, error) {
	if len(b) < 1 {
		return nil, errV23TicketBad
	}
	if b[0] != V23TicketVersion {
		return nil, errV23TicketBad
	}
	off := 1
	if len(b) < off+16+1 {
		return nil, errV23TicketBad
	}
	pt := &v23TicketPlaintext{}
	copy(pt.uuid[:], b[off:]); off += 16
	idLen := int(b[off]); off++
	if len(b) < off+idLen+8+8+8+V23TicketSeedLen+V23TicketIDLen {
		return nil, errV23TicketBad
	}
	pt.serverID = string(b[off : off+idLen]); off += idLen
	pt.routeEpoch = binary.BigEndian.Uint64(b[off:]); off += 8
	pt.issueTime = binary.BigEndian.Uint64(b[off:]); off += 8
	pt.expiryTime = binary.BigEndian.Uint64(b[off:]); off += 8
	copy(pt.outerKeySeed[:], b[off:]); off += V23TicketSeedLen
	copy(pt.ticketID[:], b[off:])
	return pt, nil
}

// deriveV23ResumeSecrets derives the resumption outer AEAD key and the
// resume-mode server nonce from the user's PSK and the ticket BLOB itself
// (not its sealed contents — the client cannot open the ticket, but it holds
// the blob, and so does the server once it arrives in ClientInitExt).
// uuidPSK is mandatory input (R4): the ticket alone is not an outer-key
// oracle. Both sides compute identical values. The resume server nonce
// replaces the HelloRetry-carried ServerNonce in status encryption and
// session-key derivation.
func deriveV23ResumeSecrets(uuid [UUIDLen]byte, ticket []byte, clientNonce [V23ClientNonceLen]byte) (outerKey [AEADKeyLen]byte, serverNonce [V23ServerNonceLen]byte, err error) {
	th := sha256.Sum256(ticket)
	psk := uuidPSK(uuid)
	prk := hkdf.Extract(sha256.New, th[:], psk[:])
	r1 := hkdf.Expand(sha256.New, prk, append([]byte("ewp/v2.3.1/resume-outer"), clientNonce[:]...))
	if _, err = io.ReadFull(r1, outerKey[:]); err != nil {
		return outerKey, serverNonce, err
	}
	r2 := hkdf.Expand(sha256.New, prk, append([]byte("ewp/v2.3.1/resume-snonce"), clientNonce[:]...))
	if _, err = io.ReadFull(r2, serverNonce[:]); err != nil {
		zero(outerKey[:])
		return outerKey, serverNonce, err
	}
	return outerKey, serverNonce, nil
}

// v23TicketHash binds a resumption handshake transcript to the exact ticket
// blob presented in ClientInitExt. The resume-mode ClientHello echoes it in
// the cookie slot so the server can check init/hello ticket consistency
// without changing the wire layout.
func v23TicketHash(ticket []byte) [32]byte {
	return sha256.Sum256(ticket)
}

// v23TicketFingerprint is a short non-invertible tag for logging/rate
// limiting without exposing the ticket blob.
func v23TicketFingerprint(serverID string, ticket []byte) [8]byte {
	h := hmac.New(sha256.New, []byte(serverID))
	h.Write(ticket)
	var out [8]byte
	copy(out[:], h.Sum(nil))
	return out
}

// wipeTicketPlaintext zeroes the sensitive fields of a verified ticket.
func wipeTicketPlaintext(pt *v23TicketPlaintext) {
	if pt == nil {
		return
	}
	zero(pt.outerKeySeed[:])
	zero(pt.uuid[:])
}
