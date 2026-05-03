package ewp

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Cryptographic constants. Fixed by spec, not configurable.
const (
	// Symmetric primitives
	AEADKeyLen     = 32 // ChaCha20-Poly1305 key
	AEADNonceLen   = 12 // ChaCha20-Poly1305 nonce
	NoncePrefixLen = 4  // first 4 bytes of NP_dir; concatenated with 8B counter
	CounterLen     = 8

	// Handshake fields
	//
	// MagicLen was the length of the legacy plaintext "EWP2"
	// identifier; v2 removed it to eliminate a fixed 4-byte DPI
	// fingerprint, so the constant is now zero. Kept as a named
	// constant so any external code that referenced it still
	// compiles, and so that arithmetic in Encode/Decode reads as
	// "everything before nonce" rather than literal zeroes.
	MagicLen        = 0
	HandshakeNonce  = 12 // matches AEADNonceLen
	X25519PubLen    = 32
	MLKEM768PubLen  = 1184
	MLKEM768CipherL = 1088
	OuterMACLen     = 16

	// HMAC truncation
	OuterMACTrunc = 16

	// Padding bounds
	MinHandshakePad = 64
	MaxHandshakePad = 1024
	MaxFramePad     = 4096
	MaxFrameSize    = 65536
	MaxMetaLen      = 1024

	// PSK input cap (UUID is 16 bytes today; encoded as 16-byte raw)
	UUIDLen = 16

	// Time window for handshake timestamp acceptance, seconds.
	HandshakeTimestampWindow = 120
)

// HKDF info labels. These strings are part of the on-wire spec; do not
// edit them without bumping the protocol.
const (
	infoHandshakeAEAD = "EWPv2 handshake aead"
	infoSaltPrefix    = "EWPv2-salt"
	infoC2SKey        = "EWPv2 c2s key"
	infoS2CKey        = "EWPv2 s2c key"
	infoC2SNonce      = "EWPv2 c2s nonce"
	infoS2CNonce      = "EWPv2 s2c nonce"
)

// ErrShortKDF reports an unexpected short read from HKDF; this should
// be impossible with SHA-256 within the byte budgets we use, but we
// surface it explicitly rather than panic.
var ErrShortKDF = errors.New("ewp/v2: HKDF short read")

// uuidPSK derives a 32-byte PSK from a UUID by SHA-256, matching the
// "key = HKDF(UUID || ...)" convention while keeping the call sites
// uniform.
func uuidPSK(uuid [UUIDLen]byte) [32]byte {
	return sha256.Sum256(uuid[:])
}

// HandshakeAEADKey derives the symmetric key used to encrypt the
// handshake plaintext.
//
// The handshake is encrypted under a key derived purely from the PSK
// (UUID-hash) and the public handshake nonce; this binds the AEAD to a
// specific UUID+nonce while keeping the construction side-channel
// trivial. The ephemeral keys are NOT yet known here.
func HandshakeAEADKey(uuid [UUIDLen]byte, nonce [HandshakeNonce]byte) [AEADKeyLen]byte {
	psk := uuidPSK(uuid)
	r := hkdf.New(sha256.New, psk[:], nonce[:], []byte(infoHandshakeAEAD))
	var out [AEADKeyLen]byte
	if _, err := io.ReadFull(r, out[:]); err != nil {
		// HKDF of < 8160 bytes from SHA-256 cannot fail in practice.
		panic("ewp/v2: handshake AEAD key derivation failed: " + err.Error())
	}
	return out
}

// OuterMAC computes the truncated HMAC-SHA-256 used to authenticate
// the entire handshake message under the UUID-derived PSK.
func OuterMAC(uuid [UUIDLen]byte, msg []byte) [OuterMACLen]byte {
	psk := uuidPSK(uuid)
	h := hmac.New(sha256.New, psk[:])
	h.Write(msg)
	sum := h.Sum(nil)
	var out [OuterMACLen]byte
	copy(out[:], sum[:OuterMACLen])
	return out
}

// VerifyOuterMAC returns true iff tag matches HMAC(uuid, msg) truncated.
// Constant-time.
func VerifyOuterMAC(uuid [UUIDLen]byte, msg []byte, tag [OuterMACLen]byte) bool {
	want := OuterMAC(uuid, msg)
	return hmac.Equal(want[:], tag[:])
}

// SessionKeys holds the derived per-direction keys produced by
// DeriveSessionKeys.
type SessionKeys struct {
	C2SKey   [AEADKeyLen]byte
	S2CKey   [AEADKeyLen]byte
	C2SNonce [NoncePrefixLen]byte
	S2CNonce [NoncePrefixLen]byte
}

// DeriveSessionKeys runs HKDF-Extract+Expand using the hybrid IKM
// (X25519 ‖ ML-KEM shared secret) and salt = "EWPv2-salt" || cNonce ||
// sNonceEcho.
//
// Both nonces are the literal handshake-nonce fields exchanged in
// ClientHello and ServerHello; sNonceEcho MUST equal cNonce in
// well-formed flows, but we feed both to keep the salt uniquely tied
// to the wire bytes.
func DeriveSessionKeys(
	x25519Shared [X25519PubLen]byte,
	mlkemShared []byte,
	clientNonce [HandshakeNonce]byte,
	serverNonceEcho [HandshakeNonce]byte,
) SessionKeys {
	// IKM = classical || PQ
	ikm := make([]byte, 0, X25519PubLen+len(mlkemShared))
	ikm = append(ikm, x25519Shared[:]...)
	ikm = append(ikm, mlkemShared...)

	salt := make([]byte, 0, len(infoSaltPrefix)+HandshakeNonce*2)
	salt = append(salt, infoSaltPrefix...)
	salt = append(salt, clientNonce[:]...)
	salt = append(salt, serverNonceEcho[:]...)

	// Single PRK; expand four labels.
	prk := hkdf.Extract(sha256.New, ikm, salt)

	var sk SessionKeys
	if err := expand(prk, infoC2SKey, sk.C2SKey[:]); err != nil {
		panic("ewp/v2: derive C2S key: " + err.Error())
	}
	if err := expand(prk, infoS2CKey, sk.S2CKey[:]); err != nil {
		panic("ewp/v2: derive S2C key: " + err.Error())
	}
	if err := expand(prk, infoC2SNonce, sk.C2SNonce[:]); err != nil {
		panic("ewp/v2: derive C2S nonce: " + err.Error())
	}
	if err := expand(prk, infoS2CNonce, sk.S2CNonce[:]); err != nil {
		panic("ewp/v2: derive S2C nonce: " + err.Error())
	}
	return sk
}

func expand(prk []byte, info string, out []byte) error {
	r := hkdf.Expand(sha256.New, prk, []byte(info))
	n, err := io.ReadFull(r, out)
	if err != nil || n != len(out) {
		if err == nil {
			err = ErrShortKDF
		}
		return err
	}
	return nil
}
