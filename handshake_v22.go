package ewp

import (
	"crypto/ecdh"
	"errors"
)

// WriteClientHelloV22 starts an EWP/v2.2 handshake. Its cryptographic labels
// are distinct from v2.1, so a v2.1 peer rejects this ClientHello before any
// application handler is invoked. There is no downgrade or retry path.
func WriteClientHelloV22(
	send func([]byte) error,
	uuid [UUIDLen]byte,
	cmd Command,
	addr Address,
	serverStaticPub []byte,
) (*ClientHandshakeState, error) {
	return writeClientHelloV2x(send, uuid, cmd, addr, serverStaticPub, &v22Suite)
}

// EncodeClientHelloV22Test re-encodes a v2.2 ClientHello from its client-side
// state. It exists for deterministic protocol tests; production callers use
// WriteClientHelloV22 through ClientV22.
func EncodeClientHelloV22Test(
	state *ClientHandshakeState,
	serverStaticPub []byte,
) ([]byte, error) {
	if state == nil || state.x25519Priv == nil {
		return nil, errors.New("ewp/v2.2: nil state or ephemeral key")
	}
	if state.version != protocolVersionV22 {
		return nil, ErrProtocolVersion
	}
	return encodeClientHelloV2xInternal(state.hello, state.x25519Priv, serverStaticPub, &v22Suite)
}

// AcceptClientHelloV22Strict accepts only v2.2 ClientHellos. Use
// AcceptClientHelloV22WithReplay for a production service.
func AcceptClientHelloV22Strict(
	msg []byte,
	lookup UUIDLookupV21,
	serverStaticPriv *ecdh.PrivateKey,
) (helloOut []byte, result *HandshakeResult, err error) {
	return acceptClientHelloV2x(msg, lookup, serverStaticPriv, nil, &v22Suite)
}

// AcceptClientHelloV22WithReplay accepts only v2.2 ClientHellos and records
// an admitted ClientHello in cache. It never attempts v2.1 verification after
// a v2.2 authentication failure.
func AcceptClientHelloV22WithReplay(
	msg []byte,
	lookup UUIDLookupV21,
	serverStaticPriv *ecdh.PrivateKey,
	cache *ReplayCache,
) (helloOut []byte, result *HandshakeResult, err error) {
	return acceptClientHelloV2x(msg, lookup, serverStaticPriv, cache, &v22Suite)
}

// ReadServerHelloV22 completes only a v2.2 handshake state. A v2.1 state or
// ServerHello fails instead of falling back to a different key schedule.
func (s *ClientHandshakeState) ReadServerHelloV22(
	msg []byte,
	serverStaticPub []byte,
) (*HandshakeResult, error) {
	return s.readServerHelloV2x(msg, serverStaticPub, &v22Suite)
}
