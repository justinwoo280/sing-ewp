# EWP/v3 Handshake

This document is the compact implementation contract for EWP/v3. The detailed
security audit is historical evidence in
`SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md`. The encrypted data plane is
specified separately in `EWP_V3_RECORDS.md`.

## Scope

EWP/v3 is a connection-oriented protocol. It runs over either:

- a byte stream wrapped by `LengthFramer`; or
- a message carrier implementing `MessageTransport`.

Each carrier connection owns one handshake and one resulting secure stream.
Handshake state is held by the current connection and process only. The
protocol has no persistent store, shared cache, cross-carrier resume, or
database contract. If a carrier or process stops, the client starts a fresh
handshake.

EWP/v3 never probes or falls back to an earlier protocol revision on the same
connection.

## Handshake Flow

The wire sequence is:

```text
ClientInit
    -> HelloRetry
    -> ClientHello
    -> ServerHello
    -> ClientFinished
    -> ServerFinished
    -> encrypted application records
```

`ClientInit` selects the listener context, signed prekey bundle, route epoch,
and client nonces. `HelloRetry` is stateless server work and contains a cookie
bound to the listener, source, ClientInit values, and expiry.

`ClientHello` contains the encrypted client core and a credential admission
tag. `ServerHello` contains a fresh server data-plane hybrid exchange, an
opaque encrypted body, and an Ed25519 signature. `ClientFinished` and
`ServerFinished` confirm possession of the derived handshake secret before the
data plane starts.

The server MUST NOT invoke a handler, dial an upstream destination, allocate a
UDP sub-session, or accept application records before ClientFinished verifies.
The client MUST NOT send application records before ServerFinished verifies.

Any malformed, unauthenticated, expired, replayed, or mode-inappropriate
handshake is terminal for the current carrier. No semantic alert is required.

## Authentication And Prekeys

The server has an Ed25519 signing identity. Clients pin the public key out of
band. The server publishes signed one-time bundles containing:

```text
version, suite, server_id, deployment_scope, route_epoch,
bundle_generation, prekey_id, validity interval,
prekey_x25519_public, prekey_mlkem768_public, signature
```

Each bundle has independent X25519 and ML-KEM-768 private halves. The running
process consumes a bundle once through `PreKeyProvider.ClaimAndBurn`, clears
the consumed material, and never reuses its ID. The provider's replay check and
prekey consumption must be atomic within that process.

On process restart, old private prekey material MUST NOT be restored or reused.
The host provisions fresh bundles. This is an operational key-lifecycle rule,
not a persistence feature of the protocol.

Each client has a random 32-byte `KAuth`, a principal ID, an immutable listener
context, and a route epoch. The route tag is an O(1) alias derived from
`KAuth`; it is not a bearer credential or a stable wire identity.

## Server Processing Order

After receiving ClientInit and ClientHello, the server performs cheap checks in
this order:

1. Decode canonical bounded fields and validate version and suite.
2. Validate the retry cookie, expiry, and trusted source binding.
3. Validate the ClientHello core digest.
4. Look up the route tag in the in-process principal map.
5. Verify the credential admission tag in constant time.
6. Apply global, source, principal, and KEM admission limits.
7. Atomically claim the replay key and one-time prekey.
8. Perform X25519 and ML-KEM operations and decrypt the ClientHello core.
9. Build, sign, and send ServerHello.
10. Verify ClientFinished, build and send ServerFinished, then create the data stream.

Invalid cookies, unknown routes, invalid admission tags, replays, and rejected
claims must not reach asymmetric work. A valid credential may still consume a
prekey before a later cryptographic failure; this is intentional fail-closed
behavior.

## Key Schedule

All KDF inputs use HKDF-SHA-256 and explicit `ewp/v3` domain separation. The
schedule binds the listener version, suite, server identity, deployment scope,
roles, directions, epochs, signed bundle digest, and canonical transcript.

The important transcript points are:

```text
T_init            = H(encode(ClientInit base))
T_client_hello    = H(encode(ClientInit, HelloRetry, ClientHello, admission tag))
T_server_hello    = H(encode(T_client_hello, ServerHello))
T_client_finished = H(encode(T_server_hello, ClientFinished))
T_server_finished = H(encode(T_client_finished, ServerFinished))
```

The schedule derives separate outer, ServerHello, Finished, traffic, session,
and per-direction key-update values. Client and server roles and directions
are never interchangeable. The exact record format and key-update behavior
are in `EWP_V3_RECORDS.md` and the KDF implementation.

## Local State And Limits

The following state is bounded to the running process or current connection:

- signed prekey material and consumed prekey IDs;
- replay claims and principal route aliases;
- ClientInit, ClientHello, KEM, and per-stage admission limits;
- handshake secrets until the current handshake succeeds or terminates;
- secure-stream counters and key-update epochs; and
- UDP dispatcher sessions and their receive queues.

There is no restart recovery. A load balancer may route new connections to any
healthy instance, but each new connection performs the full handshake.

## Public API

```go
func NewClientV3(
    credential ClientCredential,
    serverIdentity Ed25519PublicKey,
    bundles PreKeyResolver,
) (*ClientV3, error)

func NewServiceV3(
    handler Handler,
    listener V3ListenerContext,
    identity ServerSigningIdentity,
    prekeys PreKeyProvider,
    admission AdmissionController,
) (*ServiceV3, error)

func (*ClientV3) DialConn(context.Context, net.Conn, Address) (net.Conn, error)
func (*ClientV3) DialPacketConn(context.Context, net.Conn, Address) (net.PacketConn, error)
func (*ClientV3) DialMessageTransport(context.Context, MessageTransport, Address) (net.Conn, error)
func (*ClientV3) DialPacketMessageTransport(context.Context, MessageTransport, Address) (net.PacketConn, error)
func (*ServiceV3) HandleConn(context.Context, net.Conn) error
func (*ServiceV3) HandleMessageTransportWithSource(context.Context, MessageTransport, SourceBinding) error
```

`DialConn` and `DialPacketConn` add byte-stream framing. Message-oriented
carriers pass each complete EWP message unchanged. A successful adapter owns
the carrier; a failed handshake closes it.

`Handler` receives a stream only after Finished confirmation. For UDP, the
server dispatcher runs one receive loop and creates one bounded session-local
`net.PacketConn` and one handler call per `globalID`.

## Carrier Contract

`MessageTransport` preserves complete ordered messages:

```go
type MessageTransport interface {
    SendMessage([]byte) error
    ReadMessage() ([]byte, error)
    Close() error
}
```

`Close` MUST interrupt blocked reads and writes. Carriers may additionally
implement context-aware I/O, address information, and deadline methods. Source
bindings supplied to the server are trusted, bounded, and used for cookie and
admission checks.

## Security Boundary

EWP/v3 provides authenticated encrypted application records, server identity
pinning, one-time hybrid prekey protection for recorded ClientHello metadata,
client and server Finished confirmation, strict counters, and bounded parsing.

It does not provide traffic-analysis elimination, endpoint compromise
protection, automatic failover of handshake state, or post-compromise recovery
from a compromised current traffic key. Key updates provide one-way backward
secrecy for prior epochs.

Verification commands and fixed-vector policy are in `TESTING.md`.
