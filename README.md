# sing-ewp EWP/v3

This branch implements EWP/v3 only. Earlier handshake revisions are not part
of this package and are not probed or used as fallback.

The v3 handshake provides:

- canonical bounded field encoding;
- signed one-time X25519 plus ML-KEM-768 prekey bundles;
- stateless retry cookies bound to listener, source, prekey, and transcript;
- route-tag and admission checks before asymmetric work;
- atomic replay/prekey claim interfaces;
- signed ServerHello and bidirectional Finished confirmation;
- transcript-bound HKDF-SHA-256 traffic keys; and
- opaque ChaCha20-Poly1305 application records.

The normative handshake design is in [`EWP_V3_HANDSHAKE_DESIGN.md`](EWP_V3_HANDSHAKE_DESIGN.md).
The application record layer is in [`EWP_V3_RECORDS.md`](EWP_V3_RECORDS.md).
The carrier and UoT boundary is in [`EWP_V3_CARRIER_UOT_DESIGN.md`](EWP_V3_CARRIER_UOT_DESIGN.md).
The test gates are in [`TESTING.md`](TESTING.md).

## Public API

### Client

```go
client, err := ewp.NewClientV3(credential, pinnedServerIdentity, prekeyResolver)
conn, err := client.DialConn(ctx, transportConn, destination)
packetConn, err := client.DialPacketConn(ctx, transportConn, destination)

messageConn, err := client.DialMessageTransport(ctx, messageTransport, destination)
messagePacketConn, err := client.DialPacketMessageTransport(ctx, messageTransport, destination)

```

`DialMessageTransport` and `DialPacketMessageTransport` are the carrier-neutral
entry points for WebSocket, gRPC, XHTTP, and other message-oriented transports.
The returned adapters own the supplied `MessageTransport` after a successful
handshake. The existing `DialConn` and `DialPacketConn` methods add
`LengthFramer` for byte-stream carriers.

`ClientCredential` contains a random `KAuth`, principal identifier, immutable
listener context, and route epoch. The server identity is an out-of-band
pinned Ed25519 public key.

### Server

```go
service, err := ewp.NewServiceV3(
    handler,
    listener,
    signingIdentity,
    prekeyProvider,
    admissionController,
)
err = service.HandleConn(ctx, conn)
```

Construction requires the handler, immutable listener context, pinned signing
identity, a prekey provider, and an admission controller. All handshake state,
replay state, one-time prekey claims, and admission limits are bounded to the
running process. A carrier or process restart discards in-flight state; the
client must perform a fresh handshake.

The prekey provider's `ClaimAndBurn` operation must atomically validate replay
state and consume one in-process prekey.
Production admission controllers must also implement `V3AdmissionLeaser` so
concurrent processing leases remain bounded.

### Application Records

The handshake creates `V3SessionKeys`, which initialize the directional stream:

```go
stream, err := ewp.NewClientSecureStreamV3(transport, keys)
serverStream, err := ewp.NewServerSecureStreamV3(transport, keys)

err = stream.SendTCPData(payload)
event, err := stream.Recv()
```

UDP over TCP keeps the v2.1 sub-session model. One `SecureStream` can carry
multiple `globalID` values; `UDP_NEW` opens a sub-session with a default target
and an optional first datagram, `UDP_DATA` may carry a per-packet target, and
`UDP_END` closes that sub-session. The high-level packet adapter owns one
`globalID` while the low-level `SecureStream` retains the multiplexing
primitive. The service-side UDP dispatcher creates one handler and one bounded
queue per `globalID` while keeping a single receive loop.

## Transport Contract

Transports implement only:

```go
type MessageTransport interface {
    SendMessage([]byte) error
    ReadMessage() ([]byte, error)
    Close() error
}
```

Each message is delivered atomically and in order. A carrier must not inspect,
split, coalesce, or reserialize EWP bytes. `Close` must interrupt blocked reads
and writes so handshake deadlines are effective. Carriers may additionally
implement `ContextMessageTransport`, `MessageTransportInfo`, and the optional
deadline interfaces for cancellation, peer addresses, and post-handshake
`net.Conn`/`net.PacketConn` deadlines.

When the outer transport does not expose a `net.Conn`, use
`HandleMessageTransportWithSource` with a trusted, bounded source token. If
the carrier implements `MessageTransportInfo`, its `RemoteAddr` is also
forwarded to handler metadata. The plain `HandleMessageTransport` method
rejects a nil underlying connection.

For byte-stream transports, `LengthFramer` supplies the message boundary.

## Fixed Primitives

| Purpose | Primitive |
|---|---|
| AEAD | ChaCha20-Poly1305 |
| Classical component | X25519 |
| Post-quantum component | ML-KEM-768 |
| KDF | HKDF-SHA-256 |
| Server signatures | Ed25519 |

These primitives and v3 domain labels are not negotiated at runtime.

## Verification

```text
go test ./...
go vet ./...
go test -race -run '^TestV3' -count=1 ./...
go test -run '^$' -bench '^BenchmarkV3' -benchmem ./...
```

Fuzz targets and the fixed KAT vector policy are documented in `TESTING.md`.
