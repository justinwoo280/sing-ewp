# EWP/v3 Usage

`sing-ewp` owns the EWP/v3 handshake and encrypted application records. TLS,
HTTP, WebSocket, gRPC, and XHTTP are outer transports; they only provide a
`net.Conn` or `MessageTransport` and do not inspect EWP bytes.

## Client Setup

```go
credential := ewp.ClientCredential{
    Principal:  principalID,
    KAuth:      authKey,
    Listener:   listenerContext,
    RouteEpoch: routeEpoch,
}
client, err := ewp.NewClientV3(credential, pinnedServerKey, bundleResolver)
if err != nil {
    return err
}
conn, err := client.DialConn(ctx, outerConn, ewp.Address{Domain: "example.com", Port: 443})
```

`DialConn` does not return until both Finished messages verify. No application
bytes are sent before that point.

For a carrier that already has message boundaries, pass it directly:

```go
conn, err := client.DialMessageTransport(ctx, messageTransport, destination)
packetConn, err := client.DialPacketMessageTransport(ctx, messageTransport, destination)
```

After a successful handshake the returned adapter owns the message transport.
On failure, the transport is closed. `LengthFramer` is only needed for a raw
byte stream; WebSocket, gRPC, and XHTTP adapters must pass each complete EWP
message unchanged.

If the carrier closes before Finished completes, discard the failed carrier and
start a fresh complete handshake. The protocol does not transfer handshake
state between carriers and does not provide a persistence or resume contract.

## Server Setup

```go
service, err := ewp.NewServiceV3(
    handler,
    listenerContext,
    signingIdentity,
    prekeyProvider,
    admissionController,
)
if err != nil {
    return err
}
defer service.Close()

return service.HandleConn(ctx, outerConn)
```

The handler receives a `net.Conn` or `net.PacketConn` only after client key
confirmation. Invalid cookies, route tags, admission tags, claims, and
Finished messages terminate the transport without a semantic alert.

## Required Dependencies

- `PreKeyProvider.ClaimAndBurn` must atomically validate replay state and burn
  one in-process prekey. Admission leases are acquired separately and released
  when the current handshake finishes.
- `AdmissionController` must enforce source, principal, global, and KEM limits;
  production controllers must also implement `V3AdmissionLeaser`.
- The outer transport `Close` method must interrupt blocked I/O.

All protocol state is process-local and bounded. `MemoryPreKeyProvider` is
usable for a single-process deployment when its bundles and principals are
provisioned by the host. A restart invalidates in-flight handshakes and the
host must publish fresh one-time prekey material rather than restoring burned
private keys.

## Address And Records

```go
tcpTarget := ewp.Address{Domain: "example.com", Port: 443}
udpTarget := ewp.Address{Addr: netip.MustParseAddrPort("8.8.8.8:53")}

err := stream.SendTCPData(payload)
event, err := stream.Recv()
```

Use `DialPacketConn` or `DialPacketMessageTransport` for UDP semantics. EWP
UDP uses the v2.1 UDP-over-TCP model: each sub-session has a random
`globalID`, `UDP_NEW` carries its default target and optional first datagram,
`UDP_DATA` can carry a target for one packet, and `UDP_END` closes the
sub-session. A high-level `net.PacketConn` owns one sub-session; the underlying
`SecureStream` can carry multiple sub-sessions.

The base transport must preserve message boundaries, ordering, and ownership
rules, and `Close` must interrupt blocked I/O. Implementing
`ContextMessageTransport` avoids the fallback goroutine used for legacy
transports. Implement `MessageTransportInfo` to expose peer addresses to the
high-level adapters and server handler metadata. Implement the optional
deadline interfaces when the carrier supports post-handshake deadlines.

For a server `CommandUDP` flow, one carrier may create multiple concurrent
`NewPacketConnection` handler calls. Each handler receives a session-local
`net.PacketConn`; closing it sends `UDP_END` for that `globalID` without closing
other sub-sessions. Queue limits are finite and overflow closes the affected
sub-session.

See `EWP_V3_RECORDS.md` for the record layout and `TESTING.md` for verification
commands.
