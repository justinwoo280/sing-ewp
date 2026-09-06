# EWP/v3 Carrier and UoT Boundary

This document freezes the boundary between EWP/v3 and its outer carrier. It
also records the deliberate scope of the current UDP-over-TCP implementation.

## Carrier Layers

```text
sing-box dialer/listener
        |
gRPC / WebSocket / XHTTP / TLS / raw TCP carrier
        |
MessageTransport
        |
EWP/v3 handshake and opaque records
        |
net.Conn / net.PacketConn
```

The core package does not import or implement gRPC, WebSocket, XHTTP, TLS, or
HTTP. A message-oriented carrier implements `MessageTransport`; a byte-stream
carrier is wrapped by `LengthFramer`.

Each carrier message is one complete EWP message. The carrier must preserve
message boundaries and ordering, must not inspect or reserialize EWP bytes, and
must make `Close` interrupt blocked read and write operations. Optional
`ContextMessageTransport`, `MessageTransportInfo`, and deadline interfaces add
capabilities without changing the base contract.

## Public Entry Points

Clients use:

```go
DialConn(ctx, net.Conn, destination)
DialPacketConn(ctx, net.Conn, destination)
DialMessageTransport(ctx, MessageTransport, destination)
DialPacketMessageTransport(ctx, MessageTransport, destination)
```

The byte-stream methods add `LengthFramer`. The message-oriented methods pass
the carrier directly. A successful returned adapter owns the carrier; a failed
handshake closes it.

Servers use `HandleConn` for byte streams and
`HandleMessageTransportWithSource` for carriers that supply a trusted source
token. `MessageTransportInfo.RemoteAddr`, when present, is copied into handler
metadata but does not replace the trusted source token used by cookies and
admission.

## UDP Over TCP

The record layer uses the v2.1 UoT model:

- one `SecureStream` may carry multiple `globalID` sub-sessions;
- `UDP_NEW` opens a sub-session with a target and optional first datagram;
- `UDP_DATA` carries one datagram and may contain a per-packet target;
- an omitted `UDP_DATA` target means the sub-session default; and
- `UDP_END` closes the selected sub-session.

The high-level `net.PacketConn` adapter owns one `globalID`. Its first
`WriteTo` uses the actual write target when supplied, otherwise the handshake
destination. A later `UDP_NEW` for that adapter is a protocol error. Direct
`SecureStream` callers retain the lower-level multi-sub-session primitive.

This scope avoids pretending that a single `net.PacketConn` can safely consume
multiple independently owned receive queues. Frames for other IDs are not
delivered to the high-level adapter. Callers that need multiplexed handler
dispatch must use a dispatcher defined below rather than sharing one high-level
adapter.

## UDP Dispatcher

A full server-side dispatcher is a separate layer with these responsibilities:

1. run exactly one `SecureStream.Recv` loop;
2. create one bounded receive queue per `globalID` on `UDP_NEW`;
3. dispatch one handler per sub-session;
4. route `UDP_DATA` and `UDP_END` only to the matching queue;
5. reject duplicate `UDP_NEW` IDs and unknown data IDs; and
6. close all queues and handlers when the carrier or dispatcher closes.

The current dispatcher uses a finite per-session queue. Queue overflow closes
the affected sub-session; carrier write failure remains terminal for the whole
carrier because record counters cannot be rolled back. `UDP_PROBE_*` remains a
carrier-level frame and is ignored by the handler dispatcher.

## Connection Failure

Finished verification state belongs to the current handshake connection. It is
never serialized, handed to another carrier, or retained after the carrier is
closed. If a carrier fails before Finished completes, the client discards it
and starts a fresh complete handshake. This keeps the protocol connection
oriented and requires no persistence, shared cache, or resume backend.
