# sing-ewp Usage Guide

This document shows how to embed `github.com/justinwoo280/sing-ewp` into a
proxy framework (sing-box, mihomo, custom Go binary). The library is
deliberately small and unopinionated: it implements the EWP v2 wire
protocol and gives you `net.Conn` / `net.PacketConn` adapters; it does
not decide what transport you run it over (TLS, WebSocket, gRPC, h3,
plain TCP — all work).

## Quick mental model

```
+--------------------------+
|  application bytes       |
+--------------------------+
|  ewp.Client / ewp.Service  ← this library
+--------------------------+
|  TLS (with optional ECH)   ← your TLS layer
+--------------------------+
|  v2ray transport (ws/grpc/ ← your transport layer
|  httpupgrade/...) OR raw
+--------------------------+
|  TCP                       ← your dialer
+--------------------------+
```

`ewp.Client.DialConn` accepts a `net.Conn` (the byte stream after TLS
+ transport) and returns a `net.Conn` whose Read/Write transparently
encrypt under EWP's per-direction AEAD.

## Minimal client

```go
import (
    "context"
    "crypto/tls"
    "net"

    "github.com/justinwoo280/sing-ewp"
)

func dialEWP(ctx context.Context, server, uuid string, dst ewp.Address) (net.Conn, error) {
    raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server)
    if err != nil { return nil, err }
    tlsConn := tls.Client(raw, &tls.Config{ServerName: "your.server.com"})
    if err := tlsConn.HandshakeContext(ctx); err != nil {
        raw.Close()
        return nil, err
    }
    client, err := ewp.NewClient(uuid)
    if err != nil { tlsConn.Close(); return nil, err }
    return client.DialConn(ctx, tlsConn, dst)
}
```

## Minimal server

```go
type myHandler struct { /* your fields */ }

func (h *myHandler) NewConnection(ctx context.Context, conn net.Conn, md ewp.Metadata) error {
    defer conn.Close()
    upstream, err := net.Dial("tcp", md.Destination.String())
    if err != nil { return err }
    defer upstream.Close()
    go io.Copy(upstream, conn)
    _, err = io.Copy(conn, upstream)
    return err
}

func (h *myHandler) NewPacketConnection(ctx context.Context, pc net.PacketConn, md ewp.Metadata) error {
    /* analogous: dial UDP upstream, shuttle packets */
    return nil
}

svc := ewp.NewService(&myHandler{})
svc.AddUser("11111111-2222-3333-4444-555555555555")

ln, _ := tls.Listen("tcp", ":443", tlsConfig)
for {
    conn, err := ln.Accept()
    if err != nil { return err }
    go svc.HandleConn(context.Background(), conn)
}
```

## Embedding into sing-box (template)

Following the `protocol/vless/` and `transport/v2ray` pattern, an EWP
adapter sits in `protocol/ewp/{outbound,inbound}.go` and delegates the
crypto layer to this library.

### `option/ewp.go` (≈30 lines)

```go
package option

type EWPOutboundOptions struct {
    DialerOptions
    ServerOptions
    UUID    string      `json:"uuid"`
    Network NetworkList `json:"network,omitempty"`
    OutboundTLSOptionsContainer
    Multiplex *OutboundMultiplexOptions `json:"multiplex,omitempty"`
    Transport *V2RayTransportOptions    `json:"transport,omitempty"`
}

type EWPInboundOptions struct {
    ListenOptions
    Users []EWPUser `json:"users,omitempty"`
    InboundTLSOptionsContainer
    Multiplex *InboundMultiplexOptions `json:"multiplex,omitempty"`
    Transport *V2RayTransportOptions   `json:"transport,omitempty"`
}

type EWPUser struct {
    Name string `json:"name"`
    UUID string `json:"uuid"`
}
```

### `protocol/ewp/outbound.go` (skeleton)

```go
package ewp

import (
    "context"
    "net"

    "github.com/sagernet/sing-box/adapter"
    "github.com/sagernet/sing-box/adapter/outbound"
    "github.com/sagernet/sing-box/common/dialer"
    "github.com/sagernet/sing-box/common/tls"
    C "github.com/sagernet/sing-box/constant"
    "github.com/sagernet/sing-box/log"
    "github.com/sagernet/sing-box/option"
    "github.com/sagernet/sing-box/transport/v2ray"
    "github.com/sagernet/sing/common"
    M "github.com/sagernet/sing/common/metadata"
    N "github.com/sagernet/sing/common/network"

    sewp "github.com/justinwoo280/sing-ewp"
)

const TypeEWP = "ewp"

func RegisterOutbound(registry *outbound.Registry) {
    outbound.Register[option.EWPOutboundOptions](registry, TypeEWP, NewOutbound)
}

type Outbound struct {
    outbound.Adapter
    dialer     N.Dialer
    serverAddr M.Socksaddr
    tlsConfig  tls.Config
    transport  adapter.V2RayClientTransport
    client     *sewp.Client
    logger     log.ContextLogger
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger,
    tag string, options option.EWPOutboundOptions) (adapter.Outbound, error) {

    d, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
    if err != nil { return nil, err }

    o := &Outbound{
        Adapter:    outbound.NewAdapterWithDialerOptions(TypeEWP, tag, options.Network.Build(), options.DialerOptions),
        dialer:     d,
        serverAddr: options.ServerOptions.Build(),
        logger:     logger,
    }
    if options.TLS != nil {
        o.tlsConfig, err = tls.NewClient(ctx, options.Server, common.PtrValueOrDefault(options.TLS))
        if err != nil { return nil, err }
    }
    if options.Transport != nil {
        o.transport, err = v2ray.NewClientTransport(ctx, o.dialer, o.serverAddr,
            common.PtrValueOrDefault(options.Transport), o.tlsConfig)
        if err != nil { return nil, err }
    }
    o.client, err = sewp.NewClient(options.UUID)
    if err != nil { return nil, err }
    return o, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
    raw, err := h.dialUnderlying(ctx)
    if err != nil { return nil, err }
    return h.client.DialConn(ctx, raw, socksaddrToEWP(dst))
}

func (h *Outbound) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
    raw, err := h.dialUnderlying(ctx)
    if err != nil { return nil, err }
    return h.client.DialPacketConn(ctx, raw, socksaddrToEWP(dst))
}

func (h *Outbound) dialUnderlying(ctx context.Context) (net.Conn, error) {
    if h.transport != nil { return h.transport.DialContext(ctx) }
    raw, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
    if err != nil { return nil, err }
    if h.tlsConfig != nil {
        return tls.ClientHandshake(ctx, raw, h.tlsConfig)
    }
    return raw, nil
}

func socksaddrToEWP(s M.Socksaddr) sewp.Address {
    if s.IsFqdn() {
        return sewp.Address{Domain: s.Fqdn, Port: uint16(s.Port)}
    }
    return sewp.Address{Addr: s.AddrPort()}
}
```

### `protocol/ewp/inbound.go` (skeleton)

```go
type Inbound struct {
    inbound.Adapter
    listener  *listener.Listener
    tlsConfig tls.ServerConfig
    transport adapter.V2RayServerTransport
    service   *sewp.Service
    router    adapter.ConnectionRouterEx
    logger    log.ContextLogger
}

// NewConnection on the Service handler dispatches via router:
type handler struct {
    router adapter.ConnectionRouterEx
    logger log.ContextLogger
}

func (h *handler) NewConnection(ctx context.Context, conn net.Conn, md sewp.Metadata) error {
    metadata := adapter.InboundContext{
        Source:      M.SocksaddrFromNet(md.Source),
        Destination: ewpToSocksaddr(md.Destination),
    }
    return h.router.RouteConnectionEx(ctx, conn, metadata, nil)
}

func (h *handler) NewPacketConnection(ctx context.Context, pc net.PacketConn, md sewp.Metadata) error {
    metadata := adapter.InboundContext{
        Source:      M.SocksaddrFromNet(md.Source),
        Destination: ewpToSocksaddr(md.Destination),
    }
    return h.router.RoutePacketConnectionEx(ctx, pc, metadata, nil)
}
```

### Registry hook (`include/registry.go`)

```diff
 import (
+    "github.com/sagernet/sing-box/protocol/ewp"
 )

 func InboundRegistry() *inbound.Registry {
     ...
+    ewp.RegisterInbound(registry)
 }

 func OutboundRegistry() *outbound.Registry {
     ...
+    ewp.RegisterOutbound(registry)
 }
```

## Configuration example

```json
{
  "outbounds": [{
    "type": "ewp",
    "tag": "ewp-out",
    "server": "your.server.com",
    "server_port": 443,
    "uuid": "11111111-2222-3333-4444-555555555555",
    "tls": {
      "enabled": true,
      "server_name": "your.server.com",
      "ech": {
        "enabled": true,
        "config_path": "ech.bin"
      }
    },
    "transport": {
      "type": "ws",
      "path": "/ewp"
    }
  }]
}
```

## Threading and lifecycle

- `*Client` is safe to share across goroutines; each Dial owns its own
  underlying conn.
- `*Service` is safe to call `HandleConn` on from many goroutines.
- The `net.Conn` returned by `Client.DialConn` allows concurrent
  `Write`, but `Read` MUST come from a single goroutine (this matches
  the underlying SecureStream contract: the receive AEAD counter would
  race otherwise).
- Closing the returned `net.Conn` / `net.PacketConn` is idempotent and
  safely closes the underlying transport.

## Length framing

EWP v2 is a message-oriented protocol; the on-wire framing of
individual messages is the responsibility of the transport layer.
This library provides `LengthFramer`, a 4-byte big-endian length
prefix wrapper that turns any `net.Conn` into a `MessageTransport`,
and `Client.DialConn` / `Service.HandleConn` apply it automatically.

If you carry EWP over a transport that already preserves message
boundaries (WebSocket, gRPC streams, HTTP/3 datagrams), you can
implement `MessageTransport` directly and use
`Service.HandleMessageTransport` to skip the redundant length prefix.

## Crypto invariants this library enforces

(See the `README.md` for full spec context.)

- Hybrid X25519 + ML-KEM-768 handshake, per session.
- Distinct C2S and S2C ChaCha20-Poly1305 keys derived via HKDF-SHA256
  with 4 separate `info` labels (`EWPv2 c2s key`, `EWPv2 s2c key`,
  `EWPv2 c2s nonce-prefix`, `EWPv2 s2c nonce-prefix`) — prevents
  reflection attacks.
- 64-bit per-direction frame counter wrapped into AEAD nonce —
  prevents replay and reorder.
- Outer MAC over ClientHello and ServerHello using the UUID PSK with
  constant-time comparison — prevents timing oracles on UUID.
- Ephemeral private keys (`x25519Priv`, `mlkemPriv`) are zeroed and
  set to `nil` immediately after deriving session keys — bounds the
  window in which a Heartbleed-style memory disclosure could leak
  long-term-equivalent secrets.

## Versioning

`v0.x.x` is pre-1.0: the wire format is stable (matches the EWP v2
spec), but the Go API may evolve in minor revisions as we wire it
into sing-box and discover unergonomic edges. Pin a tag in `go.mod`
and read the CHANGELOG before bumping.
