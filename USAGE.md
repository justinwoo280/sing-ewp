# sing-ewp Usage Guide

This document shows how to embed `github.com/justinwoo280/sing-ewp` into a
proxy framework (sing-box, mihomo, custom Go binary). The library is
deliberately small and unopinionated: it implements the EWP/v2.2 wire
protocol and gives you `net.Conn` / `net.PacketConn` adapters; it does
not decide what transport you run it over (TLS, WebSocket, gRPC, h3,
plain TCP - all work).

All deployment examples use `ClientV22` and `ServiceV22`. Pin the server
static public key out of band; do not use the deprecated UUID-only APIs for a
new deployment. EWP/v2.2 bucketizes the observable data-plane record length,
but does not provide deployment-wide replay protection or ClientHello metadata
forward secrecy.

## Quick mental model

```
+--------------------------+
|  application bytes       |
+--------------------------+
|  ewp.ClientV22 / ewp.ServiceV22  <- this library
+--------------------------+
|  TLS (with optional ECH)   ← your TLS layer
+--------------------------+
|  v2ray transport (ws/grpc/ ← your transport layer
|  httpupgrade/...) OR raw
+--------------------------+
|  TCP                       ← your dialer
+--------------------------+
```

`ewp.ClientV22.DialConn` accepts a `net.Conn` (the byte stream after TLS
+ transport) and returns a `net.Conn` whose Read/Write transparently
encrypt under EWP's per-direction AEAD.

### EWP and TLS terminology

`EWP ClientHello` is the EWP protocol message sent after the optional outer
TLS transport has been established. It is not the `TLS ClientHello` sent by a
TLS implementation. The same distinction applies to `EWP ServerHello` and
`TLS ServerHello`. The EWP cookie, prekey, replay, Finished, and metadata
controls apply to EWP messages; TLS is an additional transport layer and is
not required for the EWP handshake itself.

## Minimal client

```go
import (
    "context"
    "crypto/tls"
    "net"

    "github.com/justinwoo280/sing-ewp"
)

func dialEWP(ctx context.Context, server, uuid, serverStaticPubB64 string, dst ewp.Address) (net.Conn, error) {
    raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server)
    if err != nil { return nil, err }
    tlsConn := tls.Client(raw, &tls.Config{ServerName: "your.server.com"})
    if err := tlsConn.HandshakeContext(ctx); err != nil {
        raw.Close()
        return nil, err
    }
    client, err := ewp.NewClientV22(uuid, serverStaticPubB64)
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

svc, err := ewp.NewServiceV22(&myHandler{}, serverStaticPrivB64)
if err != nil { return err }
defer svc.Close()
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
    ServerStaticPublicKey string `json:"server_static_public_key"`
    Network NetworkList `json:"network,omitempty"`
    OutboundTLSOptionsContainer
    Multiplex *OutboundMultiplexOptions `json:"multiplex,omitempty"`
    Transport *V2RayTransportOptions    `json:"transport,omitempty"`
}

type EWPInboundOptions struct {
    ListenOptions
    Users []EWPUser `json:"users,omitempty"`
    ServerStaticPrivateKey string `json:"server_static_private_key"`
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
    client     *sewp.ClientV22
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
    o.client, err = sewp.NewClientV22(options.UUID, options.ServerStaticPublicKey)
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
    service   *sewp.ServiceV22
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
     "server_static_public_key": "base64-encoded-32-byte-x25519-public-key",
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

- `*ClientV22` is safe to share across goroutines; each Dial owns its own
  underlying conn.
- `*ServiceV22` is safe to call `HandleConn` on from many goroutines.
- The `net.Conn` returned by `ClientV22.DialConn` allows concurrent
  `Write`. `SecureStream.Recv` serializes concurrent readers, though a
  single reader is still recommended for predictable event ordering.
- Closing the returned `net.Conn` / `net.PacketConn` is idempotent and
  safely closes the underlying transport.

## Length framing

EWP v2 is a message-oriented protocol; the on-wire framing of
individual messages is the responsibility of the transport layer.
This library provides `LengthFramer`, a 3-byte big-endian length
prefix wrapper that turns any `net.Conn` into a `MessageTransport`,
and `ClientV22.DialConn` / `ServiceV22.HandleConn` apply it automatically.

If you carry EWP over a transport that already preserves message
boundaries (WebSocket, gRPC streams, HTTP/3 datagrams), you can
implement `MessageTransport` directly and use
`ServiceV22.HandleMessageTransport` to skip the redundant length prefix.

## Crypto invariants this library enforces

(See the `README.md` for full spec context.)

- v2.2 binds the outer handshake to a pinned server X25519 public key and
  uses ephemeral X25519 plus ML-KEM-768 for post-handshake data keys.
- Distinct C2S and S2C ChaCha20-Poly1305 keys and nonce prefixes prevent
  direction reflection; frame counters reject replay, reordering, and wrap.
- Observable padding and timing decisions use `crypto/rand`; v2.2 encrypts
  the frame counter, type, metadata length, payload length, and padding.
- Ephemeral byte slices and frame AEAD references are cleared on normal
  teardown and error paths on a best-effort basis. Go does not provide
  guaranteed secure memory erasure for opaque runtime-managed key objects.
- The v2.2 outer record reveals only a bucketized ciphertext length. v2.1
  remains length-leaking for migration only, and `Rekey` remains one-way key
  evolution rather than post-compromise recovery.

## Versioning

`v0.x.x` is pre-1.0: wire revisions are explicitly incompatible and may
continue to evolve with the security model. Pin a tag in `go.mod`, coordinate
peer upgrades, and read `UPGRADING.md` plus the changelog before bumping.
