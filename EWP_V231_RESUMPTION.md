# EWP/v2.3.1 — Ticket-Based 1-RTT Resumption (Design)

Status: **design fixed, not yet implemented**
Date: 2026-09-07
Parent protocol: EWP/v2.3 (`EWP_V23.md`)

## 1. Motivation

The v2.3 six-stage handshake costs **3 RTT** before the first data byte is
routed:

```
ClientInit → HelloRetry → ClientHello → ServerHello → ClientFinished → ServerFinished
```

Two of those RTTs are deliberate purchases:

- **ClientInit → HelloRetry** buys stateless DoS resistance (return-routability
  cookie before any server state or asymmetric work) and delivers the signed
  short-term outer key.
- The remaining exchanges buy hybrid-PQC key agreement, transcript binding,
  and key-possession proofs. They are not negotiable.

The design assumption was that outer connections are long-lived. That breaks
down in the deployment shape operators actually want: **one H2 connection
carrying many muxed streams** (xhttp/grpc xmux, browser-like). When that one
outer connection dies — and on lossy mobile links it dies often — every muxed
stream stalls until a full 3-RTT handshake completes, and a 3-RTT handshake
over a high-loss path itself fails often (six messages, each a loss
opportunity). Reconnect storms turn "one bad connection" into "everything is
down for seconds".

Goal: let a client that recently completed a full handshake resume with
**1-RTT handshake confirmation, 1.5-RTT data**, without weakening any v2.3
security property.

## 2. Security invariants (non-negotiable)

R1. **Tickets never touch session-key derivation.** A ticket buys *identity
    pre-authorization* and an outer-key seed only. Every resumption performs a
    fresh hybrid X25519+ML-KEM-768 exchange. Compromise of the server ticket
    key yields nothing about any session key — same structure as TLS 1.3
    PSK+(EC)DHE: PSK authenticates, DHE provides forward secrecy.

R2. **Ticket verification failure silently falls back to the full six-stage
    handshake.** Forged/expired/malformed tickets are treated as "no ticket".
    Verification is one local AEAD open — same cost class as the cookie HMAC —
    so the DoS posture of v2.3 is unchanged. There is no ticket-specific
    amplification path.

R3. **No 0-RTT.** Application data is never accepted before ServerFinished
    verifies. 0-RTT would expose the application to replay at a layer where
    the existing (UUID, ClientNonce) cache and timestamp window cannot help.

R4. **Tickets are bearer tokens that are useless without the UUID.** The
    resumption outer key is derived from `uuidPSK ‖ outerKeySeed ‖ …`, so a
    ticket observed on the wire (it travels in cleartext ClientInit) cannot be
    used by anyone who does not already know the user's UUID. Ticket cleartext
    transmission is therefore safe by construction.

## 3. Ticket format

```
plaintext := version(1=0x01)
           ‖ uuid(16)
           ‖ serverIDLen(1) ‖ serverID (≤255)
           ‖ routeEpoch(8, BE)
           ‖ issueTime(8, BE unix seconds)
           ‖ expiryTime(8, BE unix seconds)
           ‖ outerKeySeed(32)
           ‖ ticketID(16, random)

ticket    := ticketNonce(12)
           ‖ AEAD(ticketKey, plaintext, aad = "ewp/v2.3.1/ticket" ‖ serverID)
           ‖ tag(16)
```

- Size: 12 + (1+16+1+serverIDLen+8+8+8+32+16) + 16 ≈ **119 B** for a typical
  11-byte serverID; hard ceiling 363 B.
- `ticketID` feeds the optional server-side soft replay register (§7).
- `expiryTime` is authoritative; clients never parse it (§8).

## 4. Server ticket key lifecycle

- 32-byte symmetric key, generated locally, **no persistence required**. A
  restart invalidates all outstanding tickets; clients fall back to the full
  handshake once and resume normally afterwards. This matches v2.3's
  stateless-where-possible posture.
- Rotation uses the same current+previous two-slot pattern as
  `v23OuterKeyStore`: tickets verify against current, then previous; new
  tickets are minted under current only.
- Default rotation: 24 h (≫ default ticket lifetime 2 h, so a ticket is
  always verifiable by the previous slot for its whole life).

## 5. Wire changes (all optional, all backward compatible)

### 5.1 ClientInit capability extension

Base v2.3.0 ClientInit is exactly 32 B (`ClientNonce(16) ‖ RouteTag(16)`).

Extended form (only ever sent by a client that holds a ticket for this
server):

```
ClientInitExt := ClientNonce(16) ‖ RouteTag(16)
               ‖ flags(1) = 0x01
               ‖ ticketLen(2, BE) ‖ ticket
```

- `flags=0x01` means: "I support resumption; a ticket follows; and I accept
  FrameTicket later."
- Servers that do not understand the extension will reject the over-long
  ClientInit. That is acceptable **by construction of when it is sent**: a
  client only has a ticket if this server previously minted one, i.e. the
  server is v2.3.1-capable. The only failure case is a server *downgraded*
  after issuing tickets; the client then deletes its ticket on hard failure
  and reconnects with the base format.

### 5.2 FrameTicket (0x21)

New record-layer frame type carrying one ticket blob as payload.

- Sent by the server **only to clients that set flags=0x01**, early on the
  data plane (immediately after ServerFinished processing completes).
- Unknown to v2.3.0 clients, but they never receive it (they never set the
  flag), so no compatibility surface exists.
- A fresh ticket is minted after **every** successful handshake, full or
  resumed: clients always hold exactly one, most-recent ticket.

## 6. Resumption message flow

Full handshake (unchanged) issues a ticket; resumption consumes it:

```
t=0.0  C → S   ClientInitExt(flags|ticket)          ─┐ same flush
               ClientHello_outer(resume-derived key) ┘
t=0.5  S → C   ServerHello { serverEph, sig }       ─┐ same flush
               ServerFinished                        ┘
t=1.0  C → S   ClientFinished                        ─┐ same flush
               <application data frames>             ┘
t=1.5  S       routes data
```

- **Resumption outer key** (replaces the HelloRetry-delivered outer key):

```
outerKey = HKDF-Extract(salt = outerKeySeed, ikm = uuidPSK)
         → Expand("ewp/v2.3.1/resume-outer" ‖ clientNonce, 32)
```

  uuidPSK is mandatory input (R4): the ticket alone is not an outer-key
  oracle. ClientHello AAD/nonce construction is unchanged.
- Everything after the outer AEAD open is the **standard** ClientHello
  pipeline: hybrid key exchange, transcript, Finished MACs, session-key
  derivation with fresh ephemeral keys (R1), nonce-prefix derivation, replay
  cache insert, admission control — all identical to the full path.
- ServerHello and ServerFinished are emitted in one flush; ClientFinished and
  the first data frames in one flush. Server routes data at **t=1.5 RTT**;
  the client has server authentication at **t=1.0 RTT**.

### 6.1 Fallback semantics

| Server decision | Trigger | Server action | Client action |
|---|---|---|---|
| accept ticket | AEAD opens, version/expiry/serverID/routeEpoch match, uuid resolves | skip HelloRetry, expect ClientHello under resume-derived outer key | continue §6 |
| reject ticket | anything else | send normal **HelloRetry** (fresh cookie + outer key) | discard resumption state, re-encapsulate ClientHello under the HelloRetry outer key, continue full six-stage |

Rejection is indistinguishable from "server never supported tickets": the
client always completes. The client state machine must tolerate having
already emitted a resume-mode ClientHello — it re-derives and re-sends.

## 7. Replay & abuse analysis

- **Tickets are not one-time-use.** xmux connection storms legitimately
  resume many outer connections with the same ticket within its lifetime.
  Forcing single-use would kill the primary use case.
- What a replayed ticket enables is exactly "another independent session for
  a user the attacker already is" — v2.3's existing tolerance semantics. The
  `(UUID, ClientNonce)` replay cache still rejects replayed *handshake byte
  streams*, and fresh nonces per attempt keep resumed sessions independent.
- Optional server soft register: remember `ticketID` → accept-count and
  rate-limit abnormally high reuse (default: off; the honest xmux pattern is
  indistinguishable from modest abuse and false positives hurt more than the
  attack).
- Ticket rotation on every handshake (§5.2) bounds any stolen ticket's
  useful life to `expiryTime` and keeps wire-observed tickets
  non-linkable across reconnects (random `ticketID` + fresh `outerKeySeed` +
  fresh `ticketNonce` per mint).

## 8. Client ticket store (library interface)

```go
// V23TicketStore caches resumption tickets. nil store (the default)
// disables resumption entirely: the client always runs the full six-stage
// handshake, byte-identical to v2.3.0.
type V23TicketStore interface {
    // Get returns a ticket for serverKey ("serverID@addr"), if any.
    Get(serverKey string) (ticket []byte, ok bool)
    // Put stores the most recent ticket (replacing any previous one).
    Put(serverKey string, ticket []byte)
    // Delete drops the ticket (hard handshake failure with an extended
    // ClientInit, e.g. server downgrade).
    Delete(serverKey string)
}
```

- The client **never parses** the ticket: no expiry checks, no field access.
  Expiry enforcement is exclusively the server's (via `expiryTime`), and
  rejection costs the client nothing but one normal HelloRetry round.
- The library ships a trivial in-memory store; persistence is the host's
  choice (sing-box: in-memory; SekaiMod: optional profile-adjacent storage).

## 9. Comparison with TLS 1.3 resumption

| Aspect | TLS 1.3 PSK-(EC)DHE | EWP/v2.3.1 (this design) |
|---|---|---|
| Ticket secrecy | encrypted, server-keyed | encrypted, server-keyed (same) |
| FS on resume | yes, fresh DHE | yes, fresh X25519+ML-KEM-768 (R1) |
| 0-RTT data | optional, replayable | **never** (R3) |
| DoS gate on first contact | none (TCP assumed) | cookie + admission, kept on all non-resumed flows (R2) |
| Ticket→key link | PSK feeds early secret | **none** — ticket feeds only outer-key seed; uuidPSK still required (R4) |
| Server state | ticket key only | ticket key only (same, restart-tolerant) |

## 10. Implementation phases

1. **Library — server**: ticket key store (two-slot rotation), mint/verify,
   FrameTicket emission, ClientInitExt parsing, fallback-to-HelloRetry path,
   resume outer-key derivation. All server-side; testable without any client
   state.
2. **Library — client**: `V23TicketStore`, extended ClientInit, resume
   ClientHello path, fallback re-encapsulation, ticket capture from
   FrameTicket.
3. **Hosts**: sing-box outbound ticket cache (in-memory, per outbound tag);
   SekaiMod optional store. Default everywhere: **resumption on** when a
   store is present; nothing to configure.

No inbound-side (server) config besides optional lifetime/rotation knobs
with safe defaults (2 h / 24 h).

## 11. Test plan

- **KAT**: ticket mint/verify vectors against the independent Python oracle
  (extend `testdata/v23_kat_oracle.py`).
- **Round trip**: full handshake → capture ticket → resume → echo, on
  net.Pipe and over every transport used by sing-box e2e.
- **Fallback matrix**: expired ticket, tampered ticket, wrong-serverID
  ticket, v2.3.0-server (base ClientInit only), server-downgrade (extended
  init rejected → client deletes ticket → base retry succeeds).
- **Concurrency**: N goroutines resuming with the same ticket (xmux storm)
  must all succeed with independent session keys.
- **FS audit**: derive two resumed sessions from one ticket; keys must be
  independent; zeroing check on outerKeySeed after use.
- **Fuzz**: ClientInitExt parser, ticket blob parser, FrameTicket payload
  (invariant-fuzz style: tampered ticket never verifies, malformed
  extension never panics, rejection always falls back cleanly).
- **Interop**: sing-box client ↔ sing-box server resume over ws/grpc/xhttp
  with a killed-and-reopened outer connection; measure reconnect RTTs.

## 12. Open questions (defaults chosen; revisit only with evidence)

- Ticket lifetime **2 h** and key rotation **24 h**: generous for mobile
  reconnect cadence; tighten if a deployment sees ticket theft as a
  first-class threat.
- `FrameTicket` type code **0x21** (next free after `FramePaddingOnly=0x20`).
- Soft per-ticket accept register: default **off** (§7).
