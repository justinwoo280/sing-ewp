# EWP/v2.3 — Authenticated handshake with forward-secret ClientHello

EWP/v2.3 is a breaking handshake revision on top of the v2.2 opaque record
layer. The record format is unchanged from v2.2 (`frame_v22.go`); v2.3 only
replaces the handshake. There is no negotiation and no fallback: a v2.3 peer
rejects v2.1/v2.2 handshakes at authentication, and vice versa.

The goal is to close the remaining open audit findings for the v2 series
without adopting the v3 prekey-distribution machinery:

| Finding | v2.2 status | v2.3 fix |
|---|---|---|
| H-02 (residual) | timeout exists, no admission bound | admission controller before any asymmetric work |
| H-03 | static ECDH + linear UUID scan before auth | stateless HelloRetry cookie; asymmetric work only after cookie + O(1) route lookup |
| H-04 | process-local replay, handler runs before key confirmation | six-stage handshake with client/server Finished; handler gated on Finished |
| H-05 | no ClientHello forward secrecy | server presents a signed short-term outer key in HelloRetry; static key compromise no longer decrypts recorded ClientHello metadata |
| M-03 | labels separated, no transcript binding | every stage derives from the rolling transcript hash T |

## Handshake flow

```text
ClientInit        version, client_nonce, route_tag
    ->
HelloRetry        client_nonce, server_nonce, retry_cookie,
                  outer_key_id, outer_x25519_public, signature
    ->
ClientHello       retry_cookie, client ephemeral X25519+ML-KEM-768,
                  AEAD(timestamp, UUID, command, destination, padding)
                  keyed by the HelloRetry outer key
    ->
ServerHello       server ephemeral X25519 + ML-KEM ciphertext,
                  AEAD(status, padding), Ed25519 signature over T_sh
    ->
ClientFinished    AEAD(verify_data = HMAC(fin_key_c, T_sh))
    ->
ServerFinished    AEAD(verify_data = HMAC(fin_key_s, T_cf))
    ->
v2.2 opaque application records
```

The server MUST NOT invoke any handler, dial an upstream destination, or
allocate a UDP sub-session before ClientFinished verifies. The client MUST NOT
send application records before ServerFinished verifies.

## ClientInit and HelloRetry

`ClientInit` carries only `client_nonce` (16 bytes) and `route_tag`:

```text
route_tag = Truncate_16(HMAC-SHA-256(K_auth_uuid,
              "ewp/v2.3/route" || server_id || route_epoch))
```

`K_auth_uuid = SHA-256(UUID)`, i.e. the existing per-user PSK. The route tag
is an O(1) lookup alias, not a bearer credential: it never authorizes anything
on its own.

The server answers every syntactically valid ClientInit with a HelloRetry.
The cookie is stateless:

```text
cookie = Truncate_32(HMAC-SHA-256(cookie_key,
           "ewp/v2.3/cookie" || server_id || source_binding ||
           client_nonce || server_nonce || expires_at || outer_key_id))
```

`cookie_key` rotates periodically (current + previous accepted). A ClientHello
whose cookie fails verification is rejected with zero asymmetric work.

## Short-term outer key (H-05)

The server maintains a rotating outer X25519 keypair (default lifetime 1 h,
overlap 5 min). HelloRetry carries the current public half plus an Ed25519
signature:

```text
signature = Ed25519.Sign(static_signing_key,
              "ewp/v2.3/outer-key" || outer_key_id || not_before ||
              not_after || outer_x25519_public)
```

The ClientHello outer AEAD key is derived from
`X25519(client_ephemeral, outer_x25519_public)` instead of the long-term
static key. Once the private half is destroyed at rotation, recorded
ClientHello metadata (timestamp, UUID, destination) is unrecoverable even if
the long-term static key and the UUID both leak later.

Clients pin the server's Ed25519 verification key out of band. This replaces
the v2.1/v2.2 static X25519 pin.

## Transcript binding (M-03)

```text
T_ci  = SHA-256("ewp/v2.3/t-ci"  || ClientInit)
T_hr  = SHA-256("ewp/v2.3/t-hr"  || T_ci || HelloRetry)
T_ch  = SHA-256("ewp/v2.3/t-ch"  || T_hr || ClientHello)
T_sh  = SHA-256("ewp/v2.3/t-sh"  || T_ch || ServerHello)
T_cf  = SHA-256("ewp/v2.3/t-cf"  || T_sh || ClientFinished)
T_sf  = SHA-256("ewp/v2.3/t-sf"  || T_cf || ServerFinished)
```

All keys derive from the rolling transcript with versioned, role-separated
labels:

```text
outer_key   = HKDF(psk, "ewp/v2.3/outer",   outer_ecdh || T_hr)
hello_key   = HKDF(psk, "ewp/v2.3/hello",   outer_key  || T_ch)
traffic_prk = HKDF(hybrid_ikm, "ewp/v2.3/traffic", T_sf || server_id)
fin_key_c   = HKDF(traffic_prk, "ewp/v2.3/fin-c", role="client")
fin_key_s   = HKDF(traffic_prk, "ewp/v2.3/fin-s", role="server")
c2s_key / s2c_key / nonces / session_id as v2.2 but under traffic_prk
```

`hybrid_ikm = X25519(client_eph, server_eph) || MLKEM_shared`, as in v2.2.

## Admission (H-02/H-03)

Before ClientHello is accepted the server enforces, in order:

1. canonical decode with hard bounds (no allocation before length check);
2. cookie verification (cheap, stateless, 0-alloc reject);
3. O(1) route_tag lookup in a hash map (no linear UUID scan);
4. per-source / global / per-principal token buckets;
5. a bounded semaphore around the X25519+ML-KEM work.

Invalid cookies, unknown route tags, and rejected admissions terminate the
carrier without any asymmetric operation.

## Replay (H-04)

Replay protection is layered:

- the cookie binds `client_nonce` to the source and a 10 s expiry, so a
  replayed ClientInit from a different source fails immediately;
- a process-local `(UUID, ClientNonce)` replay cache (`ReplayCache`, shared
  with the rest of the v2 line) rejects an identical handshake transcript
  re-submitted inside the timestamp window — before any KEM work. Without
  this, an on-path observer replaying the same ClientInit+ClientHello would
  pass the cookie and timestamp checks and, because the server draws a fresh
  ServerNonce each time, would derive an *independent* session the server
  could not distinguish from a legitimate reconnect. The cache turns that
  silent acceptance into an explicit `ErrReplay`;
- the Finished exchange proves possession of the derived keys, so a replayed
  ClientHello cannot produce a live session or trigger a handler.

The cache is process-local and bounded (fail-closed at `maxReplayEntries`);
losing it on restart does not enable handler side effects because the handler
gate moved behind Finished. This is deliberately weaker than v3's one-time
prekey burn + persistent `ReplayKey` store (true single-use semantics across
restarts and instances), which v2.3 omits to stay stateless and
bundle-free.

## Record layer

Unchanged from v2.2: `frame_v22.go` opaque records, bucketized outer length,
phase-aware padding. v2.3 session keys share the v2.2 opaque record layer
(`protocolVersionV22`).

## What v2.3 deliberately does NOT do

- No one-time prekey bundles or bundle distribution (that is v3's design and
  its operational cost). The short-term outer key gives forward secrecy over
  the rotation window, not per-connection.
- No persistent or cross-instance replay store. The process-local
  `(UUID, ClientNonce)` cache rejects in-window duplicates for the running
  process; unlike v3's prekey burn, a restart within the timestamp window
  forgets seen nonces, though Finished-gating still blocks any handler side
  effect.
- No change to the v2.2 record format, UDP-over-TCP model, or padding policy.
