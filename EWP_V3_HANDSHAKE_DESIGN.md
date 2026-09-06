# EWP/v3 Handshake Design

## Status

This is a design for an incompatible future protocol revision. It is not
implemented by the current package and does not change the frozen findings in
`SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md`.

EWP/v3 retains the EWP/v2.2 opaque application-record format, but derives its
traffic keys under v3-only labels. A v3 endpoint never probes, retries, or
falls back to v2.2, v2.1, or legacy v2 on the same connection.

## Terminology And Layering

This document describes the **EWP handshake**, not the TLS handshake. Unless a
section explicitly says `TLS ClientHello` or `TLS ServerHello`, the terms
`ClientHello`, `ServerHello`, `ClientFinished`, and `ServerFinished` mean EWP
protocol messages.

When TLS is used, it is an optional outer transport layer:

```text
TLS ClientHello / TLS ServerHello
    -> TLS 1.3 transport established
    -> EWP ClientInit
    -> EWP HelloRetry
    -> EWP ClientHello / EWP ServerHello
    -> EWP ClientFinished / EWP ServerFinished
    -> EWP encrypted application records
```

Without TLS, the EWP messages run directly over a compliant
`MessageTransport`. TLS can add certificate authentication and conceal EWP
handshake metadata from the outer network observer, but it does not replace
EWP cookies, prekeys, replay claims, Finished messages, or EWP traffic-key
derivation. In particular, the ClientHello metadata discussed in H-05 is the
metadata inside **EWP ClientHello**, not the TLS ClientHello.

## Goals

The v3 handshake is designed to address the remaining material audit findings:

1. Reject unauthenticated traffic before expensive per-user asymmetric work.
2. Use one linearizable replay/prekey claim across instances and restarts.
3. Require client key confirmation before any handler, upstream connection, or
   UDP state is created.
4. Protect recorded ClientHello metadata after a later compromise of the
   server signing key and client credential.
5. Bind version, suite, identity, scope, role, transcript, direction, and
   epoch into the key schedule.
6. Make legacy protocol activation explicit and unsafe during migration.

It does not eliminate traffic analysis, availability attacks that drop packets,
or compromise of a live endpoint.

## Audit Finding Mapping

| Finding | v3 control |
|---|---|
| C-01 legacy UUID-only protocol | Production builds hard-disable legacy constructors; v3 has separate listener and no fallback. |
| H-02 handshake resource exhaustion | Mandatory stage deadlines, bounded parses, global/source/principal limits, and a concurrent-KEM semaphore. |
| H-03 expensive work before authentication | Stateless retry cookie, O(1) route tag, and credential admission tag precede prekey access and asymmetric work. |
| H-04 local replay and early side effects | Shared linearizable `ClaimAndBurn` plus ClientFinished gating before handler dispatch. |
| H-05 ClientHello metadata forward secrecy | Signed one-time hybrid encryption prekeys are consumed and erased after one claim. |
| M-03 incomplete KDF binding | Canonical transcript hashes and explicit version/suite/identity/scope/role/direction/epoch labels. |
| M-01 key lifecycle | Stage secrets, consumed prekeys, and prior epoch secrets are explicitly destroyed on every terminal path. |
| M-02 replay capacity | Replay claim, quota, and prekey availability are one bounded durable transaction. |

## Trust And Provisioning

### Server identity

The server has a pinned Ed25519 signing identity, not a static X25519
encryption key. Clients receive the Ed25519 public key out of band. The signing
key signs server prekey bundles and the complete ServerHello transcript.

### One-time hybrid prekeys

The server publishes signed prekey bundles:

```text
PreKeyBundle = Encode(
  version, suite, server_id, deployment_scope, route_epoch, bundle_generation,
  prekey_id, not_before, not_after,
  prekey_x25519_public, prekey_mlkem768_public,
  signature_ed25519
)
```

The signature covers every preceding field with the `ewp/v3/prekey-bundle`
domain label. Clients reject an invalid signature, the wrong identity/scope,
an expired bundle, a reused prekey ID, a rollback below the highest persisted
`bundle_generation` for this server/scope/suite, or an unsupported suite.

Each prekey has independent X25519 and ML-KEM-768 private halves. The shared
prekey service consumes each pair once, erases it after use, never reuses its
ID, and does not restore consumed private material from backup. This is the
property that prevents a later signing-key compromise from decrypting recorded
ClientHello metadata.

### Client credential and routing alias

Each client receives a fresh random 32-byte `K_auth`. The legacy UUID can stay
as an internal migration identifier, but is never a v3 authentication key or
wire identifier.

For the route epoch in the signed bundle, the client computes:

```text
route_tag = Trunc128(HMAC-SHA-256(
  K_auth,
  Encode("ewp/v3/route", server_id, deployment_scope, route_epoch)))
```

Servers precompute current and previous epoch tags into an O(1) map from
`route_tag` to `{principal_id, K_auth, quota}`. The tag is a rolling alias, not
a permanent identifier. The server sends the same shaped retry result for an
unknown tag as for a known tag to avoid an account-enumeration oracle.

## Canonical Encoding

All handshake structures use one length-delimited canonical `Encode` format:

- fields have fixed numeric tags and canonical order;
- duplicate, unknown critical, non-minimal, and trailing fields are rejected;
- byte strings are length-prefixed and bounded before allocation;
- every transcript hash is over the exact canonical bytes transmitted;
- every cryptographic label starts with `ewp/v3/`.

The protocol must publish fixed vectors for every message, signature, cookie,
KDF stage, and Finished verification value.

## Message Flow

```text
0. Client obtains and verifies a signed one-time PreKeyBundle.

1. C -> S  ClientInit
2. S -> C  HelloRetry
3. C -> S  ClientHello
4. S -> C  ServerHello
5. C -> S  ClientFinished
6. S -> C  ServerFinished
7. Both    EWP/v2.2 opaque application records under v3 traffic keys
```

### 1. ClientInit

The client builds a ClientHello core before sending ClientInit. It first builds
the pre-encryption base, then adds the digest of the completed core:

```text
ClientInitBase = Encode(
  version, suite, server_id, deployment_scope,
  route_tag, route_epoch,
  prekey_id, bundle_generation, bundle_digest,
  init_nonce, client_nonce
)

ClientInit = Encode(ClientInitBase, client_hello_core_digest)
```

`client_nonce` is random and non-sensitive. `client_hello_core_digest` is a
SHA-256 digest of the complete bounded ClientHello core. ClientInit is padded
to a minimum retry-safe size so HelloRetry cannot amplify traffic.

The server applies only fixed message bounds, listener-wide admission limits,
and per-source rate limits at this stage. It performs no static ECDH, ML-KEM
operation, user-table scan, prekey claim, or handler work.

### 2. HelloRetry

HelloRetry is stateless and carries:

```text
HelloRetry = Encode(
  version, suite, init_nonce, retry_nonce,
  cookie_key_id, expires_at, cookie
)
```

The cookie is:

```text
cookie = HMAC-SHA-256(
  K_cookie[cookie_key_id],
  Encode("ewp/v3/cookie", version, suite, server_id, deployment_scope,
         source_binding, expires_at, prekey_id, bundle_digest,
         bundle_generation, init_nonce, client_nonce,
         client_hello_core_digest))
```

`source_binding` is a normalized peer address or a trusted outer-transport
token. Cookie key rotation accepts only a short current/previous key window.
The retry response has a fixed bounded shape and must not be larger than the
minimum ClientInit request.

### 3. ClientHello

The client creates a fresh outer X25519 keypair and ML-KEM-768 encapsulation to
the selected server prekey. The public core header is:

```text
ClientHelloCoreHeader = Encode(
  prekey_id, bundle_generation, bundle_digest, client_nonce,
  client_outer_x25519_public, outer_mlkem768_ciphertext
)

ClientHelloCore = Encode(ClientHelloCoreHeader, client_hello_ciphertext)
```

The outer hybrid secret is:

```text
outer_ikm = LD(X25519(client_outer_private, prekey_x25519_public)) ||
            LD(MLKEM768_encapsulation_secret)
```

The encrypted ClientHello plaintext contains:

```text
ClientHelloPlaintext = Encode(
  command, destination,
  client_data_x25519_public, client_data_mlkem768_public,
  negotiated_fixed_parameters, random_padding
)
```

The client sends:

```text
ClientHello = Encode(
  ClientInit, HelloRetry, ClientHelloCore,
  admission_tag
)

admission_tag = HMAC-SHA-256(
  Expand(credential_prk, "ewp/v3/admission", 32),
  H(Encode("ewp/v3/admission-input", ClientInit, HelloRetry, ClientHelloCore)))
```

The ClientHello AEAD key and AAD use `ClientInitBase` plus
`ClientHelloCoreHeader`, which are both available before ciphertext creation.
`client_hello_core_digest` is computed only after encryption over the complete
core and is then bound by ClientInit, HelloRetry, the cookie, and
`admission_tag`.

Before any asymmetric operation the server verifies, in order:

1. canonical encoding and strict bounds;
2. cookie and expiry/source binding;
3. `client_hello_core_digest`;
4. O(1) route-tag lookup;
5. `admission_tag` in constant time;
6. source, principal, global-handshake, and concurrent-KEM quotas.

Only then can the server touch a prekey private half or run X25519/ML-KEM.
This makes an attacker without `K_auth` pay only bounded parsing and HMAC cost.

### 4. Atomic replay and prekey claim

After cheap admission succeeds, the server calls a mandatory shared durable
operation:

```text
ClaimAndBurn(
  replay_key = HMAC-SHA-256(
    K_replay,
    Encode("ewp/v3/replay", version, suite, server_id, deployment_scope,
           principal_id, prekey_id, init_nonce, client_nonce,
           client_hello_core_digest)),
  version, suite, server_id, deployment_scope, route_epoch,
  bundle_generation, prekey_id, bundle_digest,
  principal_id, source_binding, expiry
)
```

`ClaimAndBurn` is one linearizable transaction across all service instances.
It requires all of the following to be true atomically:

- the replay key is absent;
- the immutable listener context matches `(version, suite, server_id,
  deployment_scope)`;
- the route-tag lookup epoch equals the transmitted route epoch;
- the prekey record matches `(route_epoch, bundle_generation, prekey_id,
  bundle_digest)` from the signed stored bundle, and is unused and unexpired;
- global, source, and principal quotas are available.

On success it persists the replay claim through cookie expiry plus handshake
grace, burns the prekey ID, and releases the private prekey material exactly
once to the claimant. Store outage, ambiguity, replay, quota exhaustion, or a
prekey conflict is fail-closed. There is no nil store or local-cache fallback.

The server then decapsulates the outer ML-KEM ciphertext, computes the outer
X25519 secret, decrypts ClientHelloPlaintext, and verifies all inner fields.
A credential holder can consume only its configured quota; malformed traffic
from that holder may consume a prekey, which is intentional fail-closed
behavior.

### 5. ServerHello

The server creates fresh data-plane X25519 and ML-KEM material:

```text
data_ikm = LD(X25519(server_data_private, client_data_x25519_public)) ||
           LD(MLKEM768_encapsulation_secret_to_client_data_public)
```

The server first creates:

```text
ServerHelloHeader = Encode(
  version, suite, prekey_id, bundle_generation, bundle_digest,
  server_nonce, handshake_id,
  server_data_x25519_public, data_mlkem768_ciphertext
)
```

`server_hello_prk`, derived from the ClientHello transcript and this public
header, provides the ServerHello body AEAD key and nonce. Optional server
parameters reside in that encrypted body. The server then signs:

```text
H(Encode("ewp/v3/server-hello-signature", T_client_hello,
         ServerHelloHeader, server_hello_ciphertext))
```

under the pinned Ed25519 identity and sends the header, ciphertext, and
signature. This ordering permits the client to derive the body AEAD key from
the public data-plane shares before the complete ServerHello transcript exists.

The client verifies the prekey bundle, bundle generation/digest, ServerHello
signature, prekey ID, nonces, and canonical transcript before processing
data-plane keys.

### 6. Finished confirmation

`handshake_id` is a fresh random 128-bit server value. The server stores a
pending handshake record keyed by it, bound to source, prekey claim, transcript
hash, and expiry. The pending-state store is shared or transport-affine; UDP
Finished processing must never trial-decrypt across pending handshakes.

ClientFinished and ServerFinished use distinct handshake traffic keys and
Finished verification keys. Their exact wire shape is:

```text
ClientFinished = Encode(
  version, suite, handshake_id,
  AEAD(client_finished_key, client_finished_nonce,
       AAD = Encode("ewp/v3/client-finished-aad", version, suite,
                    server_id, deployment_scope, handshake_id, T_server_hello),
       Plaintext = client_verify_data)
)

client_verify_data = HMAC-SHA-256(
  client_finished_verify_key,
  Encode("ewp/v3/client-finished-verify", T_server_hello))
```

The clear `handshake_id` is only a selector and is authenticated as AAD. The
server performs an O(1) pending-state lookup, validates the source binding,
AEAD, and `client_verify_data`, then atomically compares and transitions
`ServerHelloSent -> ClientFinishedVerified`. Only the winning compare-and-swap
may dispatch a handler. A duplicate valid Finished receives the cached
ServerFinished and never dispatches a second handler.

```text
ServerFinished = Encode(
  version, suite, handshake_id,
  AEAD(server_finished_key, server_finished_nonce,
       AAD = Encode("ewp/v3/server-finished-aad", version, suite,
                    server_id, deployment_scope, handshake_id,
                    T_client_finished),
       Plaintext = server_verify_data)
)

server_verify_data = HMAC-SHA-256(
  server_finished_verify_key,
  Encode("ewp/v3/server-finished-verify", T_client_finished))
```

A Finished verification value is computed over the preceding transcript only;
the complete Finished wire message is hashed afterward. It never verifies a
transcript containing itself.

The server state machine is:

```text
Init -> RetrySent -> ClaimedAndPrekeyBurned -> ServerHelloSent
     -> PendingFinishedStored -> ClientFinishedVerified
     -> ServerFinishedSent -> Established
```

The server MUST NOT invoke a TCP/UDP handler, open an upstream connection,
allocate UDP sub-session state, or accept application records before
ClientFinished verifies. The client MUST NOT send application records before
ServerFinished verifies.

## Key Schedule

Let `H` be SHA-256, `LD(x)` be a length-delimited byte string, and `T_n` be
the canonical transcript hash through message `n`.

```text
credential_prk = HKDF-Extract(
  H(Encode("ewp/v3/credential-salt", version, suite, server_id, deployment_scope)),
  K_auth)

T_init = H(Encode("ewp/v3/init", ClientInitBase))

outer_prk = HKDF-Extract(
  H(Encode("ewp/v3/outer-salt", T_init, bundle_digest,
           ClientHelloCoreHeader)),
  LD(outer_ikm) || LD(credential_prk))

T_client_hello = H(Encode("ewp/v3/client-hello", ClientInit, HelloRetry,
                           ClientHelloCore, admission_tag))

server_hello_prk = HKDF-Extract(
  H(Encode("ewp/v3/server-hello-salt", T_client_hello,
           ServerHelloHeader)),
  LD(outer_prk) || LD(data_ikm) || LD(credential_prk))

T_server_hello = H(Encode("ewp/v3/server-hello", T_client_hello,
                           ServerHello))

handshake_prk = HKDF-Extract(
  H(Encode("ewp/v3/handshake-salt", T_server_hello)),
  LD(outer_prk) || LD(data_ikm) || LD(credential_prk))

T_client_finished = H(Encode("ewp/v3/client-finished", T_server_hello,
                              ClientFinished))

T_server_finished = H(Encode("ewp/v3/server-finished", T_client_finished,
                              ServerFinished))

master_prk = HKDF-Extract(
  H(Encode("ewp/v3/master-salt", T_server_finished)),
  handshake_prk)
```

HKDF-Expand labels derive separate values for:

- ClientHello AEAD key and nonce;
- ServerHello AEAD key and nonce;
- client and server Finished traffic keys, nonces, and verification keys;
- `traffic/c2s/key`, `traffic/s2c/key`;
- `traffic/c2s/nonce-prefix`, `traffic/s2c/nonce-prefix`;
- session ID; and
- directional key-update secrets by epoch.

Every expand info contains the version, suite, server ID, scope, transcript
hash, role, direction, and epoch. All temporary byte secrets are cleared after
their successor stage derives successfully. Key updates provide backward
secrecy for prior epochs, not post-compromise recovery.

The exact expand input is:

```text
Info(label, transcript_hash, sender_role, receiver_role, direction, epoch) =
  Encode("ewp/v3/expand", label, version, suite, server_id,
         deployment_scope, transcript_hash, sender_role, receiver_role,
         direction, epoch)
```

`bundle_digest` is the SHA-256 digest of the complete canonical signed
PreKeyBundle. `T_client_hello` binds the bundle digest, ClientHello public
shares, admission tag, and ciphertext; `T_server_hello` additionally binds
the ServerHello header, ciphertext, signature, data-plane public shares, and
handshake ID. No unnamed public-key aggregate is an input to the KDF.

## Admission And Resource Controls

Every v3 listener requires configured limits. Defaults must be finite:

- maximum concurrent ClientInit and ClientHello processing;
- per-source token buckets before retry and before cookie verification;
- per-principal token buckets after route-tag lookup;
- a semaphore for concurrent X25519/ML-KEM operations;
- maximum users, prekey claims, message sizes, and buffered handshake bytes;
- per-stage deadlines for retry, ClientHello, ServerHello, and Finished.

Every v3 MessageTransport must either implement context-aware read/write or
guarantee that `Close` interrupts an in-flight read and write. A transport that
cannot meet that cancellation contract is rejected by the production listener.

The prekey provider, shared ClaimAndBurn store, and admission controller are
mandatory production dependencies. Test-only constructors may provide in-memory
implementations but cannot be selected implicitly by a production constructor.

## Production API Shape

```go
type V3ListenerContext struct {
    Version         uint16
    Suite           SuiteID
    ServerID        string
    DeploymentScope string
}

type PreKeyProvider interface {
    CurrentBundles(ctx context.Context, listener V3ListenerContext) ([]PreKeyBundle, error)
    ClaimAndBurn(ctx context.Context, listener V3ListenerContext, claim PreKeyClaim) (ConsumedPreKey, error)
}

type PendingHandshakeStore interface {
    Put(ctx context.Context, pending PendingHandshake) error
    Load(ctx context.Context, handshakeID [16]byte, source SourceBinding) (PendingHandshake, error)
    CompleteClientFinished(ctx context.Context, handshakeID [16]byte, finishedDigest [32]byte) (won bool, cached ServerFinished, err error)
}

type AdmissionController interface {
    AllowInit(source SourceBinding) bool
    AllowClientHello(source SourceBinding, principal PrincipalID) bool
    AcquireKEM(ctx context.Context) (release func(), err error)
}

func NewServiceV3(
    handler Handler,
    listener V3ListenerContext,
    identity ServerSigningIdentity,
    prekeys PreKeyProvider,
    pending PendingHandshakeStore,
    admission AdmissionController,
) (*ServiceV3, error)

func NewClientV3(
    credential ClientCredential,
    serverIdentity Ed25519PublicKey,
    bundles PreKeyResolver,
) (*ClientV3, error)
```

There is no `SetReplayCache(nil)` equivalent for v3. A service with missing
identity, immutable listener context, prekey/claim store, pending-handshake
store, or admission controller fails to start.

## Error Behavior

After ClientHello, cookie failure, unknown route tag, bad admission tag, replay,
prekey conflict, outer decrypt failure, invalid ServerHello, and bad Finished
produce the same observable result: a bounded terminal close without a
semantic alert. Internal logs and metrics may retain categorized reason codes.

## Migration And Legacy Containment

1. v3 runs on a separate ALPN, SNI/path, port, or listener from v2.2.
2. Clients receive a new Ed25519 pin, `K_auth`, and signed prekey resolver.
3. v2.2 is retained only during a named migration window with explicit risk
   acceptance for its unresolved handshake findings.
4. Legacy v2 and v2.1 constructors are hard-disabled in production builds.
   An explicitly named unsafe build tag may expose them only for migration or
   test fixtures.
5. No endpoint performs version sniffing followed by a fallback attempt.

## Limits Of A One-Pass Handshake

A one-pass ClientHello followed immediately by handler dispatch cannot prove
that the client owns the derived traffic key before side effects. It also cannot
provide metadata forward secrecy against later static-key compromise when it
encrypts directly to a reused static encryption key. Client Finished and either
one-time server prekeys or a prior authenticated server flight are mandatory
for these properties.

## Verification Requirements

Implementation is incomplete until it has:

- deterministic KATs for canonical encodings, cookies, signatures, KDF stages,
  Finished values, and key updates;
- a separate v3 interoperability implementation or differential codec tests;
- fuzzing for every v3 decoder and state transition;
- shared-store race, restart, multi-instance, and outage tests;
- tests proving no handler invocation before ClientFinished;
- tests proving no asymmetric work on invalid cookie/admission traffic;
- prekey double-claim, destruction, expiration, and rollback tests;
- transcript mutation tests for every field and role/direction/epoch label;
- full normal, shuffle, coverage, and race verification with a CGo compiler.
