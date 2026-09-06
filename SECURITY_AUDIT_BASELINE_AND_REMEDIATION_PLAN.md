# sing-ewp Security Audit Baseline and Remediation Plan

> Status: **FROZEN AUDIT BASELINE / REMEDIATION REQUIRED**
>
> Baseline date: 2026-09-03
>
> Audited revision: `e71506a`
>
> Scope: `D:\dev\sing-ewp` current working tree. No source files were changed during this audit.
>
> Audit ID: `SA-2026-09-03-E71506A`

This document records the security result reached during the 2026-09-03
audit and defines the implementation plan required before the package can be
described as providing strict confidentiality, replay resistance, and forward
secrecy.

The audit result in the first half is historical evidence. It MUST NOT be
silently rewritten when fixes land. Later reviews should append a dated status
entry and reference the fixing commit, test evidence, and any changed
assumptions.

## 1. Decision

The package is **not approved for a strict-security deployment as-is**.

The v2.1 data-plane construction has a sound cryptographic core under its
stated assumptions: ChaCha20-Poly1305 authenticates frame contents, the
directional counters reject ordinary replay and reordering, and the session
secret combines ephemeral X25519 with ML-KEM-768. Those properties do not
cover the full package security objective because:

- the legacy v2.0 API remains deployable and has UUID-only server
  authentication;
- the current frame header reveals exact application payload length;
- handshake timeout and resource controls are optional rather than enforced;
- ClientHello replay state is process-local and the TCP handler runs before a
  client Finished/key-confirmation step;
- v2.1 protects data frames against later static-key compromise, but not the
  recorded ClientHello metadata;
- key erasure, rekey terminology, KDF transcript binding, and high-level v2.1
  traffic shaping do not match the security claims in the documentation.

No Critical/High finding was found that lets an unauthenticated remote attacker
recover v2.1 application plaintext or forge an authenticated v2.1 data frame
under the assumptions below. The deployment and metadata failures are still
blocking findings for a strict security approval.

## 2. Threat Model and Assumptions

The review considers a passive or active network attacker able to observe,
modify, reorder, truncate, replay, and initiate connections. It also
separately considers:

- an attacker holding a valid UUID/PSK;
- later compromise of the server static private key and UUID store;
- disclosure of the Go process memory;
- multiple service instances, restarts, and cache loss;
- malicious or incorrectly implemented `MessageTransport` and handlers.

### Terminology boundary

Every unqualified `ClientHello` and `ServerHello` reference in this baseline
means the **EWP protocol message**. A `TLS ClientHello` or `TLS ServerHello`
belongs to the optional outer TLS transport and is called out explicitly. The
metadata in H-05, the replay state in H-04, and the Finished requirement in
the remediation plan all concern the EWP handshake layer. TLS may carry EWP
and provide additional outer confidentiality, but it does not replace EWP
authentication, replay protection, or key confirmation.

The following are security assumptions, not guarantees supplied by the
library:

- UUIDs are unpredictable, high-entropy bearer credentials;
- v2.1 clients receive and correctly pin the genuine server static public key;
- X25519, ML-KEM-768, HKDF-SHA-256, HMAC-SHA-256, ChaCha20-Poly1305, and
  `crypto/rand` are secure;
- `MessageTransport` preserves message boundaries and reliable ordering;
- the caller applies access control to destinations and protects configuration
  files and private keys;
- endpoint compromise is outside ordinary network confidentiality, except
  where a finding explicitly evaluates memory disclosure or key retention.

## 3. Frozen Findings Register

Severity meanings: Critical blocks all deployment of the affected path; High
requires remediation before normal internet exposure; Medium requires a tracked
security fix or explicit risk acceptance; Low is a correctness or hardening
gap that can affect the security boundary in combination with other issues.

### C-01: Deployable v2.0 UUID-only protocol

**Severity:** Critical for the legacy path.

**Evidence:** [`kdf.go:89`](kdf.go#L89), [`kdf.go:102`](kdf.go#L102),
[`handshake.go:517`](handshake.go#L517), [`client.go:31`](client.go#L31),
[`server.go:77`](server.go#L77).

The v2.0 handshake derives its handshake AEAD and outer MAC solely from the
UUID-derived PSK. A party that obtains the UUID can decrypt recorded
ClientHello metadata and generate a valid ServerHello, allowing server
impersonation and a full MITM. `NewClient` and `NewService` remain public, and
[`USAGE.md:50`](USAGE.md#L50), [`USAGE.md:76`](USAGE.md#L76), and
[`USAGE.md:183`](USAGE.md#L183) still demonstrate them.

**Required disposition:** remove or hard-disable the v2.0 constructors and
low-level path, or require a separately authenticated outer channel with an
explicit documented risk acceptance. No automatic fallback is permitted.

### H-01: Exact application payload length is observable

**Severity:** High for metadata confidentiality and traffic analysis.

**Evidence:** [`frame.go:45`](frame.go#L45), [`frame.go:149`](frame.go#L149),
[`frame.go:215`](frame.go#L215), [`frame.go:230`](frame.go#L230).

`FrameLen`, `MetaLen`, and `PadLen` are sent outside the AEAD. Since
`FrameLen` excludes its own four-byte field, an observer can calculate:

```text
payload_length = FrameLen - 13 - PadLen - 16 - MetaLen
```

This recovers the exact plaintext payload length despite the bucket and jitter
policy. Frame type, counter, and broad UDP/control traffic classification are
also visible. AEAD still protects content, but the documented length-hiding
property is not present.

**Required disposition:** make this a wire-format redesign. Moving only one
field or changing the random distribution is insufficient. The encrypted
inner record must carry type, metadata length, payload length, and authenticated
padding; the visible outer record may expose only a coarse padded bucket.

### H-02: No mandatory handshake timeout or cancellation path

**Severity:** High availability risk on exposed listeners.

**Evidence:** [`server.go:219`](server.go#L219),
[`client_v21.go:303`](client_v21.go#L303), [`client.go:345`](client.go#L345),
[`client.go:356`](client.go#L356).

The implementation applies a deadline only when the supplied context already
has one. A canceled context without a deadline does not interrupt
`ReadMessage`. An attacker can send a valid three-byte length prefix and then
stall while retaining a goroutine and an allocated buffer of up to
`MaxFrameSize`.

**Required disposition:** enforce a finite handshake deadline by default,
interrupt reads when the context is canceled, bound concurrent handshakes, and
apply per-source and global admission limits. The same contract must hold for
custom message transports that do not implement `SetDeadline`.

### H-03: v2.1 performs work before authenticating the UUID

**Severity:** High availability risk without upstream rate limiting.

**Evidence:** [`handshake_v21.go:452`](handshake_v21.go#L452),
[`handshake_v21.go:471`](handshake_v21.go#L471),
[`handshake_v21.go:642`](handshake_v21.go#L642).

For a structurally valid ClientHello, the server computes static X25519 before
UUID verification and then performs a linear candidate scan with HKDF/HMAC.
Unknown UUID requests therefore cost one asymmetric operation plus work that
grows with the configured user count. Replays also perform the static ECDH,
lookup, and inner AEAD before the cache check at
[`handshake_v21.go:537`](handshake_v21.go#L537).

**Required disposition:** add a stateless anti-DoS cookie or equivalent
pre-admission proof, rate-limit before asymmetric work, cap the user table, and
measure worst-case cost at the supported user count. Do not claim that all
unauthenticated requests are rejected before asymmetric work under the current
wire design.

### H-04: ClientHello anti-replay is not deployment-wide

**Severity:** High when services restart or use more than one instance.

**Evidence:** [`handshake.go:227`](handshake.go#L227),
[`anti_replay.go:80`](anti_replay.go#L80),
[`server.go:235`](server.go#L235),
[`UPGRADING.md:97`](UPGRADING.md#L97).

The default high-level cache is in-process. The low-level API can disable it,
and restarting or routing the same captured ClientHello to another instance
loses the seen set. The TCP handler is invoked after ServerHello is sent and
before the client proves possession of the derived traffic key. A captured
ClientHello can therefore trigger a duplicate outbound connection or other
handler side effect when cache state is absent.

**Required disposition:** use an atomic shared replay store or a coordinated
deployment-level replay service, include server identity and protocol version
in the key, and add a client Finished/key-confirmation message. Do not dispatch
state-changing handlers until the confirmation succeeds. Production APIs must
not make replay protection silently optional.

### H-05: v2.1 does not provide forward secrecy for ClientHello metadata

**Severity:** High when destination and handshake metadata require long-term
forward secrecy.

**Evidence:** [`handshake_v21.go:85`](handshake_v21.go#L85),
[`handshake_v21.go:284`](handshake_v21.go#L284),
[`kdf.go:143`](kdf.go#L143).

The outer ClientHello key uses the server's long-term static X25519 share and
the UUID. A later compromise of the static private key together with the UUID
lets an attacker derive the outer key from a recorded client ephemeral public
key and decrypt the historical timestamp, command, destination, and padding.
The post-handshake data keys still use ephemeral X25519 plus ML-KEM-768 and are
not recoverable from the static key alone.

**Required disposition:** either require an authenticated TLS 1.3/ECH outer
channel for metadata forward secrecy, or design a new prekey/ephemeral server
mechanism. A one-pass ClientHello encrypted directly to a reused long-term
static key cannot honestly claim forward secrecy against later static-key
compromise.

### M-01: Key lifecycle and Rekey claims exceed the implementation

**Severity:** Medium under a process-memory disclosure model.

**Evidence:** [`frame.go:81`](frame.go#L81),
[`securestream.go:310`](securestream.go#L310),
[`securestream.go:324`](securestream.go#L324),
[`securestream.go:472`](securestream.go#L472),
[`handshake_v21.go:788`](handshake_v21.go#L788).

`FrameAEAD` retains raw key material; `SecureStream.Close` closes the
transport but does not wipe or drop the AEAD contexts. Rekey retains the prior
send key and derives all future keys from the current key without fresh
entropy. The exported test accessors expose current and prior send keys. The
handshake only clears intermediate byte slices and sets opaque private-key
pointers to `nil`; this is not guaranteed zeroization of the underlying
`ecdh.PrivateKey` or ML-KEM object.

**Required disposition:** remove production key getters and obsolete-key
retention, clear byte arrays and references on all success, failure, and close
paths, and document Go memory erasure as best-effort unless secure memory is
introduced. Rename one-way HKDF evolution as such. If post-compromise recovery
is required, use a fresh authenticated ephemeral exchange rather than a
one-way key chain.

### M-02: Replay cache configuration and capacity are unsafe

**Severity:** Medium, conditional on custom configuration or sustained load.

**Evidence:** [`anti_replay.go:95`](anti_replay.go#L95),
[`anti_replay.go:169`](anti_replay.go#L169),
[`anti_replay.go:146`](anti_replay.go#L146),
[`server.go:89`](server.go#L89).

The constructor accepts sub-second windows but truncates to whole seconds. A
window such as `20ms` produces an expiry equal to the current second, so the
same `(UUID, nonce)` can be admitted again immediately. The cache has no hard
capacity limit and all nonces for one UUID use the same shard because only the
first UUID byte selects the shard.

**Required disposition:** reject windows below the timestamp acceptance budget,
use a monotonic or carefully bounded expiry representation, hash the complete
key for sharding, add per-user/global quotas, and make overload behavior
explicit.

### M-03: Session KDF lacks complete v2.1 transcript/domain binding

**Severity:** Medium design and assurance gap; no direct remote key-recovery
path was demonstrated.

**Evidence:** [`kdf.go:143`](kdf.go#L143),
[`kdf.go:162`](kdf.go#L162), [`kdf.go:171`](kdf.go#L171),
[`handshake_v21.go:70`](handshake_v21.go#L70),
[`handshake_v21.go:615`](handshake_v21.go#L615),
[`securestream.go:248`](securestream.go#L248).

The v2.1 outer labels are versioned, but session keys still use legacy
`EWPv2` labels and salt. The declared `v21LabelSessionPrefix` is not used for
session key derivation. Session derivation does not directly bind the full
ClientHello/ServerHello transcript, protocol version, identity, or role. The
server nonce input is only an echo of the client nonce, not an independent
server nonce.

**Required disposition:** define a canonical transcript hash and derive all
handshake, Finished, session, direction, and epoch secrets from explicit
versioned labels and role-separated inputs. Validate the ML-KEM shared-secret
length at the public KDF boundary.

### M-04: Traffic-shape protection is incomplete and inconsistent

**Severity:** Medium metadata confidentiality risk.

**Evidence:** legacy paths install a shaper at
[`client.go:58`](client.go#L58) and [`server.go:261`](server.go#L261), while
the recommended v2.1 paths return unshaped streams at
[`client_v21.go:82`](client_v21.go#L82) and
[`client_v21.go:342`](client_v21.go#L342). Jitter selection uses
[`padding_policy.go:245`](padding_policy.go#L245).

v2.1 high-level TCP paths omit coalescing and cover traffic. The remaining
padding cannot repair the exact length leak in H-01. `math/rand/v2` is not a
security-sensitive random source according to the Go package contract; its use
weakens the unpredictability of observable padding/timing choices.

**Required disposition:** first fix the wire-level length problem, then use a
documented CSPRNG for observable obfuscation and install the same policy on
both v2.1 directions. Treat traffic analysis resistance as probabilistic, not
as content encryption.

### M-05: Concurrency can lose or reorder application data

**Severity:** Medium correctness/integrity risk.

**Evidence:** [`packetconn.go:105`](packetconn.go#L105),
[`packetconn.go:173`](packetconn.go#L173),
[`traffic_shaper.go:162`](traffic_shaper.go#L162).

`packetConn` reads `opened` outside its mutex. Two concurrent first writes can
both report success while only one payload is carried by UDP_NEW. The shaper
extracts buffered data, unlocks, and sends later, allowing overlapping flushes
to acquire the stream write lock out of order.

**Required disposition:** make the open decision and first send atomic, and use
one ordered send queue for all application flushes and cover frames. Add race
and deterministic ordering tests.

### L-01: Protocol and API hardening gaps

**Evidence:** [`securestream.go:397`](securestream.go#L397),
[`frame.go:182`](frame.go#L182),
[`handshake_v21.go:374`](handshake_v21.go#L374),
[`address.go:133`](address.go#L133).

`Recv` does not reject trailing bytes after a decoded frame; counters wrap after
`uint64` exhaustion; `AcceptClientHelloV21` is a compatibility wrapper that
always uses an empty candidate set; and domains accept control characters,
which can become log injection when callers log `Metadata.Destination`.
Mode violations do not consistently close the stream. These are not standalone
v2.1 plaintext-recovery vulnerabilities, but they weaken protocol boundaries.

## 4. Security Property Matrix

| Property | v2.0 result | v2.1 result | Approval condition |
|---|---|---|---|
| Data content confidentiality/integrity | Partial | Partial | Keep AEAD, hide control/length metadata, add boundary tests |
| Server authentication | Fail | Pass with correct pinned static key | Remove legacy path and define provisioning/rotation |
| ClientHello confidentiality | Fail after UUID leak | Partial; fails after static-key + UUID compromise | Use FS outer channel or prekey design |
| Data-frame replay/reorder | Pass on one live stream | Pass on one live stream | Reject overflow and malformed/trailing records |
| ClientHello anti-replay | Partial | Partial | Shared atomic state plus Finished before side effects |
| Forward secrecy | Partial | Partial | Separate data FS, metadata FS, and post-compromise recovery claims |
| KDF/domain separation | Partial | Partial | Transcript, version, role, direction, and epoch binding |

## 5. Remediation Design

### Phase 0: Containment and claim correction

1. Mark `NewClient`, `NewService`, `WriteClientHello`, and the v2.0 accept path
   deprecated-for-removal, disable them in the default production build, and
   add a build/test guard preventing production examples from using them. Any
   temporary migration build must require an explicitly named unsafe build tag.
2. Rewrite `USAGE.md`, configuration examples, `UPGRADING.md`, and the Chinese
   changelog so every deployment example uses v2.1 and requires the static
   public key. Remove instructions that print private keys to stdout.
3. State explicitly that current v2.1 provides data-frame FS only, not
   ClientHello metadata FS or post-compromise recovery.
4. Add mandatory default handshake timeout, connection admission limits, and
   a maximum configured user count before optimizing the protocol.
5. Upgrade Go and `x/*` dependencies to patched versions, then make
   `govulncheck`, `go vet`, and dependency verification CI gates.

### Phase 1: Next wire revision for frame privacy

The current frame layout cannot satisfy strict length confidentiality without
a wire change. The next revision should use the following shape:

```text
outer_record_length || AEAD(
    counter || frame_type || meta_length || payload_length ||
    metadata || payload || authenticated_random_padding
)
```

The receiver uses the expected counter and current epoch to construct the
nonce, authenticates the outer record length as AEAD AAD, decrypts the entire
padded record, validates the embedded counter and lengths, and requires the
record to be consumed exactly. Only a coarse padded outer record length remains
observable. The outer length prefix MUST be bounded and bucketized; it MUST NOT
expose a clear `PadLen` or `MetaLen`.

The revision must have a distinct protocol/domain label and no automatic
fallback to v2.0 or v2.1. Existing peers require a coordinated cutover.

### Phase 2: Handshake authentication, Finished, and replay

1. Define a canonical ClientHello/ServerHello transcript encoding.
2. Derive a handshake-confirmation secret from the hybrid handshake secret and
   transcript hash.
3. Add client Finished and server Finished semantics. The server MUST NOT
   invoke a TCP/UDP handler or open an upstream resource before client
   confirmation.
4. Add an anti-DoS cookie or equivalent stateless admission proof before
   expensive per-user work. Keep per-source and global rate limits outside the
   cryptographic lookup loop.
5. Replace the process-local-only replay contract with an atomic shared store
   interface. The stored replay key should be a server-keyed digest over the
   protocol revision, server identity, UUID, nonce, and deployment scope so the
   cache does not persist raw bearer credentials. TTL and clock-skew behavior
   must be explicit.
6. Keep low-level APIs safe by default: replay protection and timeout behavior
   must not be disabled by a nil argument without an explicit unsafe/test-only
   constructor.

### Phase 3: KDF, key lifecycle, and rekey semantics

1. Use one HKDF-Extract over length-delimited hybrid components, followed by
   explicit versioned labels for outer AEAD, MAC, Finished, session, role,
   direction, and epoch.
2. Bind the transcript hash, both public ephemeral shares, the server identity,
   the UUID authentication context, and the protocol revision to the session
   derivation.
3. Validate all public KDF input lengths, especially the ML-KEM shared secret.
4. Remove `PreviousSendKey` and `CurrentSendKey` from the production API and
   stop retaining obsolete key history.
5. Add a single destruction path that clears byte arrays, drops AEAD
   references, invalidates handshake state, and runs on success, failure,
   transport error, and close. Document the limits of Go GC and opaque crypto
   key types.
6. If only backward secrecy is required, rename the current operation to key
   evolution and state that it cannot recover after current-key compromise.
7. If post-compromise recovery is required, replace it with a fresh
   authenticated ephemeral hybrid exchange per epoch.
8. Enforce a conservative per-key frame/byte limit and refuse counter
   exhaustion before `uint64` wrap.

### Phase 4: State machine and transport correctness

1. Serialize shaper flush ordering and cover traffic through one queue.
2. Make UDP sub-session creation, first-write behavior, close, and end-state
   transitions lock-consistent and race-free.
3. Reject trailing bytes, malformed control payloads, repeated invalid state
   transitions, and mode-inappropriate frames, then close the stream.
4. Validate domain syntax and reject control characters before exposing an
   address to handlers or logs.
5. Define a transport contract that guarantees context cancellation or provide
   a wrapper that closes transports when the context ends.

### Phase 5: Verification and release gates

The implementation is not complete until all gates below pass:

- `go test ./...`, `go test -shuffle=on ./...`, and `go test -race ./...` on a
  supported CGo toolchain;
- fuzz tests for all handshake, address, frame, replay, and rekey decoders;
- fixed KATs and golden wire fixtures for every KDF and wire revision;
- independent implementation or differential interoperability tests;
- frame-privacy tests that prove clear bytes cannot recover exact payload
  length;
- replay tests across process restart, multiple instances, clock movement,
  cache replacement, and concurrent admission;
- timeout/cancellation tests with partial length prefixes and custom transports;
- tests that mutate every transcript field, version label, direction, epoch,
  and Finished message;
- tests for counter exhaustion, rekey failure, close-time key disposal, and
  concurrent UDP first writes;
- `go vet`, `govulncheck`, `go mod verify`, and dependency/license review;
- a reproducible benchmark that does not measure a counter-mismatch fast path
  as successful AEAD decoding.

## 6. Definition of Done

Security approval may be reconsidered only when:

1. C-01 and every High finding are fixed or have a written, signed risk
   acceptance naming the deployment owner and expiry date.
2. The security claims in `README.md`, `USAGE.md`, `UPGRADING.md`, and both
   changelogs match tested behavior.
3. The new protocol revision has no silent fallback and has a documented
   coordinated migration procedure.
4. The property matrix is updated with test evidence, not just implementation
   intent.
5. A fresh review of the fixing diff confirms no new plaintext, nonce reuse,
   replay bypass, key-retention, or downgrade path.

## 7. Verification Record

Results recorded for this frozen baseline:

| Command | Result |
|---|---|
| `go test -count=1 ./...` | Pass |
| v2.1/frame/replay targeted tests, 20 repetitions | Pass |
| high-level client/server/hardening tests, 3 repetitions | Pass |
| `go vet ./...` | Pass |
| `go mod verify` | Pass |
| `go test -shuffle=on -count=3 ./...` | Fail: timing assertion at `audit_fixes_test.go:272` sometimes measures legitimate handshake as `0s` |
| `go test -race ./...` | Not run: local Windows environment lacks CGo/GCC |
| `go test -cover ./...` | Fails on the same flaky H4 test; observed coverage 73.9% |
| `govulncheck@latest ./...` | 0 reachable symbol findings; package/module findings remain for old Go/x/* versions |

Test gaps confirmed at baseline include fuzzing, fixed vectors, third-party
interoperability, restart/multi-instance replay, context cancellation, frame
length privacy, counter exhaustion, and key disposal.

## 8. Change Control

This baseline is frozen at `e71506a`. A remediation commit MUST NOT delete or
rewrite the findings above. It should append a status table with:

- finding ID;
- fixing commit or pull request;
- changed files;
- regression test names and command output;
- residual assumptions and risk acceptance, if any.

Status updates should use this form:

| Date | Finding | State | Fix reference | Verification | Residual risk |
|---|---|---|---|---|---|
| YYYY-MM-DD | C-01 | Open / Mitigated / Fixed / Accepted | commit or PR | commands and tests | explicit statement |

## 9. Remediation Status (2026-09-03)

This status is appended to the frozen baseline. It does not change the audit
decision in section 1: the package is not approved for strict-security
deployment.

| Date | Finding | State | Fix reference | Verification | Residual risk |
|---|---|---|---|---|---|
| 2026-09-03 | C-01 | Open; legacy API deprecated | Working tree: `client.go`, `server.go`, `handshake.go`, docs | `go test ./...` | UUID-only v2.0 remains callable for compatibility and is unsafe for new deployments. |
| 2026-09-03 | H-01 | Mitigated for v2.2; open for v2.1 | `frame_v22.go`, `securestream.go`, `EWP_V22.md` | `TestFrameV22_EqualBucketsHideDifferentPayloadLengths`, v2.2 malformed-record tests | v2.2 exposes only a bucketized record length; legacy and v2.1 clear-header records remain length-leaking during migration. |
| 2026-09-03 | H-02 | Mitigated | `handshake_context.go`, high-level client/service paths | `TestSecurity_HandshakeCancellationClosesTransport` | Default timeout and close-on-cancel exist, but no global or per-source handshake admission limit exists. |
| 2026-09-03 | H-03 | Open | No cookie/rate-limit wire design | `TestFix_H4_NoPSKAttackIsCheap` covers only legacy UUID rejection | v2.2 still performs static ECDH and candidate work before UUID authentication. |
| 2026-09-03 | H-04 | Open | No shared replay store or Finished exchange | Existing replay tests | Replay state remains process-local and handlers run before client key confirmation. |
| 2026-09-03 | H-05 | Open | No prekey or authenticated outer channel | N/A | Recorded ClientHello metadata is recoverable after static-private-key plus UUID compromise. |
| 2026-09-03 | M-01 | Mitigated | `frame.go`, `securestream.go` | `TestSecurity_SecureStreamCloseWipesFrameKeys`, `TestSecurity_SecureStreamSendFailureWipesFrameKeys` | Go erasure is best effort; opaque runtime-managed private keys cannot be guaranteed wiped. |
| 2026-09-03 | M-02 | Mitigated | `anti_replay.go`, `anti_replay_test.go` | `TestReplayCache_ExpiryReadmits`, `TestReplayCache_CapacityReservationIsAtomic` | Global cap is fail-closed; no per-user quota is implemented. |
| 2026-09-03 | M-03 | Open | No transcript-bound KDF revision | v2.2 domain-label tests | v2.2 labels are separated, but session derivation still lacks the required full transcript and role/domain binding. |
| 2026-09-03 | M-04 | Mitigated in high-level paths | `padding_policy.go`, `traffic_shaper.go`, `client_v21.go`, `client_v22.go`, `server.go` | Shaper ordering plus v2.2 padding/record tests | v2.2 hides exact frame structure, but traffic-analysis resistance remains probabilistic. |
| 2026-09-03 | M-05 | Mitigated | `packetconn.go`, `traffic_shaper.go` | UDP first-write, shaper ordering, async-failure, and blocked-close regression tests | The transport still relies on ordered, atomic `MessageTransport` semantics and Close interrupting blocked sends. |
| 2026-09-03 | L-01 | Mitigated in touched paths | `address.go`, `client.go`, `frame.go`, `packetconn.go`, `securestream.go` | Counter, trailing-byte, address, and mode-violation regression tests | The v2.1 compatibility accept wrapper remains intentionally unsuitable for new callers. |

Verification for this working-tree status: `go test ./...`,
`go test -shuffle=on -count=3 ./...`, `go test -cover ./...` (76.0%),
`go vet ./...`, `go mod verify`, and `go test -race ./...` pass. Race testing
uses local WinLibs GCC 16.1.0 with `CGO_ENABLED=1`. Dependency freshness and
`govulncheck` remain blocked by unavailable Go module proxy access.

The non-implemented v3 design for the remaining handshake findings is recorded
in `EWP_V3_HANDSHAKE_DESIGN.md`. It requires a separate implementation and
does not change the states above until its verification requirements pass.

The document may be superseded only by a new dated baseline that links back to
this revision and explains every changed security conclusion.
