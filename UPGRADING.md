# Upgrading sing-ewp

> **Terminology.** In this document, an unqualified `ClientHello` or
> `ServerHello` means the EWP protocol message. A `TLS ClientHello` or `TLS
> ServerHello` is explicitly labeled as such and belongs to the optional outer
> transport layer.

## EWP/v2.1 -> EWP/v2.2

> **Data-plane wire break.** v2.2 encrypts the frame counter, type, metadata
> length, payload length, and padding inside a bucketized AEAD record. v2.1
> and v2.2 use different outer-handshake, session, and rekey labels, so they
> reject each other before any application handler is invoked. There is no
> negotiation or automatic fallback.

### What changed

| Area | v2.1 | v2.2 |
|---|---|---|
| Visible record fields | Frame length, counter, type, metadata length, padding length | Bucketized ciphertext length only |
| Inner record | `AEAD(metadata || payload)` | `AEAD(counter || type || metadata length || payload length || metadata || payload || random padding)` |
| Session labels | v2.1 / legacy-compatible labels | `ewp/v2.2 ...` labels only |
| High-level API | `NewClientV21` / `NewServiceV21` | `NewClientV22` / `NewServiceV22` |

### Migration

1. Upgrade clients to `NewClientV22(uuid, serverStaticPubB64)`.
2. Upgrade servers to `NewServiceV22(handler, serverStaticPrivB64)`.
3. Coordinate the cutover or use separate endpoints for v2.1 and v2.2.
   A single endpoint must not retry an alternate revision after a failed
   handshake.
4. Keep the same out-of-band pinned static public key provisioning model.
5. Re-run packet-size and traffic-shaping capacity tests for your transport;
   `MaxV22RecordSize` limits the complete EWP record to 64 KiB.

See `EWP_V22.md` for the normative record layout and
`SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md` for remaining security
limitations. v2.2 mitigates exact data-plane length exposure, but it does not
by itself add a Finished exchange, shared replay store, ClientHello metadata
forward secrecy, or pre-authentication DoS protection.

## v0.1.x → v0.2.0  (EWP/v2 → EWP/v2.1)

> ⚠️ **Cryptographic break.** v0.2.0 derives every handshake key
> differently from v0.1.x and additionally requires a long-term
> server-side X25519 keypair. Mixed deployments **cannot interoperate**;
> a v0.2.0 server returns `ErrOuterMAC` to every v0.1.x ClientHello,
> and a v0.1.x server cannot decrypt a v0.2.0 ClientHello. Plan a
> synchronized upgrade.

### Why this break exists

v0.1.x derived the handshake AEAD key and outer MAC key purely from
the user UUID (= PSK). This made two practical attacks possible:

- **Offline decryption (S1).** Anyone who ever held the UUID could
  later, without observing the handshake live, decrypt every recorded
  `ClientHello` and recover its inner contents (timestamp, command,
  destination address, padding).
- **Server impersonation (S2).** Any holder of the UUID could complete
  a handshake from the server side; there was no notion of "server
  identity" to bind against.

v0.2.0 requires a pinned long-term server X25519 public key. A UUID holder
without the matching static private key cannot impersonate the server or
decrypt a captured `ClientHello`. This does not provide ClientHello metadata
forward secrecy against a later compromise of both the static private key and
the UUID. It also does not provide deployment-wide replay protection or hide
exact frame payload lengths. See `SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md`
for the remaining deployment constraints.

### What changed on the wire

| Field                                | v0.1.2                       | v0.2.0                       |
|--------------------------------------|------------------------------|------------------------------|
| `ClientHello` byte layout            | nonce ‖ classical ‖ pq ‖ ctLen ‖ inner ‖ MAC | **identical** |
| `ServerHello` byte layout            | nonce ‖ classical ‖ pqCipher ‖ time ‖ status ‖ MAC | **identical** |
| Handshake-AEAD key derivation        | `HKDF(SHA256(UUID), nonce, "EWPv2 handshake aead")` | `HKDF(staticECDH ‖ SHA256(UUID), salt, "ewp/v2.1 outer aead")` |
| Outer MAC                            | `HMAC(SHA256(UUID), msg)[:16]` | `HMAC(macKey, be64(innerCTLen) ‖ msg)[:16]` where `macKey` is itself derived from `staticECDH` |
| `LengthFramer` prefix length         | 4 bytes big-endian (high 2 bytes always zero) | **3 bytes** big-endian |
| `SessionKeys` size                   | 4 fields                     | adds `SessionID [8]byte`     |

The wire bytes of `ClientHello` and `ServerHello` are arranged
identically; only the keys used to encrypt and authenticate them
differ. This means a v0.1.x packet on the wire is structurally
parseable by a v0.2.0 server, but the outer MAC fails closed.

### What you have to do

1. **Generate a server static keypair (once per deployment).**

   ```go
    privB64, pubB64, err := ewp.GenerateServerStaticKeypair()
    // Persist privB64 directly in a protected server-side secret store.
    // Distribute pubB64 to every authorised client.
   ```

    Do not print the private key to a terminal, CI log, or shell history.

2. **Switch every server constructor to `NewServiceV21`.**

   ```diff
   - svc := ewp.NewService(handler)
   + svc, err := ewp.NewServiceV21(handler, staticPrivB64)
   + if err != nil { return err }
   ```

3. **Switch every client constructor to `NewClientV21`.**

   ```diff
   - cli, err := ewp.NewClient(uuidStr)
   + cli, err := ewp.NewClientV21(uuidStr, serverStaticPubB64)
   ```

4. **Distribute `serverStaticPubB64` to your clients out-of-band**
   (the same channel you already use to provision UUIDs).

5. **Coordinate the cutover.** A mixed deployment surfaces only as
   handshake failures (`ewp/v2.1: accept ClientHello: ewp/v2: outer
   MAC verification failed`). The wire bytes do flow once, but no
   data is exchanged.

6. **Plan replay state deliberately.** The bundled replay cache is
   process-local. Restarting a service or sending the same ClientHello to a
   second instance loses its replay history, so deployments with side-effecting
   handlers need coordinated replay protection outside this package.

7. **Tighten your timestamp budget.** `HandshakeTimestampWindow`
   dropped from 120 s to 30 s. Make sure NTP is running on every host
   that participates in the handshake.

### What you get

- **Server identity binding.** A leaked UUID alone cannot impersonate the
  server to a client that pins the genuine static public key.
- **Data-frame forward secrecy.** The post-handshake data keys use fresh
  ephemeral X25519 and ML-KEM-768 material. This does not extend to recorded
  ClientHello metadata after a static-key compromise.
- **Truncation-resistant outer MAC.** Any byte-length mutation of the
  inner ciphertext is detected.
- **Unlinkable `SessionID`.** Two handshakes from the same user yield
  different session ids; safe for logs.
- **Real anti-replay sharding.** `ReplayCache` admits scale across
  cores; the previous single-mutex design did not.
- **Fewer DPI fingerprints.** The 3-byte length prefix removes the
  always-zero high bytes; the v2.1 KDF salt eliminates correlated
  bits in derived keys.
- **`Rekey()` evolves keys.** Long-lived sessions can rotate a direction's
  key one-way; this gives backward secrecy for prior epochs but not
  post-compromise recovery.

### What can go wrong (and how to spot it)

| Symptom                                                     | Cause                                                    | Fix                                                        |
|-------------------------------------------------------------|----------------------------------------------------------|------------------------------------------------------------|
| `ewp/v2.1: accept ClientHello: outer MAC verification failed` on every connect | Mixed v0.1.x ↔ v0.2.0 deployment                        | Roll v0.2.0 to all peers in the same window                |
| `ewp/v2.1: server_static_priv: invalid server static private key` | Wrong-length scalar in server config                     | Re-generate via `GenerateServerStaticKeypair`              |
| `ewp/v2.1: x25519 keygen` errors on client                  | OS RNG unavailable                                       | Out-of-scope; investigate the host                         |
| `ErrReplay` on the very first handshake                     | Client clock skew > 30 s                                 | Run NTP, or temporarily widen via a future config knob     |
| Tests that asserted on `ErrTimestamp`                       | The sentinel still exists but is no longer returned      | Update assertions to `ErrReplay` (see `v2_test.go`)        |

---

## v0.1.1 → v0.1.2

> ⚠️ **Wire-format break.** Servers and clients running v0.1.2 cannot
> talk to peers still on v0.1.1. Plan a synchronized upgrade.

### What changed on the wire

| Field                          | v0.1.1                       | v0.1.2                       |
|--------------------------------|------------------------------|------------------------------|
| `ClientHello[0:4]`             | plaintext `"EWP2"` magic     | first 4 bytes of nonce       |
| `ServerHello[0:4]`             | plaintext `"EWP2"` magic     | first 4 bytes of `NonceEcho` |
| Total `ClientHello` length     | `4 + (rest)`                 | `(rest)` (4 bytes shorter)   |
| Total `ServerHello` length     | `4 + (rest)`                 | `(rest)` (4 bytes shorter)   |

Everything else — UUID format, AEAD primitive, KDF, frame layout, and
session-key derivation — is **identical**.

### What you have to do

1. **Update both ends to v0.1.2 in the same maintenance window.**
   A mixed deployment will look exactly like a peer with the wrong
   PSK: TLS connects, the handshake bytes flow once, then the server
   closes (it will treat your old `EWP2` bytes as a corrupted nonce
   and the outer MAC fails).
2. **No configuration changes.** UUIDs are unchanged; the option
   schemas in your front-end (e.g. sing-box) are unchanged.
3. **If you wrote your own tests against the magic field**, switch to
   asserting on `ErrOuterMAC` for tampered leading bytes (see
   `TestHandshake_TamperedLeadingBytesRejected`). The exported
   `ErrMagic` sentinel still exists for source-compatibility but the
   decoder no longer returns it.

### What you get

- **No more 4-byte protocol fingerprint at offset 0** of every
  ClientHello — the first 12 bytes are now uniformly random.
- **Replay-of-ClientHello is now `O(1)` to reject** instead of forcing
  the server through a full X25519 + ML-KEM-768 encapsulation.
- **Out-of-window `ServerHello.ServerTime`** now causes the client to
  abort the handshake before doing any decapsulation work.

See `CHANGELOG.md` (English) or `CHANGELOG.zh.md` (中文) for the full
list of changes and the security rationale.

### Optional: keep replay protection enabled (it is, by default)

`NewServiceV21` installs a `ReplayCache(ReplayWindow)` automatically.
You only need to call `SetReplayCache` if you want to:

- Disable it (e.g. in benchmarks where you replay a captured
  handshake on purpose) — pass `nil`.
- Install a cache with a different window or your own GC strategy.

```go
svc, err := ewp.NewServiceV21(handler, serverStaticPrivB64)
if err != nil { return err }
// Default: anti-replay on, window = 60s.

// Override for a high-RTT link with permissive ts-window:
svc.SetReplayCache(ewp.NewReplayCache(5 * time.Minute))

// Disable only in narrowly scoped tests:
svc.SetReplayCache(nil)
```
