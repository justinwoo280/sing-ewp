# EWP/v2.2 Record Specification

EWP/v2.2 is an incompatible successor to the v2.1 data-plane record format.
It keeps the hybrid handshake shape but uses distinct v2.2 outer-handshake and
session-key labels. A v2.1 peer therefore rejects a v2.2 handshake at
authentication; implementations MUST NOT retry another revision on the same
connection.

In this specification, `ClientHello` and `ServerHello` always mean the EWP
protocol messages. They are not the `TLS ClientHello` and `TLS ServerHello` of
an optional outer TLS transport. TLS may carry EWP and hide EWP metadata from
the outer observer, but EWP authentication and key derivation remain active.

## Record Layout

Each `MessageTransport` message is exactly one record:

```text
RecordLen(4) || AEAD(
    Counter(8) || FrameType(1) || MetaLen(2) || PayloadLen(4) ||
    Metadata || Payload || RandomPadding
)
```

`RecordLen` is a big-endian unsigned length of the following ciphertext. It is
the only cleartext field and is supplied as AEAD additional authenticated data.
`MaxV22RecordSize` bounds the complete transmitted message, including
`RecordLen`.

The AEAD is ChaCha20-Poly1305. Its nonce is the direction-specific 4-byte
prefix followed by the receiver's expected 64-bit counter. The encrypted
counter must equal that expected value. A sender or receiver MUST reject the
counter-exhausted value and rekey before it is reached.

## Sender Rules

1. Validate the frame type, metadata length, padding length, and total record
   bound.
2. Choose an encrypted padding length that brings the complete visible record
   length onto a configured coarse bucket. Random bucket-up and in-bucket
   jitter are permitted only when they remain within the record and padding
   bounds.
3. Fill `RandomPadding` with `crypto/rand` bytes.
4. Encode all inner fields, seal with `RecordLen` as AAD, send exactly the
   outer length plus ciphertext, then increment the counter.

Application frames and cover frames use the same bucket planner. No visible
type, counter, metadata length, payload length, or padding length is allowed.

## Receiver Rules

1. Read exactly four outer-length bytes and reject records outside the v2.2
   bound before allocation.
2. Read exactly `RecordLen` ciphertext bytes.
3. Construct the nonce from the local expected counter, authenticate using the
   original outer-length bytes as AAD, and reject failed authentication.
4. Validate the encrypted counter, type, metadata length, payload length, and
   exact inner consumption. Remaining decrypted bytes are authenticated
   padding and must not exceed `MaxFramePad`.
5. Increment the counter only after all validation succeeds.

Any decode, length, counter, or trailing-message error is terminal for the
stream. A v2.2 receiver must never try the v2.1 clear-header codec after a
v2.2 failure.

## Version Boundary

Use `NewClientV22` and `NewServiceV22` for high-level connections, or the
explicit v2.2 handshake and stream constructors for low-level integrations.
The v2.2 key schedule uses labels beginning with `ewp/v2.2`; v2.2 session keys
are rejected by legacy `NewClientSecureStream` and
`NewServerSecureStream` constructors.

Deployments must coordinate the cutover or route v2.1 and v2.2 to separate
endpoints. There is no negotiation and no downgrade fallback.

## Scope And Limits

This revision hides the exact data-plane frame structure behind a padded,
authenticated outer record length. It does not by itself provide distributed
replay protection, ClientHello metadata forward secrecy, a Finished exchange,
pre-authentication DoS resistance, or post-compromise recovery. Those remain
separate remediation work.
