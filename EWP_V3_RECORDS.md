# EWP/v3 Opaque Application Records

EWP/v3 uses one opaque, authenticated record format after the v3 Finished
exchange. This document specifies only the application record layer; it does
not define or import an earlier revision's handshake.

## Record Layout

Each `MessageTransport` message is exactly one record:

```text
RecordLen(4) || AEAD(
    Counter(8) || FrameType(1) || MetaLen(2) || PayloadLen(4) ||
    Metadata || Payload || RandomPadding
)
```

`RecordLen` is the big-endian length of the following ciphertext. It is the
only cleartext field and is supplied as AEAD additional authenticated data.
The complete transmitted record, including `RecordLen`, is bounded by
`MaxFrameSize`.

The AEAD is ChaCha20-Poly1305. Its nonce is the direction-specific four-byte
prefix followed by the local next 64-bit record counter. The encrypted counter
must equal that expected value.

## UDP Over TCP Sub-Sessions

`SecureStream` carries UDP over the ordered carrier by multiplexing independent
sub-sessions under an eight-byte `globalID`. `UDP_NEW` opens a sub-session and
contains its default target plus an optional first datagram. `UDP_DATA` carries
one datagram; it may include an address for that packet only, or omit the
address to use the sub-session default. `UDP_END` terminates the selected
sub-session. A high-level `net.PacketConn` owns one `globalID`, while direct
`SecureStream` callers may manage several concurrently.

The first datagram sent by a high-level packet adapter uses the address supplied
to that first write when present. The handshake destination remains the
authenticated anchor in the ClientHello metadata and does not overwrite a
per-packet target.

## Sender Rules

1. Validate frame type, metadata length, padding length, and total record size.
2. Select a bounded encrypted padding length using the v3 bucket policy.
3. Fill random padding from the configured cryptographic random source.
4. Seal with the original `RecordLen` bytes as AAD, send exactly one record,
   then increment the direction counter.

Application and cover records use the same opaque format. No visible type,
counter, metadata length, payload length, or padding length is allowed.

## Receiver Rules

1. Read exactly four outer-length bytes and reject out-of-bound lengths before
   allocation.
2. Read exactly `RecordLen` ciphertext bytes.
3. Construct the nonce from the local expected counter and authenticate using
   the original length bytes as AAD.
4. Validate encrypted counter, type, metadata length, payload length, and
   authenticated padding bounds.
5. Increment the counter only after all validation succeeds.

Any decode, length, counter, or trailing-message error is terminal for the
stream. There is no alternate record codec or fallback path.

## Key Updates

`FrameRekeyReq` is encrypted under the current epoch. Its payload is the
eight-byte pre-update counter. After successful delivery the sender derives a
new directional key and nonce prefix under the v3 key-update domain and resets
the counter. The update secret is one-way evolved first; the derivation binds
the listener context, session transcript, sender role, receiver role,
direction, and next epoch. The receiver performs the same transition only
after validating the announcement. Previous key and update-secret objects are
dropped immediately; this provides backward secrecy, not post-compromise
recovery.
