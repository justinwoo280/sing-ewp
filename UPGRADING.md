# sing-ewp v0.3.x

`0.3.x` is a clean EWP/v3 package. It has no v2, v2.1, or v2.2 handshake
constructors and performs no version probing or fallback.

The v3 API requires new provisioning:

1. Create and pin a server Ed25519 signing identity.
2. Issue each client a random 32-byte `KAuth` and principal identifier.
3. Publish signed one-time X25519 plus ML-KEM-768 prekey bundles.
4. Provision bounded in-process prekey, replay, and admission state. Do not
   restore burned private prekeys after a process restart.
5. Expose v3 on a dedicated listener, ALPN, path, or port.
6. Run the v3 test and race gates in `TESTING.md`.

Message-oriented carriers should use `DialMessageTransport` or
`DialPacketMessageTransport` on the client and
`HandleMessageTransportWithSource` on the server. They must preserve each EWP
message as one ordered carrier message; no database or persistence layer is
part of the protocol. A carrier failure discards the in-flight
handshake and the client performs a fresh complete handshake; there is no
cross-carrier resume or persistence contract.

The v3 handshake design and migration containment rules are in
`EWP_V3_HANDSHAKE_DESIGN.md`. The opaque application record format is in
`EWP_V3_RECORDS.md`. Carrier and UDP-over-TCP scope is in
`EWP_V3_CARRIER_UOT_DESIGN.md`.
