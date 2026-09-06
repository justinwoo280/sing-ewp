# EWP/v3 Test Suite

The `0.3.x` branch is v3-only. The test suite does not import or exercise any
v2, v2.1, or v2.2 handshake constructor.

## Layers

- `v3_encoding_test.go`: canonical field ordering, bounds, duplicate fields,
  unknown fields, and stable message bytes.
- `v3_crypto_kat_test.go`: fixed vectors from `testdata/v3_vectors.json` for
  route tags, cookies, admission, replay, Ed25519 bundles, KDF stages,
  Finished values, session keys, and opaque records.
- `v3_state_test.go`: prekey single-use, cookie rotation, admission limits,
  KEM bounds, bundle tombstones, and cookie rotation races.
- `EWP_V3_CARRIER_UOT_DESIGN.md`: carrier ownership, message boundaries, UoT
  scope, dispatcher behavior, and connection-local lifecycle.
- `v3_transcript_test.go`: exact transmitted bytes are retained when optional
  non-critical fields are present, including retry-safe ClientInit padding.
- `v3_rekey_test.go`: directional epoch evolution, counter reset, and stream
  interoperability across key updates.
- `v3_integration_test.go`: Finished gating, byte-stream flows, and direct
  MessageTransport TCP/UDP high-level API flows.
- `v3_transport_test.go`: context-aware carrier cancellation and transport
  method selection.
- `v3_udp_dispatch_test.go`: multiple UDP handlers, per-session receive queues,
  and carrier-level dispatcher shutdown.
- `v3_interop_test.go`: independent external-package HelloRetry and Address
  differential codec checks.
- `v3_uot_test.go`: low-level multi-`globalID` UDP-over-TCP target semantics
  and high-level duplicate-`UDP_NEW` rejection.
- `v3_fuzz_test.go`: bounded bundle, address, record, decoder, and
  handshake-action fuzz targets.
- `v3_bench_test.go`: codec, cheap rejection, and record seal/open benchmarks.
- Allocation benchmarks record the cost of exact-wire ownership copies; they
  must not include cipher initialization or reusable transport setup.

## Required Commands

```text
go test ./...
go vet ./...
go test -race -run '^TestV3' -count=1 ./...
go test -race ./...
go test -run '^$' -bench '^BenchmarkV3' -benchmem ./...
go test -fuzz='^FuzzParseV3ClientInit$' -fuzztime=30s
go test -fuzz='^FuzzParseV3PreKeyBundle$' -fuzztime=30s
go test -fuzz='^FuzzParseV3HelloRetry$' -fuzztime=30s
go test -fuzz='^FuzzParseV3ClientHelloCore$' -fuzztime=30s
go test -fuzz='^FuzzParseV3ClientHello$' -fuzztime=30s
go test -fuzz='^FuzzParseV3ServerHello$' -fuzztime=30s
go test -fuzz='^FuzzParseV3Finished$' -fuzztime=30s
go test -fuzz='^FuzzDecodeV3Record$' -fuzztime=30s
go test -fuzz='^FuzzDecodeV3Address$' -fuzztime=30s
go test -fuzz='^FuzzV3AddressRoundTrip$' -fuzztime=30s
go test -fuzz='^FuzzDecodeV3IPAddr$' -fuzztime=30s
go test -fuzz='^FuzzV3HandshakeActions$' -fuzztime=30s
```

Fuzz commands are intentionally separate because the Go test runner executes
one fuzz target at a time. Fuzzing must be repeated after changes to any v3
decoder or state transition.

## Fixture Rules

Tests use bounded in-memory providers and process-local handshake state.
Production constructors require a prekey provider, admission controller,
pinned Ed25519 identity, and immutable listener context. A carrier or process
restart invalidates in-flight handshake state.

Cryptographic expected values are stored in `testdata/v3_vectors.json`; tests
must not generate their own expected values during execution. Randomness and
time injection is instance-local and must not mutate process-global state.
