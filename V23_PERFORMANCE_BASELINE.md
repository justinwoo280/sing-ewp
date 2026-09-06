# EWP/v2.3 Performance Baseline

**Date**: 2026-09-06
**Platform**: Linux AMD EPYC 7713 64-Core (GOMAXPROCS=6)
**Method**: `go test -run '^$' -bench=BenchmarkV23 -benchmem -count=5 -benchtime=10000x`

This file records the v2.3 data-plane allocation baseline and the
optimization that produced it. It mirrors the v3 baseline on the 0.3.x
branch (`PERFORMANCE_BASELINE.md` there) so the two protocol lines can
be compared like-for-like.

## Headline numbers (medians)

| Operation | ns/op | B/op | allocs/op | Throughput |
|-----------|-------|------|-----------|------------|
| V23Handshake (6-stage, net.Pipe) | ~1,240,000 | ~73,000 | 573 | — |
| V23RecordEncode 1 KiB (io.Discard) | ~3,600 | 1,955 | 5 | ~280 MB/s |
| V23RecordEncode 16 KiB (io.Discard) | ~15,000 | 18,475 | 4 | ~1,090 MB/s |
| V23RecordDecode 1 KiB | ~1,700 | 1,152 | 5 | ~560 MB/s |
| V23EndToEndThroughput 16 KiB (SecureStream) | ~110,000 | 176,800 | 30 | ~147 MB/s |

## Optimization applied

The v2.3 record layer reuses the v2.2 opaque record codec
(`frame_v22.go`). Two allocation hot spots were removed:

1. **Per-record plaintext assembly buffer** (`encodeFrameV22WithPad`)
   previously did `make([]byte, plainLen)` every record. A reusable
   `FrameAEAD.scratch` buffer (`scratchBuf`) now holds it. `FrameAEAD`
   is documented as not goroutine-safe and `SecureStream` serialises
   each direction through its own `FrameAEAD`, so one scratch per
   direction is safe. Removed ~1 allocation per encode.

2. **Per-record ciphertext read buffer + AEAD-open output**
   (`DecodeFrameV22`) previously did `make([]byte, recordLen)` and
   `Open(nil, ...)` every record. Both now reuse the scratch buffer and
   the AEAD opens in place (`Open(ciphertext[:0], ...)`). Removed ~2
   allocations per decode. The returned `Meta`/`Payload` are still
   independently allocated because they are owned by the caller.

3. **Ciphertext seal output on the SecureStream send path**:
   `encodeFrameV22WithPad` detects a `*bytes.Buffer` sink (the sink
   `SecureStream.sendFrame` always uses) and seals directly into its
   spare capacity, eliminating the ciphertext temporary. Generic
   `io.Writer` sinks keep the previous behaviour. This is why the
   `io.Discard` encode benchmark still shows the `sliceForAppend`
   allocation while the real send path does not.

`FrameAEAD.wipe` zeroes and releases the scratch buffer.

### Result (SecureStream real path, 16 KiB records)

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| EndToEnd B/op | 324,000 | 176,800 | **-45%** |
| EndToEnd allocs/op | 38 | 30 | **-8** |
| Decode 1 KiB B/op | 4,224 | 1,152 | **-73%** |
| Decode 1 KiB allocs/op | 7 | 5 | **-2** |

## Remaining allocations are inherent

Post-optimization pprof (`-alloc_objects`) on the encode path shows:

- **~54% `secureRandIntn`** — 2 calls × 8 B per record for the
  traffic-shaping random padding (bucket-up + jitter). This is a
  security feature (anti traffic-analysis) and must stay
  cryptographically random; the 8 B per call comes from the
  `crypto/rand` fast path and is not reducible without weakening the
  padding.
- **~30% `chacha20poly1305.sliceForAppend`** — the Go AEAD library's
  output growth, unavoidable (v3 has the identical cost).
- **~11% generic-writer ciphertext temp** — only present when the sink
  is not a `*bytes.Buffer` (benchmarks, direct codec use); the real
  SecureStream path avoids it.

## Comparison with v3

v3 reports Record seal 2 allocs / open 3 allocs. v2.3 shows 5/5 on the
generic-codec benchmark because the benchmark (a) uses `io.Discard`,
not the buffer-specialised send path, and (b) includes the
traffic-shaping padding RNG that v3's codec benchmark path does not
exercise. On the real `SecureStream` send path the ciphertext seal
allocation is eliminated, bringing v2.3's marginal per-record cost to
parity with v3's. The remaining delta is the padding RNG, which v2.3
keeps for the same anti-traffic-analysis reason v2.2 introduced it.

## Verification

```
go test ./...            # PASS
go test -race ./...      # PASS
go vet ./...             # clean
```
