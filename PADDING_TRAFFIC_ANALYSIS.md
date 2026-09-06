# EWP v2.2/v2.3 Padding — Traffic-Analysis Strength

Measured strength of the padding policy (`padding_policy.go`, shared by v2.2
and v2.3) against a passive size-only observer. Numbers are from a Monte-Carlo
evaluation over thousands of (payload, wire) samples; see "Reproduce" below.

## Threat model

A passive observer sees only the sequence of **wire frame sizes** (no content,
no timing). For a set of candidate plaintext sizes they try to recover the
plaintext size from the wire size. The policy's goal is to degrade that
recovery, destroying the TLS-in-TLS length fingerprint.

## Policy under test

- **Bucket ladder** anchored to TLS record sizes: `[256, 512, 1024, 1500,
  2048, 4096, 8192, 12288, 16384]`.
- **Bucket-up (45%)**: pad to the *next larger* bucket instead of the smallest
  fitting one, breaking payload→wire monotonicity.
- **Jitter (0–64 B)**: uniform random extra inside the chosen bucket, so wire
  sizes do not land on discrete bucket boundaries.
- All randomness from `crypto/rand` (rejection-sampled, no modulo bias).

## Results

### Global correlation (uniform payload sweep 1 B..16 KiB, N=4000)

| Policy | Spearman ρ | NMI | bucket-recovery accuracy |
|--------|-----------|-----|--------------------------|
| no padding | 1.000 | 1.000 | 100% (fully leaked) |
| **full (current)** | 0.952 | **0.49** | **27%** |
| without bucket-up | 0.954 | 0.52 | 27% |
| **without jitter** | 0.975 | **0.98** | **95% (broken)** |

(bucket-recovery accuracy = fraction of samples where the attacker's modal
bucket estimate from the wire size equals the true payload bucket; ~9 buckets
→ random baseline ≈ 11%.)

### Two-point discrimination (website-fingerprint style, Bayes accuracy)

Given a wire size, can the attacker tell payload A from payload B?
50% = pure guessing (safe), 100% = certain identification (broken).

| Payload pair | Accuracy |
|--------------|----------|
| 256 B vs 512 B (adjacent buckets) | ~77% |
| 512 B vs 1024 B (adjacent) | ~77% |
| 1024 B vs 1500 B (adjacent) | ~78% |
| 1024 B vs 4096 B (far apart) | **100%** |
| 2048 B vs 8192 B (far apart) | **100%** |
| 4096 B vs 16384 B (far apart) | **100%** |

## Interpretation

1. **Jitter is the load-bearing defence, not bucket-up.** Removing jitter
   collapses NMI from 0.49 to 0.98 and bucket-recovery from 27% to 95% —
   nearly no protection. The discrete bucket boundary is the fatal fingerprint;
   jitter is what smears sizes across a continuous range. (The code comments
   credit bucket-up for the rank collapse; measurement shows jitter does the
   heavy lifting.)

2. **Bucket-up contributes little in this metric** (NMI 0.49 vs 0.52 without
   it). Jitter already breaks rank order, so the extra bucket-up perturbation
   at bucket edges is marginal. It is cheap to keep, but it is not the
   primary defence.

3. **Spearman ρ stays high (~0.95) by design.** Buckets are monotonic, so
   larger payloads tend to produce larger wire sizes. That residual rank
   correlation does not by itself leak the payload, because precise bucket
   recovery — the attacker's actual goal — is destroyed by jitter.

4. **Adjacent-bucket confusion works (~77%).** Sizes within one or two
   buckets overlap under jitter, so fine-grained size differences are
   partially hidden.

5. **Far-apart sizes are NOT hidden (100%).** A 1 KiB record pads to at most
   ~1.1 KiB and a 4 KiB record to at least 4 KiB, so their wire distributions
   never overlap — coarse content-size fingerprinting (small page vs large
   page) is fully possible.

## What this policy does and does not protect

**Protects against:**
- Fine-grained record-size fingerprinting (exact TLS record sizes).
- Inner-TLS handshake record-sequence fingerprinting (the handshake-phase
  ladder reshapes the opening frames into a TLS-1.3-like silhouette).
- Discrete wire-size histogram spikes (jitter).

**Does NOT protect against:**
- Coarse content-size fingerprinting across distant size classes (small vs
  large resource). Closing that needs constant-bit-rate shaping or aggressive
  cover traffic, at much higher bandwidth cost — out of scope for this
  design.
- Timing / inter-arrival analysis (not modelled).
- Total-volume / session-length analysis (padding adds overhead but does not
  equalise session byte counts).

## Overhead

Bucket-up + jitter add, on average, roughly 30–50% wire bytes on the steady
ladder (more during the 16-frame handshake phase). This is the deliberate
cost of the size-obfuscation above.

## Reproduce

The evaluation was a temporary `go test` harness (Monte-Carlo over
`padToBucket` and two custom variants with bucket-up / jitter disabled) that
printed the tables above. It was removed after the run so the numbers here
are the record of that measurement. To re-run, reconstruct a test that
samples `raw + padToBucket(raw, steadyBuckets)` and computes Spearman ρ
(helper `spearman` in `padding_policy_test.go`), NMI under equal-frequency
binning, and per-bucket recovery accuracy as described.
