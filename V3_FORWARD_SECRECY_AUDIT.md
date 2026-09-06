# EWP/v3 ClientHello Metadata Forward Secrecy Audit

**Date**: 2026-09-05  
**Auditor**: Automated Security Review  
**Focus**: H-05 Remediation — Forward Secrecy for ClientHello Metadata  
**Scope**: `/root/project/sing-ewp`, uncommitted v3 implementation

---

## Executive Summary

✅ **EWP/v3 successfully achieves forward secrecy for ClientHello metadata** through one-time hybrid prekey protection.

### Key Finding

**EWP/v2.x vulnerability (H-05):**
- ClientHello outer encryption uses server's **long-term static X25519** key
- Compromise of static key + UUID allows decryption of **recorded historical metadata** (destination, command, timestamp)

**EWP/v3 remediation:**
- ClientHello outer encryption uses **one-time hybrid prekey** (X25519 + ML-KEM-768)
- Each prekey is used **exactly once** and then **destroyed**
- Historical traffic remains secure even if:
  - Server's signing key is compromised
  - Client credential (KAuth) is leaked
  - Current process memory is disclosed

---

## Forward Secrecy Mechanism

### 1. One-Time Prekey Generation

**Location**: `v3_prekey.go:252-300` (`GenerateV3PreKeyMaterial`)

Each prekey contains:
```go
type V3PreKeyMaterial struct {
    Bundle        V3PreKeyBundle          // Public signed bundle
    X25519Private *ecdh.PrivateKey        // Classical private key
    MLKEMPrivate  *mlkem.DecapsulationKey768  // Post-quantum private key
}
```

**Security properties:**
1. Fresh X25519 + ML-KEM-768 keypairs generated per prekey
2. Signed by server's Ed25519 identity (prevents impersonation)
3. Includes validity window and generation counter
4. Never reused across process restarts (operational requirement)

**Evidence**:
```go
// v3_prekey.go:271-278
xPrivate, err := ecdh.X25519().GenerateKey(runtime.reader())
pqPrivate, err := generateV3MLKEM768(runtime.reader())
```

### 2. Client Handshake: Hybrid Encapsulation

**Location**: `v3_handshake.go:116-141`

Client performs:
```go
// 1. Generate ephemeral outer X25519 keypair
outerPrivate, err := ecdh.X25519().GenerateKey(runtime.reader())

// 2. Classical ECDH with prekey
classical, err := outerPrivate.ECDH(prekeyX25519)

// 3. ML-KEM-768 encapsulation
pqShared, outerCiphertext := prekeyMLKEM.Encapsulate()

// 4. Combine into hybrid IKM
outerIKM, err = v3HybridIKM(classical, pqShared)
```

**Critical**: `outerPrivate` is ephemeral and destroyed after use. Neither classical nor pqShared components are retained.

### 3. ClientHello Outer PRK Derivation

**Location**: `v3_kdf.go:160-182` (`deriveV3OuterPRK`)

```go
func deriveV3OuterPRK(
    listener V3ListenerContext,
    credentialPRK [32]byte,   // From KAuth (long-term)
    outerIKM []byte,          // From one-time prekey hybrid exchange
    tInit [32]byte,           // Transcript binding
    bundleDigest BundleDigest,
    clientHelloHeader []byte,
) ([32]byte, error) {
    salt := v3Hash("ewp/v3/outer-salt", tInit[:], bundleDigest[:], clientHelloHeader)
    ikm := v3LengthDelimited(outerIKM, credentialPRK[:])  // Combines ephemeral + credential
    prk := hkdf.Extract(sha256.New, ikm, salt[:])
    // ...
}
```

**Key insight**: `outerPRK` depends on **both** ephemeral `outerIKM` and long-term `credentialPRK`. Even if `credentialPRK` is compromised later, the ephemeral component is unrecoverable.

### 4. ClientHello Metadata Encryption

**Location**: `v3_handshake.go:201-237`

```go
// Derive keys from outerPRK
keyBytes := v3Expand(outerPRK[:], "client-hello/key", ...)
nonceBytes := v3Expand(outerPRK[:], "client-hello/nonce", ...)

// Encrypt plaintext metadata
plain := V3ClientHelloPlaintext{
    Command:                command,         // TCP/UDP
    Destination:            destination,     // Target address
    ClientDataX25519Public: dataPublic,     // Ephemeral data-plane key
    ClientDataMLKEMPublic:  ...,
    RandomPadding:          padding,
}
ciphertext := v3Seal(clientHelloKey, clientHelloNonce, aad, plainBytes)
```

**Protected metadata**: destination address, command type, data-plane public keys, padding.

### 5. Server: Atomic Prekey Consumption

**Location**: `v3_prekey.go:529-546` (`ClaimAndBurn`)

```go
func (p *MemoryPreKeyProvider) ClaimAndBurn(ctx, listener, claim) (V3ConsumedPreKey, error) {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Validate claim (replay check, admission, expiry)
    if err := p.validateClaimLocked(...); err != nil {
        return V3ConsumedPreKey{}, err
    }
    
    // Atomically consume prekey
    return p.claimAndBurnLocked(claim)
}
```

**Critical section** (`v3_prekey.go:592-604`):
```go
func (p *MemoryPreKeyProvider) claimAndBurnLocked(claim) (V3ConsumedPreKey, error) {
    material := p.entries[claim.PreKeyID]
    delete(p.entries, claim.PreKeyID)      // Remove from available pool
    p.burned[claim.PreKeyID] = struct{}{}  // Mark as consumed forever
    p.claims[claim.ReplayKey] = claim.Expiry  // Record replay claim
    return V3ConsumedPreKey{...}, nil
}
```

**Security guarantee**: Each prekey is consumed **exactly once** under a single mutex. Even if the process restarts, operational rules require fresh bundles, not restoration of burned material.

### 6. Server: Hybrid Decapsulation

**Location**: `v3_handshake.go:593-610`

```go
// Classical ECDH using consumed prekey
classical, err := consumed.X25519Private.ECDH(outerPublic)

// ML-KEM-768 decapsulation
pqShared, err := consumed.MLKEMPrivate.Decapsulate(outerCiphertext)

// Reconstruct hybrid IKM
outerIKM, err = v3HybridIKM(classical, pqShared)
```

After successful handshake, `consumed.Destroy()` is called (`v3_prekey.go:325-331`):
```go
func (m *V3ConsumedPreKey) Destroy() {
    m.X25519Private = nil
    m.MLKEMPrivate = nil
}
```

The private prekey material is dropped and never reused.

---

## Threat Model Analysis

### Scenario 1: Server Signing Key Compromise

**Attacker capability:**
- Obtains server's Ed25519 signing private key
- Has recorded ClientHello traffic

**Cannot decrypt because:**
- Signing key validates bundle authenticity, but does not participate in ECDH/KEM operations
- Prekey private material was destroyed after use
- `outerIKM = ECDH(ephemeral_client, one-time_server) || KEM(ephemeral_ct, one-time_server)`

✅ **Forward secrecy holds**

### Scenario 2: Client Credential (KAuth) Leak

**Attacker capability:**
- Obtains client's KAuth
- Has recorded ClientHello traffic

**Cannot decrypt because:**
- `outerPRK` depends on both `credentialPRK` (from KAuth) and `outerIKM`
- `outerIKM` is ephemeral and unrecoverable without prekey private material
- `outerIKM` components: `ECDH(client_ephemeral, server_one_time)` + `KEM_encap(server_one_time)`

✅ **Forward secrecy holds**

### Scenario 3: Combined Signing Key + KAuth Compromise

**Attacker capability:**
- Both server signing key and client KAuth leaked
- Recorded ClientHello traffic

**Cannot decrypt because:**
- Prekey private halves were destroyed after use
- Client ephemeral `outerPrivate` was destroyed after ClientInit creation
- No material exists to reconstruct `outerIKM = hybrid(classical, pq)`

✅ **Forward secrecy holds**

### Scenario 4: Live Process Memory Disclosure

**Attacker capability:**
- Full read access to running process memory during active handshake

**Can decrypt current handshake:**
- Handshake state holds `outerPRK`, `credentialPRK`, plaintext metadata until handshake completes
- This is expected: forward secrecy protects **historical** traffic, not live sessions

**Cannot decrypt past handshakes:**
- Prior prekey private material already destroyed
- Prior `outerIKM`, `outerPRK` cleared on handshake completion

✅ **Forward secrecy holds for historical traffic**

---

## Key Destruction Lifecycle

### Client Side

**Location**: `v3_handshake.go:76-84` (defer in `startV3ClientHandshakeWithRuntime`)

```go
keepSecrets := false
defer func() {
    if !keepSecrets {
        dataX25519Private = nil
        dataMLKEMPrivate = nil
        outerPrivate = nil       // ← Ephemeral outer key
        zero(outerIKM)           // ← Hybrid shared secret
        zero(credentialPRK[:])
        zero(outerPRK[:])
    }
}()
```

On handshake failure, all intermediate secrets are cleared. On success, only data-plane keys are retained.

**Evidence of proper cleanup**: `v3_handshake.go:141`
```go
outerPrivate = nil  // Dropped before returning state
```

### Server Side

**Location**: `v3_handshake.go:510-521` (defer in `acceptV3ClientHello`)

```go
keepSecrets := false
defer func() {
    if !keepSecrets {
        serverDataPrivate = nil
        zero(credentialPRK[:])
        zero(outerIKM)
        zero(outerPRK[:])
        zero(dataIKM)
        releaseKEM()
    }
}()
```

**Evidence**: Prekey private material is explicitly destroyed via `consumed.Destroy()` after use (`v3_handshake.go:585`).

---

## Verification

### Test Coverage

**Location**: `v3_prekey_test.go`, `v3_handshake_test.go`

1. **Single-use enforcement**: `TestMemoryPreKeyProvider_ClaimAndBurnOnlyOnce`
   - Verifies second claim with same PreKeyID fails with `ErrV3PreKey`

2. **Burned ID rejection**: `TestMemoryPreKeyProvider_BurnedIDRejected`
   - Verifies `Add(material)` fails if PreKeyID was previously burned

3. **Generation lifecycle**: `TestV3PreKeyGenerationAndLifecycle`
   - Verifies fresh bundles are generated
   - Confirms validity windows are respected
   - Checks signature verification

4. **Handshake integration**: `TestV3ClientServerHandshake`
   - Full round-trip with prekey consumption
   - Confirms second handshake requires fresh prekey

### Known-Answer Test

**Location**: `testdata/v3_vectors.json`, `v3_crypto_kat_test.go`

Fixed KAT test verifies:
```go
outerIKM := hybrid(classical_ecdh, pq_kem_shared_secret)
outerPRK := HKDF-Extract(outerIKM || credentialPRK, salt)
clientHelloKey := HKDF-Expand(outerPRK, "client-hello/key", ...)
```

**External oracle**: `testdata/v3_kat_oracle.py` independently verifies these operations with Python cryptography library (see `EXTERNAL_KAT_VERIFICATION.md`).

---

## Comparison: v2.1 vs v3

| Property | v2.1 (H-05 finding) | v3 (remediation) |
|---|---|---|
| **Outer encryption key** | Static server X25519 | One-time hybrid prekey |
| **Key material lifecycle** | Long-term static key | Single-use, destroyed after claim |
| **Hybrid construction** | Static ECDH only | ECDH + ML-KEM-768 |
| **Post-compromise secrecy** | ❌ Historical metadata recoverable | ✅ Historical metadata unrecoverable |
| **Requires** | Server static key + UUID | Prekey private + KAuth + ephemeral |
| **Operational constraint** | Static key persisted | Prekey must not be restored on restart |

### v2.1 Attack Path (from H-05)

```
Attacker has:
  - Static server X25519 private key (compromised later)
  - Client UUID (leaked)
  - Recorded ClientHello wire traffic

Attack:
  1. Extract client ephemeral X25519 public key from ClientHello
  2. Compute ECDH(static_server_private, client_ephemeral_public)
  3. Derive outerKey from ECDH + UUID
  4. Decrypt historical ClientHello metadata (destination, command, etc.)
```

### v3 Defense

```
Attacker has:
  - Server Ed25519 signing key (signs bundles, but not used in ECDH)
  - Client KAuth
  - Recorded ClientHello wire traffic

Cannot attack:
  1. Client ephemeral X25519 public + prekey X25519 public are visible
  2. BUT: Prekey X25519 **private** was destroyed after use
  3. Cannot compute ECDH(prekey_private, client_ephemeral_public)
  4. Cannot decrypt ML-KEM ciphertext without burned private key
  5. outerIKM = hybrid(ecdh_output, kem_shared) is unrecoverable
  6. Even with KAuth, outerPRK depends on unavailable outerIKM
```

---

## Residual Risks

### 1. Operational Compliance

**Risk**: If server operator **restores burned prekey private material** after restart, forward secrecy is violated.

**Mitigation**:
- Documentation (`USAGE.md`, `EWP_V3_HANDSHAKE_DESIGN.md`) explicitly forbids restoration
- `MemoryPreKeyProvider` is process-local by design
- Burned IDs tracked in `p.burned` map to prevent re-add

**Recommendation**: Add CI test that verifies `Add(material)` after simulated restart with same PreKeyID fails.

### 2. Go Runtime Key Erasure

**Risk**: Setting pointer to `nil` does not guarantee zeroization of underlying Go-managed crypto objects (`ecdh.PrivateKey`, `mlkem.DecapsulationKey768`).

**Current state**:
- `Destroy()` methods set pointers to `nil`
- Byte slices are explicitly zeroed with `zero()`
- Best-effort approach given Go memory management

**Documented**: `M-01` remediation status acknowledges Go erasure limits.

### 3. Live Session Compromise

**Risk**: Process memory disclosure **during active handshake** exposes current `outerPRK` and plaintext metadata.

**Expected behavior**: Forward secrecy protects historical traffic, not live sessions. This is consistent with TLS 1.3 and other FS protocols.

### 4. Timing Side Channels

**Observation**: ECDH and ML-KEM operations are not constant-time with respect to prekey consumption order.

**Impact**: Admission and prekey lookup timing may leak whether a PreKeyID exists in the current pool.

**Mitigation**: Cheap checks (cookie, admission tag) run before asymmetric work.

---

## Conformance to Audit Baseline

### H-05 Requirement (from `SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md:213-216`)

> **Required disposition:** either require an authenticated TLS 1.3/ECH outer channel for metadata forward secrecy, or design a new prekey/ephemeral server mechanism. A one-pass ClientHello encrypted directly to a reused long-term static key cannot honestly claim forward secrecy against later static-key compromise.

✅ **v3 satisfies "prekey/ephemeral server mechanism" path**:
- One-time hybrid prekey (X25519 + ML-KEM-768)
- Atomic single-use consumption
- Private material destroyed after claim
- ClientHello metadata encrypted to ephemeral `outerPRK` derived from one-time prekey exchange

### Phase 2 Requirement (from `SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md:393-408`)

Not explicitly in Phase 2 checklist, but implied by H-05 remediation design goal.

✅ **v3 implementation verified against:**
1. ✅ Prekey bundles signed by server identity (prevents impersonation)
2. ✅ Hybrid construction (ECDH + ML-KEM) with length-delimited IKM
3. ✅ Single-use consumption enforced (`ClaimAndBurn` atomic under mutex)
4. ✅ Destroyed after use (`Destroy()` methods, `defer` cleanup)
5. ✅ Operational rule: no restoration after restart (documented, not code-enforced)

---

## Independent Verification

### External KAT Oracle

**File**: `testdata/v3_kat_oracle.py`

Python implementation independently verifies:
```python
# Classical ECDH + ML-KEM shared secret → hybrid IKM
outer_ikm = length_delimited(classical, pq_shared)

# Derive outerPRK
salt = sha256(b"ewp/v3/outer-salt" + tInit + bundle_digest + header)
ikm_combined = length_delimited(outer_ikm, credential_prk)
outer_prk = hmac.new(salt, ikm_combined, sha256).digest()

# Expand ClientHello key
client_hello_key = hkdf_expand(outer_prk, info="client-hello/key", ...)
```

All vectors match Go implementation (see `EXTERNAL_KAT_VERIFICATION.md`).

---

## Conclusion

✅ **EWP/v3 achieves forward secrecy for ClientHello metadata** through one-time hybrid prekey protection.

### Key Security Properties

1. **One-time use**: Each prekey consumed exactly once, atomically, under mutex
2. **Hybrid construction**: X25519 + ML-KEM-768 combined via length-delimited IKM
3. **Ephemeral binding**: `outerPRK` depends on ephemeral `outerIKM` + long-term `credentialPRK`
4. **Destruction**: Private prekey material destroyed after use (best-effort Go erasure)
5. **Operational rule**: No restoration of burned material across restarts

### Threat Resistance

- ✅ Server signing key compromise alone: Cannot decrypt historical ClientHello
- ✅ Client KAuth leak alone: Cannot decrypt without ephemeral prekey exchange
- ✅ Combined compromise: Still cannot reconstruct destroyed `outerIKM`
- ⚠️ Live process memory: Current handshake exposed (expected for FS protocols)

### Recommendations

1. **CI test**: Add explicit test for restart scenario with burned prekey re-add attempt
2. **Documentation**: Already compliant; operational rules clearly stated
3. **Monitoring**: Consider deployment metrics for prekey consumption rate vs generation

### H-05 Status

**Finding H-05 (v2.1 ClientHello metadata not forward secret) is FIXED in v3.**

---

**Audit Trail**:
- `v3_handshake.go:116-141` — Client hybrid encapsulation
- `v3_kdf.go:160-182` — Outer PRK derivation with ephemeral binding
- `v3_prekey.go:592-604` — Atomic single-use consumption
- `v3_prekey.go:325-331` — Private key destruction
- `testdata/v3_kat_oracle.py` — Independent cryptographic verification

**Next**: Full protocol review and deployment approval gate (see `SECURITY_AUDIT_BASELINE_AND_REMEDIATION_PLAN.md` section 5).
