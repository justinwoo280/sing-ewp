package ewp

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"sort"
	"sync"
	"time"

	"crypto/mlkem"
)

const (
	v3TagBundleNotBefore uint16 = 41
	v3TagBundleNotAfter  uint16 = 42
	v3TagPreKeyX25519    uint16 = 43
	v3TagPreKeyMLKEM     uint16 = 44
	v3TagBundleSignature uint16 = 45
)

var v3PreKeyBundleTags = v3KnownTags(
	v3TagVersion, v3TagSuite, v3TagServerID, v3TagDeploymentScope,
	v3TagRouteEpoch, v3TagPreKeyID, v3TagBundleGeneration,
	v3TagBundleNotBefore, v3TagBundleNotAfter, v3TagPreKeyX25519,
	v3TagPreKeyMLKEM, v3TagBundleSignature,
)

// V3PreKeyBundle is the signed public description of one one-time hybrid
// prekey. The complete canonical signed bytes are the bundle digest used by
// ClientInit, cookies, replay claims, and the key schedule.
type V3PreKeyBundle struct {
	Version            uint16
	Suite              SuiteID
	ServerID           string
	DeploymentScope    string
	RouteEpoch         uint64
	BundleGeneration   uint64
	PreKeyID           PreKeyID
	NotBefore          uint64
	NotAfter           uint64
	PreKeyX25519Public [X25519PubLen]byte
	PreKeyMLKEMPublic  [MLKEM768PubLen]byte
	Signature          [V3SignatureLen]byte
	rawBytes           string
	rawUnsignedBytes   string
}

func (b V3PreKeyBundle) MarshalUnsigned() ([]byte, error) {
	if b.rawBytes != "" && b.rawUnsignedBytes != "" {
		if parsed, err := ParseV3PreKeyBundle([]byte(b.rawBytes)); err == nil && sameV3PreKeyBundle(parsed, b) {
			return []byte(b.rawUnsignedBytes), nil
		}
	}
	return b.marshalUnsignedCanonical()
}

func (b V3PreKeyBundle) marshalUnsignedCanonical() ([]byte, error) {
	if b.Version != V3ProtocolVersion {
		return nil, ErrV3Version
	}
	if b.Suite != V3SuiteX25519MLKEM768ChaCha20Poly1305 {
		return nil, ErrV3Suite
	}
	if len(b.ServerID) == 0 || len(b.ServerID) > V3MaxServerIDLen || len(b.DeploymentScope) > V3MaxScopeLen {
		return nil, ErrV3Malformed
	}
	if b.PreKeyID.isZero() || b.BundleGeneration == 0 || b.NotAfter <= b.NotBefore {
		return nil, ErrV3PreKey
	}
	var zeroX25519 [X25519PubLen]byte
	var zeroMLKEM [MLKEM768PubLen]byte
	if b.PreKeyX25519Public == zeroX25519 || b.PreKeyMLKEMPublic == zeroMLKEM {
		return nil, ErrV3PreKey
	}
	return encodeV3Fields(
		v3U16(v3TagVersion, b.Version),
		v3U16(v3TagSuite, uint16(b.Suite)),
		v3Bytes(v3TagServerID, []byte(b.ServerID)),
		v3Bytes(v3TagDeploymentScope, []byte(b.DeploymentScope)),
		v3U64(v3TagRouteEpoch, b.RouteEpoch),
		v3Bytes(v3TagPreKeyID, b.PreKeyID[:]),
		v3U64(v3TagBundleGeneration, b.BundleGeneration),
		v3U64(v3TagBundleNotBefore, b.NotBefore),
		v3U64(v3TagBundleNotAfter, b.NotAfter),
		v3Bytes(v3TagPreKeyX25519, b.PreKeyX25519Public[:]),
		v3Bytes(v3TagPreKeyMLKEM, b.PreKeyMLKEMPublic[:]),
	)
}

func (b V3PreKeyBundle) MarshalBinary() ([]byte, error) {
	if _, err := b.marshalUnsignedCanonical(); err != nil {
		return nil, err
	}
	if b.rawBytes != "" {
		if parsed, err := ParseV3PreKeyBundle([]byte(b.rawBytes)); err == nil && sameV3PreKeyBundle(parsed, b) {
			return []byte(b.rawBytes), nil
		}
	}
	return encodeV3Fields(
		v3U16(v3TagVersion, b.Version),
		v3U16(v3TagSuite, uint16(b.Suite)),
		v3Bytes(v3TagServerID, []byte(b.ServerID)),
		v3Bytes(v3TagDeploymentScope, []byte(b.DeploymentScope)),
		v3U64(v3TagRouteEpoch, b.RouteEpoch),
		v3Bytes(v3TagPreKeyID, b.PreKeyID[:]),
		v3U64(v3TagBundleGeneration, b.BundleGeneration),
		v3U64(v3TagBundleNotBefore, b.NotBefore),
		v3U64(v3TagBundleNotAfter, b.NotAfter),
		v3Bytes(v3TagPreKeyX25519, b.PreKeyX25519Public[:]),
		v3Bytes(v3TagPreKeyMLKEM, b.PreKeyMLKEMPublic[:]),
		v3Bytes(v3TagBundleSignature, b.Signature[:]),
	)
}

func (b *V3PreKeyBundle) Sign(identity ServerSigningIdentity) error {
	if b == nil || identity.validate() != nil {
		return ErrV3Identity
	}
	unsigned, err := b.marshalUnsignedCanonical()
	if err != nil {
		return err
	}
	payload := v3Domain("ewp/v3/prekey-bundle", unsigned)
	signature := ed25519.Sign(identity.Private, payload)
	copy(b.Signature[:], signature)
	b.rawBytes = ""
	b.rawUnsignedBytes = ""
	return nil
}

func (b V3PreKeyBundle) Verify(identity Ed25519PublicKey) error {
	unsigned, err := b.MarshalUnsigned()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(identity[:]), v3Domain("ewp/v3/prekey-bundle", unsigned), b.Signature[:]) {
		return ErrV3Signature
	}
	return nil
}

func (b V3PreKeyBundle) Digest() (BundleDigest, error) {
	encoded, err := b.MarshalBinary()
	if err != nil {
		return BundleDigest{}, err
	}
	return BundleDigest(v3Hash("ewp/v3/prekey-bundle-digest", encoded)), nil
}

func sameV3PreKeyBundle(a, b V3PreKeyBundle) bool {
	return a.Version == b.Version && a.Suite == b.Suite && a.ServerID == b.ServerID &&
		a.DeploymentScope == b.DeploymentScope && a.RouteEpoch == b.RouteEpoch &&
		a.BundleGeneration == b.BundleGeneration && a.PreKeyID == b.PreKeyID &&
		a.NotBefore == b.NotBefore && a.NotAfter == b.NotAfter &&
		a.PreKeyX25519Public == b.PreKeyX25519Public && a.PreKeyMLKEMPublic == b.PreKeyMLKEMPublic &&
		a.Signature == b.Signature
}

func (b V3PreKeyBundle) ValidAt(now time.Time) bool {
	seconds := uint64(now.Unix())
	return b.NotBefore <= seconds && seconds < b.NotAfter
}

func ParseV3PreKeyBundle(data []byte) (V3PreKeyBundle, error) {
	fields, err := decodeV3Fields(data, v3PreKeyBundleTags)
	if err != nil {
		return V3PreKeyBundle{}, err
	}
	var result V3PreKeyBundle
	if result.Version, err = v3ReadU16(&fields, v3TagVersion); err != nil {
		return result, err
	}
	suite, err := v3ReadU16(&fields, v3TagSuite)
	if err != nil {
		return result, err
	}
	result.Suite = SuiteID(suite)
	serverID, err := v3Required(&fields, v3TagServerID)
	if err != nil || len(serverID) == 0 || len(serverID) > V3MaxServerIDLen {
		return result, ErrV3Malformed
	}
	result.ServerID = string(serverID)
	scope, err := v3Required(&fields, v3TagDeploymentScope)
	if err != nil || len(scope) > V3MaxScopeLen {
		return result, ErrV3Malformed
	}
	result.DeploymentScope = string(scope)
	if result.RouteEpoch, err = v3ReadU64(&fields, v3TagRouteEpoch); err != nil {
		return result, err
	}
	preKeyID, err := v3Exact(&fields, v3TagPreKeyID, V3PreKeyIDLen)
	if err != nil {
		return result, err
	}
	copy(result.PreKeyID[:], preKeyID)
	if result.BundleGeneration, err = v3ReadU64(&fields, v3TagBundleGeneration); err != nil {
		return result, err
	}
	if result.NotBefore, err = v3ReadU64(&fields, v3TagBundleNotBefore); err != nil {
		return result, err
	}
	if result.NotAfter, err = v3ReadU64(&fields, v3TagBundleNotAfter); err != nil {
		return result, err
	}
	public, err := v3Exact(&fields, v3TagPreKeyX25519, X25519PubLen)
	if err != nil {
		return result, err
	}
	copy(result.PreKeyX25519Public[:], public)
	pqPublic, err := v3Exact(&fields, v3TagPreKeyMLKEM, MLKEM768PubLen)
	if err != nil {
		return result, err
	}
	copy(result.PreKeyMLKEMPublic[:], pqPublic)
	signature, err := v3Exact(&fields, v3TagBundleSignature, V3SignatureLen)
	if err != nil {
		return result, err
	}
	_, signatureEnd, err := v3FieldRegion(data, v3TagBundleSignature)
	if err != nil {
		return result, err
	}
	if signatureEnd != len(data) {
		return result, ErrV3NonCanonical
	}
	copy(result.Signature[:], signature)
	if _, err := result.marshalUnsignedCanonical(); err != nil {
		return V3PreKeyBundle{}, err
	}
	unsigned, err := v3WithoutField(data, v3TagBundleSignature)
	if err != nil {
		return V3PreKeyBundle{}, err
	}
	result.rawBytes = string(data)
	result.rawUnsignedBytes = string(unsigned)
	return result, nil
}

// V3PreKeyMaterial is held by a prekey provider until a successful atomic
// ClaimAndBurn. Private key objects are runtime-managed by Go and can only be
// dropped, not guaranteed zeroized.
type V3PreKeyMaterial struct {
	Bundle        V3PreKeyBundle
	X25519Private *ecdh.PrivateKey
	MLKEMPrivate  *mlkem.DecapsulationKey768
}

func GenerateV3PreKeyMaterial(listener V3ListenerContext, identity ServerSigningIdentity, id PreKeyID, generation, routeEpoch uint64, notBefore, notAfter time.Time) (V3PreKeyMaterial, error) {
	return generateV3PreKeyMaterial(listener, identity, id, generation, routeEpoch, notBefore, notAfter, productionV3Runtime())
}

func generateV3PreKeyMaterial(listener V3ListenerContext, identity ServerSigningIdentity, id PreKeyID, generation, routeEpoch uint64, notBefore, notAfter time.Time, runtime v3Runtime) (V3PreKeyMaterial, error) {
	if err := listener.validate(); err != nil {
		return V3PreKeyMaterial{}, err
	}
	if err := identity.validate(); err != nil {
		return V3PreKeyMaterial{}, err
	}
	if id.isZero() {
		if err := v3ReadRandom(runtime.reader(), id[:]); err != nil {
			return V3PreKeyMaterial{}, err
		}
	}
	if !notAfter.After(notBefore) || notAfter.Unix() <= 0 {
		return V3PreKeyMaterial{}, ErrV3PreKey
	}
	xPrivate, err := ecdh.X25519().GenerateKey(runtime.reader())
	if err != nil {
		return V3PreKeyMaterial{}, err
	}
	pqPrivate, err := generateV3MLKEM768(runtime.reader())
	if err != nil {
		return V3PreKeyMaterial{}, err
	}
	var xPublic [X25519PubLen]byte
	copy(xPublic[:], xPrivate.PublicKey().Bytes())
	var pqPublic [MLKEM768PubLen]byte
	copy(pqPublic[:], pqPrivate.EncapsulationKey().Bytes())
	bundle := V3PreKeyBundle{
		Version:            listener.Version,
		Suite:              listener.Suite,
		ServerID:           listener.ServerID,
		DeploymentScope:    listener.DeploymentScope,
		RouteEpoch:         routeEpoch,
		BundleGeneration:   generation,
		PreKeyID:           id,
		NotBefore:          uint64(notBefore.Unix()),
		NotAfter:           uint64(notAfter.Unix()),
		PreKeyX25519Public: xPublic,
		PreKeyMLKEMPublic:  pqPublic,
	}
	if err := bundle.Sign(identity); err != nil {
		return V3PreKeyMaterial{}, err
	}
	return V3PreKeyMaterial{Bundle: bundle, X25519Private: xPrivate, MLKEMPrivate: pqPrivate}, nil
}

func generateV3MLKEM768(reader io.Reader) (*mlkem.DecapsulationKey768, error) {
	seed := make([]byte, mlkem.SeedSize)
	defer zero(seed)
	if err := v3ReadRandom(reader, seed); err != nil {
		return nil, err
	}
	return mlkem.NewDecapsulationKey768(seed)
}

func (m *V3PreKeyMaterial) Destroy() {
	if m == nil {
		return
	}
	m.X25519Private = nil
	m.MLKEMPrivate = nil
}

type V3ConsumedPreKey struct {
	Bundle        V3PreKeyBundle
	X25519Private *ecdh.PrivateKey
	MLKEMPrivate  *mlkem.DecapsulationKey768
}

func (m *V3ConsumedPreKey) Destroy() {
	if m == nil {
		return
	}
	m.X25519Private = nil
	m.MLKEMPrivate = nil
}

type V3PreKeyClaim struct {
	ReplayKey        ReplayKey
	Version          uint16
	Suite            SuiteID
	ServerID         string
	DeploymentScope  string
	RouteEpoch       uint64
	BundleGeneration uint64
	PreKeyID         PreKeyID
	BundleDigest     BundleDigest
	InitNonce        V3Nonce
	ClientNonce      V3Nonce
	CoreDigest       [32]byte
	Principal        PrincipalID
	RouteTag         RouteTag
	Source           SourceBinding
	Expiry           time.Time
}

type PreKeyResolver interface {
	CurrentBundles(ctx context.Context, listener V3ListenerContext) ([]V3PreKeyBundle, error)
}

type PreKeyProvider interface {
	PreKeyResolver
	CredentialResolver
	// ClaimAndBurn must atomically validate replay state and consume one
	// process-local prekey, returning its private material exactly once.
	ClaimAndBurn(ctx context.Context, listener V3ListenerContext, claim V3PreKeyClaim) (V3ConsumedPreKey, error)
}

// MemoryPreKeyProvider is the bounded in-process implementation for a v3
// endpoint. It provides atomic replay/prekey consumption; all such state is
// intentionally lost when the process exits.
type MemoryPreKeyProvider struct {
	mu             sync.Mutex
	entries        map[PreKeyID]V3PreKeyMaterial
	claims         map[ReplayKey]time.Time
	burned         map[PreKeyID]struct{}
	generations    map[V3ListenerContext]uint64
	hasGeneration  map[V3ListenerContext]bool
	principals     map[RouteTag]V3Principal
	principalsByID map[PrincipalID]V3Principal
	runtime        v3Runtime
}

func NewMemoryPreKeyProvider(materials ...V3PreKeyMaterial) (*MemoryPreKeyProvider, error) {
	return newMemoryPreKeyProvider(productionV3Runtime(), materials...)
}

func newMemoryPreKeyProvider(runtime v3Runtime, materials ...V3PreKeyMaterial) (*MemoryPreKeyProvider, error) {
	p := &MemoryPreKeyProvider{
		entries:        make(map[PreKeyID]V3PreKeyMaterial, len(materials)),
		claims:         make(map[ReplayKey]time.Time),
		burned:         make(map[PreKeyID]struct{}),
		generations:    make(map[V3ListenerContext]uint64),
		hasGeneration:  make(map[V3ListenerContext]bool),
		principals:     make(map[RouteTag]V3Principal),
		principalsByID: make(map[PrincipalID]V3Principal),
		runtime:        runtime,
	}
	for _, material := range materials {
		if err := p.Add(material); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// AddPrincipal configures the O(1) route-tag lookup used by ServiceV3. It is
// kept beside the in-memory prekey provider so test fixtures can provision a
// complete v3 service without an implicit user-table fallback.
func (p *MemoryPreKeyProvider) AddPrincipal(principal V3Principal) error {
	if p == nil {
		return ErrV3Credential
	}
	if err := principal.validate(); err != nil {
		return err
	}
	tag := ComputeV3RouteTag(principal.KAuth, principal.Listener, principal.RouteEpoch)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.principals == nil {
		p.principals = make(map[RouteTag]V3Principal)
	}
	if p.principalsByID == nil {
		p.principalsByID = make(map[PrincipalID]V3Principal)
	}
	if _, exists := p.principals[tag]; !exists && len(p.principals) >= MaxV3Principals {
		return ErrV3Credential
	}
	if _, exists := p.principals[tag]; exists {
		return ErrV3Credential
	}
	if _, exists := p.principalsByID[principal.ID]; exists {
		return ErrV3Credential
	}
	p.principals[tag] = principal
	p.principalsByID[principal.ID] = principal
	return nil
}

func (p *MemoryPreKeyProvider) LookupRouteTag(ctx context.Context, listener V3ListenerContext, tag RouteTag, routeEpoch uint64) (V3Principal, bool) {
	if err := contextErr(ctx); err != nil || p == nil {
		return V3Principal{}, false
	}
	p.mu.Lock()
	principal, ok := p.principals[tag]
	p.mu.Unlock()
	if !ok || principal.Listener != listener || principal.RouteEpoch != routeEpoch {
		return V3Principal{}, false
	}
	return principal, true
}

func (p *MemoryPreKeyProvider) Add(material V3PreKeyMaterial) error {
	if p == nil || material.X25519Private == nil || material.MLKEMPrivate == nil {
		return ErrV3PreKey
	}
	if _, err := material.Bundle.MarshalBinary(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries == nil {
		p.entries = make(map[PreKeyID]V3PreKeyMaterial)
	}
	if p.burned == nil {
		p.burned = make(map[PreKeyID]struct{})
	}
	if p.generations == nil {
		p.generations = make(map[V3ListenerContext]uint64)
	}
	if p.hasGeneration == nil {
		p.hasGeneration = make(map[V3ListenerContext]bool)
	}
	if material.Bundle.BundleGeneration == 0 {
		return ErrV3PreKey
	}
	if _, exists := p.entries[material.Bundle.PreKeyID]; exists {
		return ErrV3PreKey
	}
	if len(p.entries) >= MaxV3PreKeys {
		return ErrV3PreKey
	}
	if _, burned := p.burned[material.Bundle.PreKeyID]; burned {
		return ErrV3PreKey
	}
	listener := V3ListenerContext{
		Version:         material.Bundle.Version,
		Suite:           material.Bundle.Suite,
		ServerID:        material.Bundle.ServerID,
		DeploymentScope: material.Bundle.DeploymentScope,
	}
	if p.hasGeneration[listener] && material.Bundle.BundleGeneration < p.generations[listener] {
		return ErrV3PreKey
	}
	if !p.hasGeneration[listener] || material.Bundle.BundleGeneration > p.generations[listener] {
		p.generations[listener] = material.Bundle.BundleGeneration
		p.hasGeneration[listener] = true
	}
	p.entries[material.Bundle.PreKeyID] = material
	return nil
}

func (p *MemoryPreKeyProvider) CurrentBundles(ctx context.Context, listener V3ListenerContext) ([]V3PreKeyBundle, error) {
	if err := listener.validate(); err != nil {
		return nil, err
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrV3PreKey
	}
	now := p.runtime.nowTime()
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]V3PreKeyBundle, 0, len(p.entries))
	for _, material := range p.entries {
		bundle := material.Bundle
		if bundle.Version == listener.Version && bundle.Suite == listener.Suite &&
			bundle.ServerID == listener.ServerID && bundle.DeploymentScope == listener.DeploymentScope &&
			bundle.ValidAt(now) {
			result = append(result, bundle)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].BundleGeneration != result[j].BundleGeneration {
			return result[i].BundleGeneration < result[j].BundleGeneration
		}
		return string(result[i].PreKeyID[:]) < string(result[j].PreKeyID[:])
	})
	return result, nil
}

func (p *MemoryPreKeyProvider) ClaimAndBurn(ctx context.Context, listener V3ListenerContext, claim V3PreKeyClaim) (V3ConsumedPreKey, error) {
	if err := listener.validate(); err != nil {
		return V3ConsumedPreKey{}, err
	}
	if err := contextErr(ctx); err != nil {
		return V3ConsumedPreKey{}, err
	}
	if p == nil {
		return V3ConsumedPreKey{}, ErrV3PreKey
	}
	now := p.runtime.nowTime()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireClaimsLocked(now)
	if err := p.validateClaimLocked(listener, claim, now); err != nil {
		return V3ConsumedPreKey{}, err
	}
	return p.claimAndBurnLocked(claim)
}

func (p *MemoryPreKeyProvider) expireClaimsLocked(now time.Time) {
	for key, expiry := range p.claims {
		if !expiry.After(now) {
			delete(p.claims, key)
		}
	}
}

func (p *MemoryPreKeyProvider) validateClaimLocked(listener V3ListenerContext, claim V3PreKeyClaim, now time.Time) error {
	if claim.Version != listener.Version || claim.Suite != listener.Suite ||
		claim.ServerID != listener.ServerID || claim.DeploymentScope != listener.DeploymentScope ||
		claim.Expiry.IsZero() || !claim.Expiry.After(now) || len(claim.Source) == 0 || len(claim.Source) > V3MaxSourceLen ||
		claim.BundleGeneration == 0 || claim.ReplayKey == (ReplayKey{}) {
		return ErrV3PreKey
	}
	principal, ok := p.principalsByID[claim.Principal]
	if !ok || principal.ID != claim.Principal || principal.Listener != listener || principal.RouteEpoch != claim.RouteEpoch {
		return ErrV3Admission
	}
	if claim.RouteTag != (RouteTag{}) && ComputeV3RouteTag(principal.KAuth, listener, claim.RouteEpoch) != claim.RouteTag {
		return ErrV3Admission
	}
	expectedReplay, err := ComputeV3ReplayKey(principal.KAuth, listener, principal.ID, claim)
	if err != nil || expectedReplay != claim.ReplayKey {
		return ErrV3Replay
	}
	if _, exists := p.claims[claim.ReplayKey]; exists {
		return ErrV3Replay
	}
	if len(p.claims) >= MaxV3ReplayClaims {
		return ErrV3Replay
	}
	material, exists := p.entries[claim.PreKeyID]
	if !exists {
		return ErrV3PreKey
	}
	bundleDigest, err := material.Bundle.Digest()
	if err != nil || bundleDigest != claim.BundleDigest || material.Bundle.BundleGeneration != claim.BundleGeneration || material.Bundle.RouteEpoch != claim.RouteEpoch || !material.Bundle.ValidAt(now) {
		return ErrV3PreKey
	}
	return nil
}

func (p *MemoryPreKeyProvider) claimAndBurnLocked(claim V3PreKeyClaim) (V3ConsumedPreKey, error) {
	material, exists := p.entries[claim.PreKeyID]
	if !exists {
		return V3ConsumedPreKey{}, ErrV3PreKey
	}
	delete(p.entries, claim.PreKeyID)
	p.burned[claim.PreKeyID] = struct{}{}
	p.claims[claim.ReplayKey] = claim.Expiry
	return V3ConsumedPreKey{
		Bundle:        material.Bundle,
		X25519Private: material.X25519Private,
		MLKEMPrivate:  material.MLKEMPrivate,
	}, nil
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func v3EqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func v3Uint64Bytes(value uint64) []byte {
	var result [8]byte
	binary.BigEndian.PutUint64(result[:], value)
	return result[:]
}
