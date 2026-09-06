package ewp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"sync"
	"time"
)

func onceV3Release(release func()) func() {
	if release == nil {
		return func() {}
	}
	var once sync.Once
	return func() {
		once.Do(release)
	}
}

type V3CookieKey struct {
	ID  uint8
	Key [32]byte
}

type V3CookieKeys struct {
	Current     V3CookieKey
	Previous    V3CookieKey
	HasPrevious bool
	runtime     v3Runtime
	state       *v3CookieKeyState
}

type v3CookieKeyState struct {
	mu sync.RWMutex
}

var v3CookieStateInitMu sync.Mutex

func (k *V3CookieKeys) ensureState() *v3CookieKeyState {
	if k == nil {
		return nil
	}
	v3CookieStateInitMu.Lock()
	if k.state == nil {
		k.state = &v3CookieKeyState{}
	}
	state := k.state
	v3CookieStateInitMu.Unlock()
	return state
}

func (k *V3CookieKeys) validate() error {
	state := k.ensureState()
	if state == nil {
		return ErrV3Cookie
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	if k.Current.Key == [32]byte{} {
		return ErrV3Cookie
	}
	if k.HasPrevious && (k.Previous.Key == [32]byte{} || k.Previous.ID == k.Current.ID) {
		return ErrV3Cookie
	}
	return nil
}

func NewV3CookieKeys() (V3CookieKeys, error) {
	return newV3CookieKeys(productionV3Runtime())
}

func newV3CookieKeys(runtime v3Runtime) (V3CookieKeys, error) {
	var keys V3CookieKeys
	if err := v3ReadRandom(runtime.reader(), keys.Current.Key[:]); err != nil {
		return V3CookieKeys{}, err
	}
	if err := v3ReadRandom(runtime.reader(), keys.Previous.Key[:]); err != nil {
		return V3CookieKeys{}, err
	}
	keys.Current.ID = 1
	keys.Previous.ID = 0
	keys.HasPrevious = true
	keys.runtime = runtime
	keys.state = &v3CookieKeyState{}
	return keys, nil
}

func (k *V3CookieKeys) Rotate() error {
	state := k.ensureState()
	if state == nil {
		return ErrV3Cookie
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	runtime := k.runtime
	if runtime.random == nil {
		runtime = productionV3Runtime()
	}
	var nextKey [32]byte
	if err := v3ReadRandom(runtime.reader(), nextKey[:]); err != nil {
		return err
	}
	k.Previous = k.Current
	k.Current.Key = nextKey
	k.Current.ID++
	k.HasPrevious = true
	return nil
}

func v3ListenerBytes(listener V3ListenerContext) []byte {
	return v3Domain("ewp/v3/listener", v3Uint16Bytes(listener.Version), v3Uint16Bytes(uint16(listener.Suite)), []byte(listener.ServerID), []byte(listener.DeploymentScope))
}

func ComputeV3RouteTag(credential [V3KAuthLen]byte, listener V3ListenerContext, routeEpoch uint64) RouteTag {
	mac := hmac.New(sha256.New, credential[:])
	mac.Write(v3Domain("ewp/v3/route", []byte(listener.ServerID), []byte(listener.DeploymentScope), v3Uint64Bytes(routeEpoch)))
	sum := mac.Sum(nil)
	var result RouteTag
	copy(result[:], sum[:V3RouteTagLen])
	return result
}

func (k *V3CookieKeys) Mint(listener V3ListenerContext, init V3ClientInit, source SourceBinding) (V3HelloRetry, error) {
	if err := k.validate(); err != nil {
		return V3HelloRetry{}, err
	}
	state := k.ensureState()
	if state == nil {
		return V3HelloRetry{}, ErrV3Cookie
	}
	state.mu.RLock()
	current := k.Current
	runtime := k.runtime
	state.mu.RUnlock()
	if runtime.now == nil || runtime.random == nil {
		production := productionV3Runtime()
		if runtime.now == nil {
			runtime.now = production.now
		}
		if runtime.random == nil {
			runtime.random = production.random
		}
	}
	return mintV3Cookie(listener, init, source, runtime.nowTime(), runtime.reader(), current)
}

func (k *V3CookieKeys) mintAt(listener V3ListenerContext, init V3ClientInit, source SourceBinding, now time.Time, reader io.Reader) (V3HelloRetry, error) {
	if err := k.validate(); err != nil {
		return V3HelloRetry{}, err
	}
	state := k.ensureState()
	if state == nil {
		return V3HelloRetry{}, ErrV3Cookie
	}
	state.mu.RLock()
	current := k.Current
	state.mu.RUnlock()
	return mintV3Cookie(listener, init, source, now, reader, current)
}

func mintV3Cookie(listener V3ListenerContext, init V3ClientInit, source SourceBinding, now time.Time, reader io.Reader, current V3CookieKey) (V3HelloRetry, error) {
	if err := listener.validate(); err != nil {
		return V3HelloRetry{}, err
	}
	if init.Version != listener.Version || init.Suite != listener.Suite || init.ServerID != listener.ServerID || init.DeploymentScope != listener.DeploymentScope {
		return V3HelloRetry{}, ErrV3Cookie
	}
	if len(source) == 0 || len(source) > V3MaxSourceLen {
		return V3HelloRetry{}, ErrV3Cookie
	}
	var retry V3HelloRetry
	retry.Version = listener.Version
	retry.Suite = listener.Suite
	retry.InitNonce = init.InitNonce
	if err := v3ReadRandom(reader, retry.RetryNonce[:]); err != nil {
		return V3HelloRetry{}, err
	}
	retry.CookieKeyID = current.ID
	retry.ExpiresAt = uint64(now.Add(V3RetryLifetime).Unix())
	retry.Cookie = (V3CookieKeys{}).cookie(listener, init, retry, source, current.Key)
	return retry, nil
}

func (k *V3CookieKeys) Verify(listener V3ListenerContext, init V3ClientInit, retry V3HelloRetry, source SourceBinding) error {
	if err := k.validate(); err != nil {
		return err
	}
	state := k.ensureState()
	if state == nil {
		return ErrV3Cookie
	}
	state.mu.RLock()
	current, previous, hasPrevious := k.Current, k.Previous, k.HasPrevious
	runtime := k.runtime
	state.mu.RUnlock()
	if runtime.now == nil {
		runtime.now = time.Now
	}
	return verifyV3Cookie(listener, init, retry, source, runtime.nowTime(), current, previous, hasPrevious)
}

func (k *V3CookieKeys) verifyAt(listener V3ListenerContext, init V3ClientInit, retry V3HelloRetry, source SourceBinding, now time.Time) error {
	if err := k.validate(); err != nil {
		return err
	}
	state := k.ensureState()
	if state == nil {
		return ErrV3Cookie
	}
	state.mu.RLock()
	current, previous, hasPrevious := k.Current, k.Previous, k.HasPrevious
	state.mu.RUnlock()
	return verifyV3Cookie(listener, init, retry, source, now, current, previous, hasPrevious)
}

func verifyV3Cookie(listener V3ListenerContext, init V3ClientInit, retry V3HelloRetry, source SourceBinding, now time.Time, current, previous V3CookieKey, hasPrevious bool) error {
	if err := listener.validate(); err != nil {
		return err
	}
	if retry.Version != listener.Version || retry.Suite != listener.Suite || retry.InitNonce != init.InitNonce {
		return ErrV3Cookie
	}
	if len(source) == 0 || len(source) > V3MaxSourceLen {
		return ErrV3Cookie
	}
	nowSeconds := uint64(now.Unix())
	if retry.ExpiresAt < nowSeconds || retry.ExpiresAt > nowSeconds+uint64(V3RetryLifetime/time.Second)+1 {
		return ErrV3Cookie
	}
	var key *V3CookieKey
	switch {
	case retry.CookieKeyID == current.ID:
		key = &current
	case hasPrevious && retry.CookieKeyID == previous.ID:
		key = &previous
	default:
		return ErrV3Cookie
	}
	want := (V3CookieKeys{}).cookie(listener, init, retry, source, key.Key)
	if !hmac.Equal(want[:], retry.Cookie[:]) {
		return ErrV3Cookie
	}
	return nil
}

func (V3CookieKeys) cookie(listener V3ListenerContext, init V3ClientInit, retry V3HelloRetry, source SourceBinding, key [32]byte) [V3CookieLen]byte {
	input := v3Domain(
		"ewp/v3/cookie",
		v3Uint16Bytes(listener.Version),
		v3Uint16Bytes(uint16(listener.Suite)),
		[]byte(listener.ServerID),
		[]byte(listener.DeploymentScope),
		[]byte(source),
		v3Uint64Bytes(retry.ExpiresAt),
		init.PreKeyID[:],
		init.BundleDigest[:],
		v3Uint64Bytes(init.BundleGeneration),
		init.InitNonce[:],
		init.ClientNonce[:],
		init.CoreDigest[:],
	)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(input)
	var result [V3CookieLen]byte
	copy(result[:], mac.Sum(nil))
	return result
}

type V3Principal struct {
	ID         PrincipalID
	KAuth      [V3KAuthLen]byte
	Listener   V3ListenerContext
	RouteEpoch uint64
}

func (p V3Principal) validate() error {
	if err := p.Listener.validate(); err != nil {
		return err
	}
	var zero [V3KAuthLen]byte
	if p.KAuth == zero {
		return ErrV3Credential
	}
	return nil
}

type CredentialResolver interface {
	LookupRouteTag(ctx context.Context, listener V3ListenerContext, tag RouteTag, routeEpoch uint64) (V3Principal, bool)
}

// MemoryCredentialResolver is a small in-process resolver for tests and local
// deployments. A host may replace it with another bounded resolver without
// changing the v3 wire protocol.
type MemoryCredentialResolver struct {
	mu         sync.RWMutex
	principals map[RouteTag]V3Principal
}

func NewMemoryCredentialResolver(principals ...V3Principal) (*MemoryCredentialResolver, error) {
	r := &MemoryCredentialResolver{principals: make(map[RouteTag]V3Principal, len(principals))}
	for _, principal := range principals {
		if err := r.Add(principal); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *MemoryCredentialResolver) Add(principal V3Principal) error {
	if r == nil {
		return ErrV3Credential
	}
	if err := principal.validate(); err != nil {
		return err
	}
	tag := ComputeV3RouteTag(principal.KAuth, principal.Listener, principal.RouteEpoch)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.principals == nil {
		r.principals = make(map[RouteTag]V3Principal)
	}
	if _, exists := r.principals[tag]; !exists && len(r.principals) >= MaxV3Principals {
		return ErrV3Credential
	}
	if _, exists := r.principals[tag]; exists {
		return ErrV3Credential
	}
	r.principals[tag] = principal
	return nil
}

func (r *MemoryCredentialResolver) LookupRouteTag(ctx context.Context, listener V3ListenerContext, tag RouteTag, routeEpoch uint64) (V3Principal, bool) {
	if contextErr(ctx) != nil || r == nil {
		return V3Principal{}, false
	}
	r.mu.RLock()
	principal, ok := r.principals[tag]
	r.mu.RUnlock()
	if !ok || principal.RouteEpoch != routeEpoch || principal.Listener != listener {
		return V3Principal{}, false
	}
	return principal, true
}

// V3AdmissionController enforces finite global, source, and principal rates,
// plus a hard cap on concurrent ML-KEM/X25519 work. It is intentionally a
// small in-process controller; a host may replace it with another bounded
// process-local implementation behind the same interface.
type V3AdmissionController struct {
	mu                     sync.Mutex
	initGlobal             v3TokenBucket
	helloGlobal            v3TokenBucket
	initBySource           map[SourceBinding]v3TokenBucket
	helloBySource          map[SourceBinding]v3TokenBucket
	helloByPrincipal       map[PrincipalID]v3TokenBucket
	initInFlight           int
	helloInFlight          int
	initSourceInFlight     map[SourceBinding]int
	helloSourceInFlight    map[SourceBinding]int
	helloPrincipalInFlight map[PrincipalID]int

	maxInitGlobal     int
	maxHelloGlobal    int
	maxInitSource     int
	maxHelloSource    int
	maxHelloPrincipal int
	kem               chan struct{}
	runtime           v3Runtime
}

type AdmissionController interface {
	AllowInit(SourceBinding) bool
	AllowClientHello(SourceBinding, PrincipalID) bool
	AcquireKEM(context.Context) (func(), error)
}

// V3AdmissionLeaser adds bounded processing leases to the compatibility
// admission interface. The lease is held only for the corresponding parsing
// or asymmetric-processing stage and must be released exactly once.
type V3AdmissionLeaser interface {
	AdmissionController
	AcquireInit(context.Context, SourceBinding) (func(), error)
	ReserveClientHello(context.Context, SourceBinding, PrincipalID) (func(), error)
}

type v3TokenBucket struct {
	tokens float64
	last   time.Time
}

func (b *v3TokenBucket) allow(now time.Time, capacity int) bool {
	if capacity <= 0 {
		return false
	}
	if b.last.IsZero() {
		b.tokens = float64(capacity)
		b.last = now
	}
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * float64(capacity)
		if b.tokens > float64(capacity) {
			b.tokens = float64(capacity)
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (b v3TokenBucket) idle(now time.Time, capacity int) bool {
	return capacity > 0 && !b.last.IsZero() && now.Sub(b.last) >= time.Second
}

func NewV3AdmissionController(maxInitGlobal, maxHelloGlobal, maxInitSource, maxHelloSource, maxHelloPrincipal, maxKEM int) (*V3AdmissionController, error) {
	return newV3AdmissionController(maxInitGlobal, maxHelloGlobal, maxInitSource, maxHelloSource, maxHelloPrincipal, maxKEM, productionV3Runtime())
}

func newV3AdmissionController(maxInitGlobal, maxHelloGlobal, maxInitSource, maxHelloSource, maxHelloPrincipal, maxKEM int, runtime v3Runtime) (*V3AdmissionController, error) {
	if maxInitGlobal <= 0 || maxHelloGlobal <= 0 || maxInitSource <= 0 || maxHelloSource <= 0 || maxHelloPrincipal <= 0 || maxKEM <= 0 {
		return nil, ErrV3Admission
	}
	return &V3AdmissionController{
		initGlobal:             v3TokenBucket{tokens: float64(maxInitGlobal), last: runtime.nowTime()},
		helloGlobal:            v3TokenBucket{tokens: float64(maxHelloGlobal), last: runtime.nowTime()},
		initBySource:           make(map[SourceBinding]v3TokenBucket),
		helloBySource:          make(map[SourceBinding]v3TokenBucket),
		helloByPrincipal:       make(map[PrincipalID]v3TokenBucket),
		initSourceInFlight:     make(map[SourceBinding]int),
		helloSourceInFlight:    make(map[SourceBinding]int),
		helloPrincipalInFlight: make(map[PrincipalID]int),
		maxInitGlobal:          maxInitGlobal,
		maxHelloGlobal:         maxHelloGlobal,
		maxInitSource:          maxInitSource,
		maxHelloSource:         maxHelloSource,
		maxHelloPrincipal:      maxHelloPrincipal,
		kem:                    make(chan struct{}, maxKEM),
		runtime:                runtime,
	}, nil
}

func (a *V3AdmissionController) AcquireInit(ctx context.Context, source SourceBinding) (func(), error) {
	if a == nil || len(source) == 0 || len(source) > V3MaxSourceLen {
		return nil, ErrV3Admission
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	a.mu.Lock()
	now := a.runtime.nowTime()
	a.pruneLocked(now)
	if a.initInFlight >= a.maxInitGlobal || a.initSourceInFlight[source] >= a.maxInitSource || !a.allowInitRateLocked(now, source) {
		a.mu.Unlock()
		return nil, ErrV3Admission
	}
	a.initInFlight++
	a.initSourceInFlight[source]++
	a.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			if a.initInFlight > 0 {
				a.initInFlight--
			}
			if count := a.initSourceInFlight[source]; count <= 1 {
				delete(a.initSourceInFlight, source)
			} else {
				a.initSourceInFlight[source] = count - 1
			}
			a.mu.Unlock()
		})
	}, nil
}

func (a *V3AdmissionController) ReserveClientHello(ctx context.Context, source SourceBinding, principal PrincipalID) (func(), error) {
	if a == nil || len(source) == 0 || len(source) > V3MaxSourceLen {
		return nil, ErrV3Admission
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	a.mu.Lock()
	now := a.runtime.nowTime()
	a.pruneLocked(now)
	if a.helloInFlight >= a.maxHelloGlobal || a.helloSourceInFlight[source] >= a.maxHelloSource || a.helloPrincipalInFlight[principal] >= a.maxHelloPrincipal || !a.allowHelloRateLocked(now, source, principal) {
		a.mu.Unlock()
		return nil, ErrV3Admission
	}
	a.helloInFlight++
	a.helloSourceInFlight[source]++
	a.helloPrincipalInFlight[principal]++
	a.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			if a.helloInFlight > 0 {
				a.helloInFlight--
			}
			if count := a.helloSourceInFlight[source]; count <= 1 {
				delete(a.helloSourceInFlight, source)
			} else {
				a.helloSourceInFlight[source] = count - 1
			}
			if count := a.helloPrincipalInFlight[principal]; count <= 1 {
				delete(a.helloPrincipalInFlight, principal)
			} else {
				a.helloPrincipalInFlight[principal] = count - 1
			}
			a.mu.Unlock()
		})
	}, nil
}

func (a *V3AdmissionController) allowInitRateLocked(now time.Time, source SourceBinding) bool {
	bucket, exists := a.initBySource[source]
	if !exists && len(a.initBySource) >= a.maxInitGlobal {
		return false
	}
	global := a.initGlobal
	if !global.allow(now, a.maxInitGlobal) || !bucket.allow(now, a.maxInitSource) {
		return false
	}
	a.initGlobal = global
	a.initBySource[source] = bucket
	return true
}

func (a *V3AdmissionController) allowHelloRateLocked(now time.Time, source SourceBinding, principal PrincipalID) bool {
	sourceBucket, sourceExists := a.helloBySource[source]
	principalBucket, principalExists := a.helloByPrincipal[principal]
	if (!sourceExists && len(a.helloBySource) >= a.maxHelloGlobal) || (!principalExists && len(a.helloByPrincipal) >= a.maxHelloGlobal) {
		return false
	}
	global := a.helloGlobal
	if !global.allow(now, a.maxHelloGlobal) || !sourceBucket.allow(now, a.maxHelloSource) || !principalBucket.allow(now, a.maxHelloPrincipal) {
		return false
	}
	a.helloGlobal = global
	a.helloBySource[source] = sourceBucket
	a.helloByPrincipal[principal] = principalBucket
	return true
}

func (a *V3AdmissionController) pruneLocked(now time.Time) {
	for source, bucket := range a.initBySource {
		if bucket.idle(now, a.maxInitSource) && a.initSourceInFlight[source] == 0 {
			delete(a.initBySource, source)
		}
	}
	for source, bucket := range a.helloBySource {
		if bucket.idle(now, a.maxHelloSource) && a.helloSourceInFlight[source] == 0 {
			delete(a.helloBySource, source)
		}
	}
	for principal, bucket := range a.helloByPrincipal {
		if bucket.idle(now, a.maxHelloPrincipal) && a.helloPrincipalInFlight[principal] == 0 {
			delete(a.helloByPrincipal, principal)
		}
	}
}

func (a *V3AdmissionController) AllowInit(source SourceBinding) bool {
	if a == nil || len(source) == 0 || len(source) > V3MaxSourceLen {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.runtime.nowTime()
	a.pruneLocked(now)
	if !a.allowInitRateLocked(now, source) {
		return false
	}
	return true
}

func (a *V3AdmissionController) AllowClientHello(source SourceBinding, principal PrincipalID) bool {
	if a == nil || len(source) == 0 || len(source) > V3MaxSourceLen {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.runtime.nowTime()
	a.pruneLocked(now)
	if !a.allowHelloRateLocked(now, source, principal) {
		return false
	}
	return true
}

func (a *V3AdmissionController) AcquireKEM(ctx context.Context) (func(), error) {
	if a == nil || a.kem == nil {
		return nil, ErrV3Admission
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case a.kem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-a.kem }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func v3Uint16Bytes(value uint16) []byte {
	return []byte{byte(value >> 8), byte(value)}
}
