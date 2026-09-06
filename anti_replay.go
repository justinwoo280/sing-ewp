package ewp

import (
	"sync"
	"sync/atomic"
	"time"
)

// ReplayWindow is the duration for which a (UUID, nonce) tuple is
// remembered after first sight. It MUST be at least
// HandshakeTimestampWindow so that a replayed ClientHello cannot
// "outlive" the timestamp check by hiding in a fresh cache.
//
// We add a small grace margin to account for clock skew between client
// and server.
const ReplayWindow = (HandshakeTimestampWindow + 30) * time.Second

// replayKey identifies a single ClientHello by its (UUID, nonce) pair.
// 16 + 12 bytes are enough to be globally unique with overwhelming
// probability for any practical traffic volume.
type replayKey [UUIDLen + HandshakeNonce]byte

func makeReplayKey(uuid [UUIDLen]byte, nonce [HandshakeNonce]byte) replayKey {
	var k replayKey
	copy(k[:UUIDLen], uuid[:])
	copy(k[UUIDLen:], nonce[:])
	return k
}

// replayShardCount is the number of independent shards in ReplayCache.
// 16 is chosen to keep contention well below saturation on commodity
// CPUs (with 32 admit goroutines lock acquisitions are spread across
// 16 mutexes ≈ 2 goroutines per shard) while keeping per-shard map
// sizes large enough that map growth amortizes well.
//
// MUST be a power of two so the shard index can be derived from a
// single byte mask.
const replayShardCount = 16

// maxReplayEntries is a fail-closed memory bound. A full cache rejects new
// admissions until expired entries are collected instead of allowing an
// authenticated client to grow the process indefinitely.
const maxReplayEntries = 1 << 18

// gcInterval is how many MarkSeenOrReject calls per shard between
// opportunistic sweeps. The background ticker also sweeps periodically;
// the per-shard counter exists so a shard that admits a sudden burst
// can free expired entries without waiting for the next tick.
const gcInterval = 1024

// gcTickInterval is the upper bound on how often the background
// goroutine sweeps every shard. The actual interval is min(this, window/3)
// so that a cache configured with a short window (test cases, or
// future protocol revisions that drop the timestamp window) still
// frees expired entries promptly. Picked to keep worst-case live-set
// bounded at roughly (admit_rate * (window + tickInterval)) and small
// enough that a quiescent server frees memory promptly.
const gcTickInterval = 30 * time.Second

// minGCTick is the floor on the ticker period; below this the
// goroutine wakes too often and starts to dominate idle CPU. Chosen
// so even a 1s test-only window still gets at least three sweeps
// before the second one would matter.
const minGCTick = 100 * time.Millisecond

// replayShard is a single mutex-guarded map of recently-seen keys.
type replayShard struct {
	mu        sync.Mutex
	entries   map[replayKey]time.Time // value: expiry with monotonic clock reading
	gcCounter uint32
}

// ReplayCache is a sharded, time-bounded set of (UUID, nonce) pairs
// used to reject duplicate ClientHello messages within the handshake
// timestamp window.
//
// The cache uses replayShardCount independent shards, each guarded by
// its own mutex, so concurrent admits from many users contend on at
// most ⌈N/replayShardCount⌉ goroutines per lock instead of all of them
// on a single lock.
//
// A background sweeper goroutine runs every gcTickInterval to free
// expired entries. The goroutine is started by NewReplayCache and is
// terminated when (*ReplayCache).Close is called; for the typical
// long-running Service this is never necessary.
type ReplayCache struct {
	shards [replayShardCount]replayShard
	window time.Duration
	total  atomic.Uint64

	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
}

// NewReplayCache constructs a ReplayCache whose entries live for
// `window`. Pass ReplayWindow for the standard EWP/v2 setting.
//
// The returned cache spawns a single background goroutine that sweeps
// expired entries every gcTickInterval. Call (*ReplayCache).Close to
// terminate it; for a process-lifetime Service this is optional.
func NewReplayCache(window time.Duration) *ReplayCache {
	if window < ReplayWindow {
		// A shorter window would let a still-valid ClientHello outlive the
		// cache and silently re-enable replay. Keep the public constructor
		// fail-closed; short windows are available only to package tests.
		window = ReplayWindow
	}
	return newReplayCache(window)
}

func newReplayCache(window time.Duration) *ReplayCache {
	c := &ReplayCache{
		window: window,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	for i := range c.shards {
		c.shards[i].entries = make(map[replayKey]time.Time)
	}
	go c.gcLoop()
	return c
}

// Close stops the background GC goroutine. Safe to call multiple
// times.
func (c *ReplayCache) Close() {
	c.stopOnce.Do(func() { close(c.stopCh) })
	<-c.doneCh
}

func (c *ReplayCache) gcLoop() {
	defer close(c.doneCh)
	period := gcTickInterval
	if w := c.window / 3; w < period {
		period = w
	}
	if period < minGCTick {
		period = minGCTick
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-t.C:
			now := time.Now()
			for i := range c.shards {
				s := &c.shards[i]
				s.mu.Lock()
				for k, exp := range s.entries {
					if !exp.After(now) {
						delete(s.entries, k)
						c.total.Add(^uint64(0))
					}
				}
				s.mu.Unlock()
			}
		}
	}
}

// shardOf maps the complete replay key across shards. Using all key bytes is
// important because a single user can generate an unbounded sequence of
// nonces; selecting only from the UUID would put all of that load on one lock.
func (c *ReplayCache) shardOf(k replayKey) *replayShard {
	// FNV-1a is used only for lock distribution. The replay key is already
	// authenticated before it reaches this cache, so a cryptographic hash is
	// unnecessary here.
	h := uint32(2166136261)
	for _, b := range k {
		h ^= uint32(b)
		h *= 16777619
	}
	idx := uint(h) & (replayShardCount - 1)
	return &c.shards[idx]
}

// MarkSeenOrReject returns true if (uuid, nonce) is being seen for the
// first time within the window, false if it is a replay. On true, the
// pair is recorded and will be remembered until window has elapsed
// since now.
//
// The check is constant-time-equal-irrelevant: the value is the
// (uuid, nonce) pair itself, which is already authenticated by the
// outer MAC by the time we are called, so timing leaks of map lookups
// reveal nothing the attacker doesn't already know.
func (c *ReplayCache) MarkSeenOrReject(
	uuid [UUIDLen]byte,
	nonce [HandshakeNonce]byte,
) bool {
	now := time.Now()
	expiry := now.Add(c.window)
	key := makeReplayKey(uuid, nonce)
	s := c.shardOf(key)

	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.entries[key]; ok {
		if exp.After(now) {
			return false
		}
		delete(s.entries, key)
		c.total.Add(^uint64(0))
	}
	if !c.reserveEntry() {
		return false
	}
	s.entries[key] = expiry

	s.gcCounter++
	if s.gcCounter >= gcInterval {
		s.gcCounter = 0
		// Per-shard opportunistic sweep. Keeps a hot shard from
		// growing unboundedly between background ticks.
		for k, exp := range s.entries {
			if !exp.After(now) {
				delete(s.entries, k)
				c.total.Add(^uint64(0))
			}
		}
	}
	return true
}

func (c *ReplayCache) reserveEntry() bool {
	for {
		current := c.total.Load()
		if current >= maxReplayEntries {
			return false
		}
		if c.total.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// Len returns the current number of remembered pairs across all
// shards. Intended for metrics / tests; the value is racy by definition
// under concurrent admits and should not be used for control flow.
func (c *ReplayCache) Len() int {
	return int(c.total.Load())
}

// ErrReplay is returned by AcceptClientHello when a ClientHello with a
// previously-seen (UUID, nonce) pair is received within the replay
// window, AND when a ClientHello timestamp falls outside the
// HandshakeTimestampWindow. The two failure modes are deliberately
// merged onto the same sentinel so that a network attacker observing
// only the absence of a ServerHello cannot distinguish "I have seen
// this before" from "your clock is out of sync" — both leak no
// information about other clients on the same server.
var ErrReplay = errSentinel("ewp/v2: replayed ClientHello rejected")

// errSentinel exists so we can declare ErrReplay as a typed error
// without importing errors at this file's scope twice. It is a thin
// wrapper around the standard error contract.
type errSentinel string

func (e errSentinel) Error() string { return string(e) }
