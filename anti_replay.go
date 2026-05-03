package ewp

import (
	"sync"
	"time"
)

// ReplayWindow is the duration for which a (UUID, nonce) tuple is
// remembered after first sight. It MUST be at least
// HandshakeTimestampWindow so that a replayed ClientHello cannot
// "outlive" the timestamp check by hiding in a fresh cache.
//
// We add a small grace margin to account for clock skew between client
// and server.
const ReplayWindow = (HandshakeTimestampWindow + 60) * time.Second

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

// ReplayCache is a sharded, time-bounded set of (UUID, nonce) pairs
// used to reject duplicate ClientHello messages within the handshake
// timestamp window.
//
// The zero value is NOT usable; construct with NewReplayCache.
//
// MarkSeenOrReject is the only operation callers need; entries expire
// implicitly via opportunistic GC on every Nth admit (no goroutine
// required, so a Service that is never used does not leak resources).
type ReplayCache struct {
	mu      sync.Mutex
	entries map[replayKey]int64 // value: unix-second expiry
	window  time.Duration

	// gcCounter triggers an opportunistic sweep every gcInterval admits.
	gcCounter uint32
}

// gcInterval is how many MarkSeenOrReject calls between sweeps. 1024
// is small enough that bursts of expired entries get freed promptly,
// large enough that the amortized cost is negligible.
const gcInterval = 1024

// NewReplayCache constructs a ReplayCache whose entries live for
// `window`. Pass ReplayWindow for the standard EWP/v2 setting.
func NewReplayCache(window time.Duration) *ReplayCache {
	return &ReplayCache{
		entries: make(map[replayKey]int64),
		window:  window,
	}
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
	now := time.Now().Unix()
	expiry := now + int64(c.window/time.Second)
	key := makeReplayKey(uuid, nonce)

	c.mu.Lock()
	defer c.mu.Unlock()

	if exp, ok := c.entries[key]; ok && exp > now {
		return false
	}
	c.entries[key] = expiry

	c.gcCounter++
	if c.gcCounter >= gcInterval {
		c.gcCounter = 0
		c.gcLocked(now)
	}
	return true
}

// gcLocked sweeps expired entries. Caller MUST hold c.mu.
func (c *ReplayCache) gcLocked(now int64) {
	for k, exp := range c.entries {
		if exp <= now {
			delete(c.entries, k)
		}
	}
}

// Len returns the current number of remembered pairs. Intended for
// metrics / tests; the value is racy by definition under concurrent
// admits and should not be used for control flow.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// ErrReplay is returned by AcceptClientHello when a ClientHello with a
// previously-seen (UUID, nonce) pair is received within the replay
// window.
var ErrReplay = errSentinel("ewp/v2: replayed ClientHello rejected")

// errSentinel exists so we can declare ErrReplay as a typed error
// without importing errors at this file's scope twice. It is a thin
// wrapper around the standard error contract.
type errSentinel string

func (e errSentinel) Error() string { return string(e) }
