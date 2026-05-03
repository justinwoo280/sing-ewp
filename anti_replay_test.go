package ewp

import (
	"sync"
	"testing"
	"time"
)

func TestReplayCache_FirstSeenAdmits(t *testing.T) {
	c := NewReplayCache(time.Second)
	var u [UUIDLen]byte
	var n [HandshakeNonce]byte
	u[0] = 0xab
	n[0] = 0xcd
	if !c.MarkSeenOrReject(u, n) {
		t.Fatal("first sight should admit")
	}
}

func TestReplayCache_SecondSeenRejects(t *testing.T) {
	c := NewReplayCache(time.Second)
	var u [UUIDLen]byte
	var n [HandshakeNonce]byte
	if !c.MarkSeenOrReject(u, n) {
		t.Fatal("first sight should admit")
	}
	if c.MarkSeenOrReject(u, n) {
		t.Fatal("replay should be rejected")
	}
}

func TestReplayCache_DistinctNoncesIndependent(t *testing.T) {
	c := NewReplayCache(time.Second)
	var u [UUIDLen]byte
	var n1, n2 [HandshakeNonce]byte
	n2[0] = 0x01
	if !c.MarkSeenOrReject(u, n1) {
		t.Fatal("n1 first sight")
	}
	if !c.MarkSeenOrReject(u, n2) {
		t.Fatal("n2 should still admit (different nonce)")
	}
}

func TestReplayCache_DistinctUUIDsIndependent(t *testing.T) {
	c := NewReplayCache(time.Second)
	var u1, u2 [UUIDLen]byte
	u2[0] = 0xff
	var n [HandshakeNonce]byte
	if !c.MarkSeenOrReject(u1, n) {
		t.Fatal("u1 first sight")
	}
	if !c.MarkSeenOrReject(u2, n) {
		t.Fatal("u2 should still admit (different UUID)")
	}
}

func TestReplayCache_ExpiryReadmits(t *testing.T) {
	// Window of 1 second; the entry's expiry is computed from
	// time.Now().Unix(), so we must wait > 1 full second of wall
	// clock to be sure we cross the boundary.
	c := NewReplayCache(time.Second)
	var u [UUIDLen]byte
	var n [HandshakeNonce]byte
	if !c.MarkSeenOrReject(u, n) {
		t.Fatal("first")
	}
	time.Sleep(1100 * time.Millisecond)
	if !c.MarkSeenOrReject(u, n) {
		t.Fatal("after window expiry, the same pair should re-admit")
	}
}

func TestReplayCache_ConcurrentAdmitsRaceFree(t *testing.T) {
	// Run a high-contention burst through MarkSeenOrReject and
	// confirm exactly one goroutine sees the "admit" outcome.
	c := NewReplayCache(time.Minute)
	var u [UUIDLen]byte
	var n [HandshakeNonce]byte

	const workers = 64
	var (
		wg       sync.WaitGroup
		admits   int
		admitsMu sync.Mutex
	)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if c.MarkSeenOrReject(u, n) {
				admitsMu.Lock()
				admits++
				admitsMu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if admits != 1 {
		t.Fatalf("expected exactly 1 admit under contention, got %d", admits)
	}
}

func TestReplayCache_GCEvictsExpired(t *testing.T) {
	// Force enough admits to trigger the opportunistic sweep, then
	// verify Len shrinks back to roughly the live-set size.
	c := NewReplayCache(20 * time.Millisecond)
	var u [UUIDLen]byte
	var n [HandshakeNonce]byte
	for i := 0; i < gcInterval+10; i++ {
		// vary the nonce so each call admits a new entry
		n[0] = byte(i)
		n[1] = byte(i >> 8)
		_ = c.MarkSeenOrReject(u, n)
	}
	// Sleep past the window so all earlier entries are expired, then
	// admit one more — that admit triggers the per-N sweep.
	time.Sleep(100 * time.Millisecond)
	n[0] = 0xff
	n[1] = 0xff
	for i := 0; i < gcInterval; i++ {
		n[2] = byte(i)
		_ = c.MarkSeenOrReject(u, n)
	}
	// After the sweep, only the freshly-inserted gcInterval entries
	// should remain; we allow some slack because gc only runs every
	// gcInterval admits.
	if got := c.Len(); got > 2*gcInterval {
		t.Fatalf("GC failed to bound cache size: %d entries remain", got)
	}
}
