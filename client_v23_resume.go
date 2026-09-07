package ewp

import (
	"fmt"
	"sync"
)

// EWP/v2.3.1 client-side resumption glue: the ticket store interface, a
// memory implementation, and ClientV23's resumption wiring.
// See EWP_V231_RESUMPTION.md §8.

// V23TicketStore caches resumption tickets, one per server. A nil store on
// ClientV23 (the default) disables resumption entirely: the client always
// runs the full six-stage handshake, byte-identical to v2.3.0.
//
// The client never parses ticket contents: expiry enforcement is the
// server's job (via the sealed expiryTime), and rejection costs nothing but
// one normal HelloRetry round.
type V23TicketStore interface {
	// Get returns a ticket for serverKey ("serverID@addr"), if any.
	Get(serverKey string) (ticket []byte, ok bool)
	// Put stores the most recent ticket, replacing any previous one.
	Put(serverKey string, ticket []byte)
	// Delete drops the ticket (e.g. a hard failure with an extended
	// ClientInit suggests a server downgrade).
	Delete(serverKey string)
}

// MemoryV23TicketStore is a trivial in-memory V23TicketStore. It is safe for
// concurrent use and has no persistence: a process restart simply resumes
// through one full handshake.
type MemoryV23TicketStore struct {
	mu      sync.RWMutex
	tickets map[string][]byte
}

// NewMemoryV23TicketStore builds an empty store.
func NewMemoryV23TicketStore() *MemoryV23TicketStore {
	return &MemoryV23TicketStore{tickets: make(map[string][]byte)}
}

// Get implements V23TicketStore.
func (m *MemoryV23TicketStore) Get(serverKey string) ([]byte, bool) {
	m.mu.RLock()
	t, ok := m.tickets[serverKey]
	m.mu.RUnlock()
	return t, ok
}

// Put implements V23TicketStore.
func (m *MemoryV23TicketStore) Put(serverKey string, ticket []byte) {
	if len(ticket) == 0 {
		return
	}
	m.mu.Lock()
	m.tickets[serverKey] = append([]byte(nil), ticket...)
	m.mu.Unlock()
}

// Delete implements V23TicketStore.
func (m *MemoryV23TicketStore) Delete(serverKey string) {
	m.mu.Lock()
	delete(m.tickets, serverKey)
	m.mu.Unlock()
}

// SetTicketStore installs a resumption ticket store on the client. Passing
// nil restores v2.3.0 behavior. Not safe for concurrent use with Dial.
func (c *ClientV23) SetTicketStore(store V23TicketStore) {
	c.ticketStore = store
}

// v23TicketServerKey builds the store key from the pinned server identity
// and the transport address.
func (c *ClientV23) v23TicketServerKey(remoteAddr string) string {
	return fmt.Sprintf("%s@%s", c.serverID, remoteAddr)
}
