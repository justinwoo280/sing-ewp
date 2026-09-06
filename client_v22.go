package ewp

import (
	"context"
	"net"
)

// ClientV22 is the EWP/v2.2 client. It uses the v2.2 handshake labels and
// opaque record codec; it does not fall back to v2.1 after a failure.
type ClientV22 struct {
	*ClientV21
}

// NewClientV22 parses a UUID and pinned server static public key for the v2.2
// suite. Both peers must be upgraded together because v2.1 rejects the v2.2
// handshake authentication labels.
func NewClientV22(uuidStr, serverStaticPubB64 string) (*ClientV22, error) {
	client, err := newClientV2x(uuidStr, serverStaticPubB64, protocolVersionV22)
	if err != nil {
		return nil, err
	}
	return &ClientV22{ClientV21: client}, nil
}

// UUID returns the configured user UUID.
func (c *ClientV22) UUID() [UUIDLen]byte { return c.ClientV21.UUID() }

// DialConn opens an opaque-record v2.2 TCP stream.
func (c *ClientV22) DialConn(ctx context.Context, conn net.Conn, dst Address) (net.Conn, error) {
	return c.ClientV21.DialConn(ctx, conn, dst)
}

// DialPacketConn opens an opaque-record v2.2 UDP stream.
func (c *ClientV22) DialPacketConn(ctx context.Context, conn net.Conn, dst Address) (net.PacketConn, error) {
	return c.ClientV21.DialPacketConn(ctx, conn, dst)
}

// ServiceV22 is the EWP/v2.2 service. Its embedded implementation retains the
// v2.1 management surface (AddUser, RemoveUser, Users, Close) while selecting
// the v2.2 handshake and record suite for every connection.
type ServiceV22 struct {
	*ServiceV21
}

// NewServiceV22 creates a v2.2-only service. It rejects v2.1 handshakes
// rather than trying an alternate derivation or record codec.
func NewServiceV22(h Handler, staticPrivB64 string) (*ServiceV22, error) {
	service, err := newServiceV2x(h, staticPrivB64, protocolVersionV22)
	if err != nil {
		return nil, err
	}
	return &ServiceV22{ServiceV21: service}, nil
}
