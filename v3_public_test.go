package ewp_test

import (
	"context"
	"errors"
	"net"
	"testing"

	ewp "github.com/justinwoo280/sing-ewp"
)

type publicHandler struct{}

func (publicHandler) NewConnection(context.Context, net.Conn, ewp.Metadata) error {
	return errors.New("public API test handler")
}

func (publicHandler) NewPacketConnection(context.Context, net.PacketConn, ewp.Metadata) error {
	return errors.New("public API test packet handler")
}

func TestV3PublicConstructorsHaveExplicitDependencies(t *testing.T) {
	identity, err := ewp.GenerateServerSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	listener := ewp.V3ListenerContext{
		Version:         ewp.V3ProtocolVersion,
		Suite:           ewp.V3SuiteX25519MLKEM768ChaCha20Poly1305,
		ServerID:        "public-server",
		DeploymentScope: "public-scope",
	}
	var auth [ewp.V3KAuthLen]byte
	auth[0] = 1
	credential := ewp.ClientCredential{KAuth: auth, Listener: listener}
	provider, err := ewp.NewMemoryPreKeyProvider()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ewp.NewClientV3(credential, identity.Public, provider); err != nil {
		t.Fatal(err)
	}
	admission, err := ewp.NewV3AdmissionController(4, 4, 2, 2, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	service, err := ewp.NewServiceV3(publicHandler{}, listener, identity, provider, admission)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}
