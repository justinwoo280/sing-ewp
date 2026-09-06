package ewp

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestV3SecureStreamMultiplexesUDPSubSessionsAndTargets(t *testing.T) {
	clientTransport, serverTransport := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(clientTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(serverTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}

	targets := map[[8]byte]Address{
		{1}: {Domain: "one.example", Port: 1001},
		{2}: {Domain: "two.example", Port: 1002},
	}
	payloads := map[[8]byte]string{
		{1}: "first sub-session",
		{2}: "second sub-session",
	}
	serverDone := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			event, err := server.Recv()
			if err != nil {
				serverDone <- err
				return
			}
			if event.Type != FrameUDPNew && event.Type != FrameUDPData {
				serverDone <- errors.New("unexpected non-UDP event")
				return
			}
			target := event.Address
			if event.Type == FrameUDPData && string(event.Payload) == "default target" {
				target = Address{}
			}
			if err := server.SendUDPData(event.GlobalID, target, event.Payload); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	for gid, target := range targets {
		if err := client.SendUDPNew(gid, target, []byte(payloads[gid])); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.SendUDPData([8]byte{1}, Address{}, []byte("default target")); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		event, err := recvV3EventWithTimeout(client, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if event.Type != FrameUDPData {
			t.Fatalf("event type = %d, want UDP_DATA", event.Type)
		}
		if i < 2 {
			wantTarget, ok := targets[event.GlobalID]
			if !ok {
				t.Fatalf("unknown globalID %v", event.GlobalID)
			}
			if event.Address != wantTarget || !event.HasAddr {
				t.Fatalf("target for %v = %#v/%v, want %#v/true", event.GlobalID, event.Address, event.HasAddr, wantTarget)
			}
			if string(event.Payload) != payloads[event.GlobalID] {
				t.Fatalf("payload for %v = %q", event.GlobalID, event.Payload)
			}
		} else {
			if event.GlobalID != [8]byte{1} || event.HasAddr || event.Address != (Address{}) {
				t.Fatalf("default-target event = %#v", event)
			}
			if string(event.Payload) != "default target" {
				t.Fatalf("default-target payload = %q", event.Payload)
			}
		}
	}

	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = server.Close()
}

func TestV3PacketConnRejectsRepeatedUDPNew(t *testing.T) {
	clientTransport, serverTransport := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(clientTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(serverTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	gid := [8]byte{0x31}
	defaultTarget := Address{Domain: "repeat.example", Port: 443}
	pc := newClientPacketConnWithRuntime(client, nil, defaultTarget, newV3Runtime(time.Unix(1_700_000_000, 0)))
	pc.globalID = gid
	pc.opened = true
	if err := server.SendUDPNew(gid, defaultTarget, []byte("unexpected")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pc.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("repeated UDP_NEW was accepted by packet connection")
	}
}

func TestV3PacketConnKeepsRemoteEndState(t *testing.T) {
	clientTransport, serverTransport := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(clientTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(serverTransport, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	gid := [8]byte{0x32}
	pc := newClientPacketConnWithRuntime(client, nil, Address{Domain: "end.example", Port: 53}, newV3Runtime(time.Unix(1_700_000_000, 0)))
	pc.globalID = gid
	pc.opened = true
	if err := server.SendUDPEnd(gid); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, _, err := pc.ReadFrom(make([]byte, 64)); !errors.Is(err, io.EOF) {
			t.Fatalf("remote UDP_END read %d error = %v", i, err)
		}
	}
	if _, err := pc.WriteToAddress([]byte("after-end"), Address{Domain: "end.example", Port: 53}); !errors.Is(err, ErrPacketConnClosed) {
		t.Fatalf("write after remote UDP_END error = %v", err)
	}
}

func TestV3GlobalIDSkipsZero(t *testing.T) {
	random := bytes.NewReader(append(make([]byte, 8), bytes.Repeat([]byte{0x5a}, 8)...))
	id := newGlobalIDWithReader(random)
	if id == ([8]byte{}) {
		t.Fatal("global ID generator returned the zero value")
	}
}

func TestV3PacketAddressAcceptsPointerFQDN(t *testing.T) {
	address, err := addrToEWP(&FqdnAddr{Fqdn: "pointer.example", Port: 5353})
	if err != nil {
		t.Fatal(err)
	}
	if address.Domain != "pointer.example" || address.Port != 5353 {
		t.Fatalf("pointer FQDN address = %#v", address)
	}
}

func recvV3EventWithTimeout(stream *SecureStream, timeout time.Duration) (*Event, error) {
	result := make(chan struct {
		event *Event
		err   error
	}, 1)
	go func() {
		event, err := stream.Recv()
		result <- struct {
			event *Event
			err   error
		}{event: event, err: err}
	}()
	select {
	case value := <-result:
		return value.event, value.err
	case <-time.After(timeout):
		return nil, errors.New("timed out waiting for UDP event")
	}
}
