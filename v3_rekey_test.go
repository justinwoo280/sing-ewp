package ewp

import (
	"testing"
	"time"
)

func testV3SessionKeys() V3SessionKeys {
	listener := V3ListenerContext{
		Version:         V3ProtocolVersion,
		Suite:           V3SuiteX25519MLKEM768ChaCha20Poly1305,
		ServerID:        "rekey-server",
		DeploymentScope: "rekey-scope",
	}
	var keys V3SessionKeys
	for i := range keys.C2SKey {
		keys.C2SKey[i] = byte(i + 1)
		keys.S2CKey[i] = byte(0x40 + i)
		keys.C2SUpdateSecret[i] = byte(0x80 + i)
		keys.S2CUpdateSecret[i] = byte(0xc0 + i)
	}
	for i := range keys.C2SNonce {
		keys.C2SNonce[i] = byte(0x10 + i)
		keys.S2CNonce[i] = byte(0x20 + i)
	}
	for i := range keys.TrafficTranscript {
		keys.TrafficTranscript[i] = byte(0xe0 + i)
	}
	keys.listener = listener
	return keys
}

func TestV3SecureStreamRekeyResetsCounterAndKeepsDirection(t *testing.T) {
	left, right := newV3DuplexPair()
	client, err := NewClientSecureStreamV3(left, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerSecureStreamV3(right, testV3SessionKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	serverEvent := make(chan struct {
		event *Event
		err   error
	}, 1)
	go func() {
		event, err := server.Recv()
		serverEvent <- struct {
			event *Event
			err   error
		}{event: event, err: err}
	}()
	if err := client.Rekey(); err != nil {
		t.Fatal(err)
	}
	if err := client.SendTCPData([]byte("after-client-rekey")); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-serverEvent:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if string(result.event.Payload) != "after-client-rekey" {
			t.Fatalf("server payload = %q", result.event.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive data after client rekey")
	}

	clientEvent := make(chan struct {
		event *Event
		err   error
	}, 1)
	go func() {
		event, err := client.Recv()
		clientEvent <- struct {
			event *Event
			err   error
		}{event: event, err: err}
	}()
	if err := server.Rekey(); err != nil {
		t.Fatal(err)
	}
	if err := server.SendTCPData([]byte("after-server-rekey")); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-clientEvent:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if string(result.event.Payload) != "after-server-rekey" {
			t.Fatalf("client payload = %q", result.event.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not receive data after server rekey")
	}
	_ = server.Close()
}

func TestV3RecordRekeyBindsDirectionAndEpoch(t *testing.T) {
	keys := testV3SessionKeys()
	client, err := newFrameAEAD(keys.C2SKey, keys.C2SNonce, keys.C2SUpdateSecret, v3RecordContext{
		listener:   keys.listener,
		transcript: keys.TrafficTranscript,
		sender:     v3RoleClient,
		receiver:   v3RoleServer,
		direction:  v3DirectionC2S,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newFrameAEAD(keys.C2SKey, keys.C2SNonce, keys.C2SUpdateSecret, v3RecordContext{
		listener:   keys.listener,
		transcript: keys.TrafficTranscript,
		sender:     v3RoleServer,
		receiver:   v3RoleClient,
		direction:  v3DirectionS2C,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientSecret, clientKey, clientPrefix, err := deriveFrameRekey(client)
	if err != nil {
		t.Fatal(err)
	}
	serverSecret, serverKey, serverPrefix, err := deriveFrameRekey(server)
	if err != nil {
		t.Fatal(err)
	}
	if clientSecret == serverSecret || clientKey == serverKey || clientPrefix == serverPrefix {
		t.Fatal("record rekey did not separate directions")
	}
}
