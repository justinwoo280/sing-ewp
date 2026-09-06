package ewp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestV3TCPHandlerAsyncHandoffKeepsConnectionOpen(t *testing.T) {
	fixture := newV3Fixture(t)
	handler := &v3AsyncRouteHandler{dispatched: make(chan Metadata, 1)}
	service := fixture.newService(t, handler, nil)
	defer service.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()

	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, clientConn, Address{Domain: "handoff.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case metadata := <-handler.dispatched:
		if metadata.Destination.Domain != "handoff.example" {
			t.Fatalf("unexpected metadata: %#v", metadata)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not dispatched")
	}

	// The handler returned immediately; the connection must stay usable.
	payload := []byte("async handoff echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write after async handoff: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read after async handoff: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf[:n], payload)
	}

	// Closing the client conn lets the server handler goroutine close its
	// side, which unblocks handleTransport.
	_ = conn.Close()
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish after client close")
	}
}

func TestV3TCPHandlerErrorClosesImmediately(t *testing.T) {
	fixture := newV3Fixture(t)
	service := fixture.newService(t, v3FailHandler{}, nil)
	defer service.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()

	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The handler rejects the connection after Finished. Depending on the
	// byte-level race between ServerFinished delivery and the rejection
	// teardown, the client either fails the handshake or gets a connection
	// that is closed immediately. Both are correct; the load-bearing
	// assertion is that the server returns the handler error promptly.
	conn, err := client.DialConn(ctx, clientConn, Address{Domain: "fail.example", Port: 443})
	if err == nil {
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, rerr := conn.Read(make([]byte, 1)); rerr == nil {
			t.Fatal("read unexpectedly succeeded after handler rejection")
		}
	}
	select {
	case serr := <-serverDone:
		if serr == nil {
			t.Fatal("server returned nil after handler rejection")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish after handler rejection")
	}
}

func TestV3TCPRoundTrip(t *testing.T) {
	fixture := newV3Fixture(t)
	called := make(chan Metadata, 1)
	service := fixture.newService(t, &v3EchoHandler{called: called}, nil)
	defer service.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()

	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, clientConn, Address{Domain: "tcp.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case metadata := <-called:
		if metadata.PrincipalID != fixture.principal.ID || metadata.Destination.Domain != "tcp.example" {
			t.Fatalf("unexpected metadata: %#v", metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("handler was not dispatched")
	}
	if _, err := conn.Write([]byte("v3 tcp")); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "v3 tcp" {
		t.Fatalf("echo = %q", buf[:n])
	}
	_ = conn.Close()
	select {
	case serverErr := <-serverDone:
		if serverErr != nil {
			t.Logf("server rejection: %v", serverErr)
		}
	case <-time.After(time.Second):
		t.Fatal("server handler did not finish")
	}
}

func TestV3MessageTransportTCPHighLevelAPI(t *testing.T) {
	fixture := newV3Fixture(t)
	called := make(chan Metadata, 1)
	service := fixture.newService(t, &v3EchoHandler{called: called}, nil)
	defer service.Close()

	clientTransport, serverTransport := newV3DuplexPair()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.HandleMessageTransportWithSource(context.Background(), serverTransport, SourceBinding("carrier-peer"))
	}()

	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialMessageTransport(ctx, clientTransport, Address{Domain: "carrier.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(interface{ Rekey() error }); !ok {
		t.Fatal("high-level message transport connection does not expose rekey")
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); !errors.Is(err, ErrV3DeadlineUnsupported) {
		t.Fatalf("unsupported read deadline error = %v", err)
	}
	if _, err := conn.Write([]byte("message transport tcp")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "message transport tcp" {
		t.Fatalf("echo = %q", buf[:n])
	}
	select {
	case metadata := <-called:
		if metadata.Destination != (Address{Domain: "carrier.example", Port: 443}) {
			t.Fatalf("unexpected metadata: %#v", metadata)
		}
		if metadata.Source != nil {
			t.Fatalf("unexpected source without transport address: %v", metadata.Source)
		}
	case <-time.After(time.Second):
		t.Fatal("handler was not dispatched")
	}
	_ = conn.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server handler did not finish")
	}
}

func TestV3MessageTransportCarriesInfoAndDeadlines(t *testing.T) {
	fixture := newV3Fixture(t)
	called := make(chan Metadata, 1)
	service := fixture.newService(t, &v3EchoHandler{called: called}, nil)
	defer service.Close()

	clientTransport, serverTransport := newV3AddressedDuplexPair()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.HandleMessageTransportWithSource(context.Background(), serverTransport, SourceBinding("carrier-peer"))
	}()

	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialMessageTransport(ctx, clientTransport, Address{Domain: "addressed.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if conn.LocalAddr() == nil || conn.LocalAddr().String() != clientTransport.local.String() {
		t.Fatalf("local address = %v", conn.LocalAddr())
	}
	if conn.RemoteAddr() == nil || conn.RemoteAddr().String() != clientTransport.remote.String() {
		t.Fatalf("remote address = %v", conn.RemoteAddr())
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("addressed carrier")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "addressed carrier" {
		t.Fatalf("echo = %q, err = %v", buf[:n], err)
	}
	select {
	case metadata := <-called:
		if metadata.Source == nil || metadata.Source.String() != clientTransport.local.String() {
			t.Fatalf("metadata source = %v", metadata.Source)
		}
	case <-time.After(time.Second):
		t.Fatal("handler was not dispatched")
	}
	_ = conn.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server handler did not finish")
	}
}

func TestV3ServiceCloseCancelsApplicationHandler(t *testing.T) {
	fixture := newV3Fixture(t)
	handler := &v3ContextBlockingHandler{started: make(chan struct{}), stopped: make(chan struct{})}
	service := fixture.newService(t, handler, nil)

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()
	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialConn(ctx, clientConn, Address{Domain: "close.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("application handler did not start")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.stopped:
	case <-time.After(time.Second):
		t.Fatal("application handler did not observe service close")
	}
	_ = conn.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not finish after service close")
	}
}

func TestV3UDPRoundTrip(t *testing.T) {
	fixture := newV3Fixture(t)
	called := make(chan Metadata, 1)
	service := fixture.newService(t, &v3UDPEchoHandler{called: called}, nil)
	defer service.Close()

	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()

	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	destination := Address{Domain: "udp.example", Port: 53}
	pc, err := client.DialPacketConn(ctx, clientConn, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.(*packetConn).WriteToAddress([]byte("v3 udp"), destination); err != nil {
		t.Fatal(err)
	}
	select {
	case metadata := <-called:
		if metadata.PrincipalID != fixture.principal.ID || metadata.Destination != destination {
			t.Fatalf("unexpected metadata: %#v", metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP handler was not dispatched")
	}
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, source, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "v3 udp" || source == nil {
		t.Fatalf("echo = %q from %v", buf[:n], source)
	}
	_ = pc.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("UDP handler did not finish")
	}
}

func TestV3MessageTransportUDPUsesFirstPacketTarget(t *testing.T) {
	fixture := newV3Fixture(t)
	called := make(chan Metadata, 1)
	service := fixture.newService(t, &v3UDPEchoHandler{called: called}, nil)
	defer service.Close()

	clientTransport, serverTransport := newV3DuplexPair()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.HandleMessageTransportWithSource(context.Background(), serverTransport, SourceBinding("carrier-peer"))
	}()

	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	anchor := Address{Domain: "anchor.example", Port: 53}
	firstTarget := Address{Domain: "first-packet.example", Port: 5353}
	pc, err := client.DialPacketMessageTransport(ctx, clientTransport, anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	packetConn, ok := pc.(*packetConn)
	if !ok {
		t.Fatal("message transport packet connection has unexpected type")
	}
	if _, err := packetConn.WriteToAddress([]byte("message transport udp"), firstTarget); err != nil {
		t.Fatal(err)
	}
	select {
	case metadata := <-called:
		if metadata.Destination != anchor {
			t.Fatalf("anchor destination = %#v, want %#v", metadata.Destination, anchor)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP handler was not dispatched")
	}
	buf := make([]byte, 64)
	n, source, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "message transport udp" {
		t.Fatalf("echo = %q", buf[:n])
	}
	if source == nil || source.String() != firstTarget.String() {
		t.Fatalf("first packet source = %v, want %v", source, firstTarget)
	}
	_ = pc.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("UDP server handler did not finish")
	}
}

func TestV3HandlerWaitsForClientFinished(t *testing.T) {
	fixture := newV3Fixture(t)
	called := make(chan Metadata, 1)
	service := fixture.newService(t, &v3EchoHandler{called: called}, nil)
	defer service.Close()

	clientConn, serverConn := net.Pipe()
	clientTransport := NewLengthFramer(clientConn)
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()

	state, initBytes, err := startV3ClientHandshake(fixture.credential, fixture.identity.Public, fixture.material.Bundle, CommandTCP, Address{Domain: "gate.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	if err := clientTransport.SendMessage(initBytes); err != nil {
		t.Fatal(err)
	}
	retryBytes, err := clientTransport.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	retry, err := ParseV3HelloRetry(retryBytes)
	if err != nil {
		t.Fatal(err)
	}
	helloBytes, err := state.buildClientHello(retry)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientTransport.SendMessage(helloBytes); err != nil {
		t.Fatal(err)
	}
	serverHelloBytes, err := clientTransport.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
		t.Fatal("handler ran before ClientFinished")
	default:
	}
	_, pending, clientFinishedBytes, err := state.completeServerHello(serverHelloBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientTransport.SendMessage(clientFinishedBytes); err != nil {
		t.Fatal(err)
	}
	serverFinishedBytes, err := clientTransport.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	tClientFinished := v3Hash("ewp/v3/client-finished", pending.TServerHello[:], clientFinishedBytes)
	if _, err := verifyV3ServerFinished(fixture.listener, pending, serverFinishedBytes, tClientFinished); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("handler was not dispatched after Finished")
	}
	_ = clientTransport.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not finish after transport close")
	}
}

func TestV3ServerFinishedFailureClosesWithoutResume(t *testing.T) {
	fixture := newV3Fixture(t)
	called := make(chan Metadata, 1)
	service := fixture.newService(t, &v3EchoHandler{called: called}, nil)
	defer service.Close()

	clientTransport, serverBase := newV3DuplexPair()
	serverTransport := &v3FailServerFinishedTransport{v3DuplexTransport: serverBase, fail: true}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.HandleMessageTransportWithSource(context.Background(), serverTransport, SourceBinding("finished-failure"))
	}()

	client := fixture.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialMessageTransport(ctx, clientTransport, Address{Domain: "finished-failure.example", Port: 443})
	if err == nil || conn != nil {
		t.Fatalf("failed Finished dial = conn %v err %v", conn, err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not close after ServerFinished failure")
	}
	select {
	case metadata := <-called:
		t.Fatalf("handler ran after ServerFinished failure: %#v", metadata)
	default:
	}
}

func TestV3InvalidCookieStopsBeforeClaimAndKEM(t *testing.T) {
	fixture := newV3Fixture(t)
	countingProvider := &v3CountingPreKeyProvider{inner: fixture.provider}
	countingAdmission := &v3CountingAdmission{}
	countingAdmission.allowInit.Store(true)
	countingAdmission.allowHello.Store(true)
	called := make(chan Metadata, 1)
	service, err := NewServiceV3(&v3EchoHandler{called: called}, fixture.listener, fixture.identity, countingProvider, countingAdmission)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	clientConn, serverConn := net.Pipe()
	clientTransport := NewLengthFramer(clientConn)
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()
	state, initBytes, err := startV3ClientHandshake(fixture.credential, fixture.identity.Public, fixture.material.Bundle, CommandTCP, Address{Domain: "bad-cookie.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	if err := clientTransport.SendMessage(initBytes); err != nil {
		t.Fatal(err)
	}
	retryBytes, err := clientTransport.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	retry, err := ParseV3HelloRetry(retryBytes)
	if err != nil {
		t.Fatal(err)
	}
	helloBytes, err := state.buildClientHello(retry)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := ParseV3ClientHello(helloBytes)
	if err != nil {
		t.Fatal(err)
	}
	hello.Retry.Cookie[0] ^= 1
	helloBytes, err = hello.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := clientTransport.SendMessage(helloBytes); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not reject invalid cookie")
	}
	if got := countingProvider.claims.Load(); got != 0 {
		t.Fatalf("prekey claims = %d, want 0", got)
	}
	if got := countingAdmission.kemCalls.Load(); got != 0 {
		t.Fatalf("KEM acquisitions = %d, want 0", got)
	}
	if got := countingAdmission.helloCalls.Load(); got != 0 {
		t.Fatalf("hello admissions = %d, want 0", got)
	}
	select {
	case <-called:
		t.Fatal("handler ran for invalid cookie")
	default:
	}
}

func TestV3InvalidAdmissionStopsBeforeClaimAndKEM(t *testing.T) {
	fixture := newV3Fixture(t)
	countingProvider := &v3CountingPreKeyProvider{inner: fixture.provider}
	countingAdmission := &v3CountingAdmission{}
	countingAdmission.allowInit.Store(true)
	countingAdmission.allowHello.Store(true)
	called := make(chan Metadata, 1)
	service, err := NewServiceV3(&v3EchoHandler{called: called}, fixture.listener, fixture.identity, countingProvider, countingAdmission)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	clientConn, serverConn := net.Pipe()
	clientTransport := NewLengthFramer(clientConn)
	serverDone := make(chan error, 1)
	go func() { serverDone <- service.HandleConn(context.Background(), serverConn) }()
	state, initBytes, err := startV3ClientHandshake(fixture.credential, fixture.identity.Public, fixture.material.Bundle, CommandTCP, Address{Domain: "bad-admission.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	if err := clientTransport.SendMessage(initBytes); err != nil {
		t.Fatal(err)
	}
	retryBytes, err := clientTransport.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	retry, err := ParseV3HelloRetry(retryBytes)
	if err != nil {
		t.Fatal(err)
	}
	helloBytes, err := state.buildClientHello(retry)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := ParseV3ClientHello(helloBytes)
	if err != nil {
		t.Fatal(err)
	}
	hello.AdmissionTag[0] ^= 1
	helloBytes, err = hello.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := clientTransport.SendMessage(helloBytes); err != nil {
		t.Fatal(err)
	}
	select {
	case serverErr := <-serverDone:
		if serverErr != nil {
			t.Logf("server rejection: %v", serverErr)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not reject invalid admission")
	}
	if got := countingAdmission.helloCalls.Load(); got != 0 {
		t.Fatalf("hello admissions = %d, want 0", got)
	}
	if got := countingAdmission.kemCalls.Load(); got != 0 {
		t.Fatalf("KEM acquisitions = %d, want 0", got)
	}
	if got := countingProvider.claims.Load(); got != 0 {
		t.Fatalf("prekey claims = %d, want 0", got)
	}
	select {
	case <-called:
		t.Fatal("handler ran for invalid admission")
	default:
	}
}

func TestV3TransportCloseUnblocksRead(t *testing.T) {
	left, right := newV3DuplexPair()
	result := make(chan error, 1)
	go func() {
		_, err := left.ReadMessage()
		result <- err
	}()
	if err := right.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("transport read remained blocked")
	}
}

type v3OversizedTransport struct{}

func (v3OversizedTransport) SendMessage([]byte) error { return nil }
func (v3OversizedTransport) ReadMessage() ([]byte, error) {
	return make([]byte, MaxV3MessageSize+1), nil
}
func (v3OversizedTransport) Close() error { return nil }

func TestV3TransportContextCancellationAndMessageBound(t *testing.T) {
	left, right := newV3DuplexPair()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := readV3MessageContext(ctx, left)
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not unblock transport read")
	}
	_ = right.Close()

	if _, err := readV3MessageContext(context.Background(), v3OversizedTransport{}); !errors.Is(err, ErrV3MessageTooLarge) {
		t.Fatalf("oversized transport error = %v", err)
	}
}
