package ewp

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"
)

func TestV3TranscriptsRetainUnknownNonCriticalBytes(t *testing.T) {
	fixture := newV3Fixture(t)
	state, initBytes, err := startV3ClientHandshake(fixture.credential, fixture.identity.Public, fixture.material.Bundle, CommandTCP, Address{Domain: "transcript.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	extraInit, err := encodeV3Fields(v3Bytes(100, []byte("init-extension")))
	if err != nil {
		t.Fatal(err)
	}
	initWithExtension := append(append([]byte(nil), initBytes...), extraInit...)
	parsedInit, err := ParseV3ClientInit(initWithExtension)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedInit.wireBytes(), initWithExtension) {
		t.Fatal("ClientInit raw bytes were not retained")
	}
	wantBase, err := v3WithoutField(initWithExtension, v3TagCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedInit.baseWireBytes(), wantBase) {
		t.Fatal("ClientInitBase raw bytes were not retained")
	}

	coreBytes, err := state.core.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	extraCore, err := encodeV3Fields(v3Bytes(100, []byte("core-extension")))
	if err != nil {
		t.Fatal(err)
	}
	coreWithExtension := append(append([]byte(nil), coreBytes...), extraCore...)
	parsedCore, err := ParseV3ClientHelloCore(coreWithExtension)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedCore.wireBytes(), coreWithExtension) {
		t.Fatal("ClientHelloCore raw bytes were not retained")
	}
	gotDigest, err := parsedCoreDigest(parsedCore)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(coreWithExtension)
	if gotDigest != wantDigest {
		t.Fatal("ClientHelloCore digest did not use exact wire bytes")
	}
}

func TestV3ClientInitUsesRetrySafeMinimumPadding(t *testing.T) {
	fixture := newV3Fixture(t)
	state, initBytes, err := startV3ClientHandshake(fixture.credential, fixture.identity.Public, fixture.material.Bundle, CommandTCP, Address{Domain: "padding.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	if len(initBytes) < V3MinClientInitSize {
		t.Fatalf("ClientInit size = %d, want at least %d", len(initBytes), V3MinClientInitSize)
	}
	parsed, err := ParseV3ClientInit(initBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Padding) == 0 {
		t.Fatal("ClientInit did not carry retry-safe padding")
	}
	if !bytes.Equal(parsed.baseWireBytes(), state.initBaseBytes) {
		t.Fatal("ClientInitBase bytes changed after parsing")
	}
}

func TestV3ClientHelloReencodeRetainsNestedWireBytes(t *testing.T) {
	fixture := newV3Fixture(t)
	state, _, err := startV3ClientHandshake(fixture.credential, fixture.identity.Public, fixture.material.Bundle, CommandTCP, Address{Domain: "nested.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer state.destroy()
	retry := V3HelloRetry{
		Version:     fixture.listener.Version,
		Suite:       fixture.listener.Suite,
		InitNonce:   state.init.InitNonce,
		RetryNonce:  V3Nonce{1},
		CookieKeyID: 1,
		ExpiresAt:   uint64(time.Now().Add(time.Minute).Unix()),
		Cookie:      [V3CookieLen]byte{2},
	}
	helloBytes, err := state.buildClientHello(retry)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := ParseV3ClientHello(helloBytes)
	if err != nil {
		t.Fatal(err)
	}
	initExtra, err := encodeV3Fields(v3Bytes(100, []byte("init-extension")))
	if err != nil {
		t.Fatal(err)
	}
	coreExtra, err := encodeV3Fields(v3Bytes(101, []byte("core-extension")))
	if err != nil {
		t.Fatal(err)
	}
	initWire := append(append([]byte(nil), hello.Init.wireBytes()...), initExtra...)
	coreWire := append(append([]byte(nil), hello.Core.wireBytes()...), coreExtra...)
	parsedInit, err := ParseV3ClientInit(initWire)
	if err != nil {
		t.Fatal(err)
	}
	parsedCore, err := ParseV3ClientHelloCore(coreWire)
	if err != nil {
		t.Fatal(err)
	}
	hello.Init = parsedInit
	hello.Core = parsedCore
	reencoded, err := hello.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV3ClientHello(reencoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Init.wireBytes(), initWire) || !bytes.Equal(parsed.Core.wireBytes(), coreWire) {
		t.Fatal("re-encoding discarded nested exact bytes")
	}
}

func parsedCoreDigest(core V3ClientHelloCore) ([32]byte, error) {
	return sha256.Sum256(core.wireBytes()), nil
}
