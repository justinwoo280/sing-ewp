package ewp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestV3PreKeyBundleRoundTripAndSignature(t *testing.T) {
	fixture := newV3Fixture(t)
	encoded, err := fixture.material.Bundle.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV3PreKeyBundle(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !sameV3PreKeyBundle(parsed, fixture.material.Bundle) {
		t.Fatal("prekey bundle round-trip changed fields")
	}
	if err := parsed.Verify(fixture.identity.Public); err != nil {
		t.Fatal(err)
	}
	parsed.Signature[0] ^= 1
	if err := parsed.Verify(fixture.identity.Public); !errors.Is(err, ErrV3Signature) {
		t.Fatalf("tampered signature error = %v", err)
	}

	badVersion := fixture.material.Bundle
	badVersion.Version++
	if _, err := badVersion.MarshalBinary(); !errors.Is(err, ErrV3Version) {
		t.Fatalf("bad version error = %v", err)
	}
	badSuite := fixture.material.Bundle
	badSuite.Suite++
	if _, err := badSuite.MarshalBinary(); !errors.Is(err, ErrV3Suite) {
		t.Fatalf("bad suite error = %v", err)
	}
}

func TestV3PreKeyBundleRetainsSignedExtensionBytes(t *testing.T) {
	fixture := newV3Fixture(t)
	unsigned, err := fixture.material.Bundle.marshalUnsignedCanonical()
	if err != nil {
		t.Fatal(err)
	}
	extra, err := encodeV3Fields(v3Bytes(40, []byte("bundle-extension")))
	if err != nil {
		t.Fatal(err)
	}
	insertAt, _, err := v3FieldRegion(unsigned, v3TagBundleNotBefore)
	if err != nil {
		t.Fatal(err)
	}
	unsignedWithExtension := append(append(append([]byte(nil), unsigned[:insertAt]...), extra...), unsigned[insertAt:]...)
	signature := ed25519.Sign(fixture.identity.Private, v3Domain("ewp/v3/prekey-bundle", unsignedWithExtension))
	full, err := encodeV3Fields(
		v3U16(v3TagVersion, fixture.material.Bundle.Version),
		v3U16(v3TagSuite, uint16(fixture.material.Bundle.Suite)),
		v3Bytes(v3TagServerID, []byte(fixture.material.Bundle.ServerID)),
		v3Bytes(v3TagDeploymentScope, []byte(fixture.material.Bundle.DeploymentScope)),
		v3U64(v3TagRouteEpoch, fixture.material.Bundle.RouteEpoch),
		v3Bytes(v3TagPreKeyID, fixture.material.Bundle.PreKeyID[:]),
		v3U64(v3TagBundleGeneration, fixture.material.Bundle.BundleGeneration),
		v3Bytes(40, []byte("bundle-extension")),
		v3U64(v3TagBundleNotBefore, fixture.material.Bundle.NotBefore),
		v3U64(v3TagBundleNotAfter, fixture.material.Bundle.NotAfter),
		v3Bytes(v3TagPreKeyX25519, fixture.material.Bundle.PreKeyX25519Public[:]),
		v3Bytes(v3TagPreKeyMLKEM, fixture.material.Bundle.PreKeyMLKEMPublic[:]),
		v3Bytes(v3TagBundleSignature, signature),
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV3PreKeyBundle(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(fixture.identity.Public); err != nil {
		t.Fatal(err)
	}
	reencoded, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, full) {
		t.Fatal("bundle extension bytes were not retained")
	}
	digest, err := parsed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	want := BundleDigest(v3Hash("ewp/v3/prekey-bundle-digest", full))
	if digest != want {
		t.Fatal("bundle digest did not include extension bytes")
	}
}

func TestV3PreKeyClaimIsSingleUseAndMismatchDoesNotBurn(t *testing.T) {
	fixture := newV3Fixture(t)
	digest, err := fixture.material.Bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	claim := V3PreKeyClaim{
		Version:          fixture.listener.Version,
		Suite:            fixture.listener.Suite,
		ServerID:         fixture.listener.ServerID,
		DeploymentScope:  fixture.listener.DeploymentScope,
		RouteEpoch:       fixture.credential.RouteEpoch,
		BundleGeneration: fixture.material.Bundle.BundleGeneration,
		PreKeyID:         fixture.material.Bundle.PreKeyID,
		BundleDigest:     digest,
		InitNonce:        V3Nonce{1},
		ClientNonce:      V3Nonce{2},
		CoreDigest:       [32]byte{3},
		Principal:        fixture.principal.ID,
		RouteTag:         ComputeV3RouteTag(fixture.principal.KAuth, fixture.listener, fixture.principal.RouteEpoch),
		Source:           SourceBinding("source-a"),
		Expiry:           time.Now().Add(time.Minute),
	}
	claim.ReplayKey, err = ComputeV3ReplayKey(fixture.credential.KAuth, fixture.listener, fixture.principal.ID, claim)
	if err != nil {
		t.Fatal(err)
	}
	wrong := claim
	wrong.BundleDigest[0] ^= 1
	if _, err := fixture.provider.ClaimAndBurn(context.Background(), fixture.listener, wrong); !errors.Is(err, ErrV3PreKey) {
		t.Fatalf("mismatched claim error = %v", err)
	}
	consumed, err := fixture.provider.ClaimAndBurn(context.Background(), fixture.listener, claim)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.X25519Private == nil || consumed.MLKEMPrivate == nil {
		t.Fatal("successful claim did not return private material")
	}
	consumed.Destroy()
	if err := fixture.provider.Add(fixture.material); !errors.Is(err, ErrV3PreKey) {
		t.Fatalf("re-adding burned prekey error = %v", err)
	}
	if _, err := fixture.provider.ClaimAndBurn(context.Background(), fixture.listener, claim); !errors.Is(err, ErrV3Replay) {
		t.Fatalf("replayed claim error = %v", err)
	}
	second := claim
	second.ReplayKey[0] = 2
	if _, err := fixture.provider.ClaimAndBurn(context.Background(), fixture.listener, second); !errors.Is(err, ErrV3Replay) {
		t.Fatalf("second replay-key claim error = %v", err)
	}
}

func TestV3ClientDoesNotReuseOneTimePreKeyConcurrently(t *testing.T) {
	fixture := newV3Fixture(t)
	now := time.Now()
	second, err := GenerateV3PreKeyMaterial(fixture.listener, fixture.identity, PreKeyID{0x99}, fixture.material.Bundle.BundleGeneration, fixture.credential.RouteEpoch, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.provider.Add(second); err != nil {
		t.Fatal(err)
	}
	client := fixture.newClient(t)
	results := make(chan struct {
		bundle V3PreKeyBundle
		err    error
	}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			bundle, err := client.selectBundle(context.Background())
			results <- struct {
				bundle V3PreKeyBundle
				err    error
			}{bundle: bundle, err: err}
		}()
	}
	var selected []PreKeyID
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent bundle selection: %v", result.err)
		}
		selected = append(selected, result.bundle.PreKeyID)
	}
	if selected[0] == selected[1] {
		t.Fatalf("concurrent selections reused prekey %v", selected[0])
	}
	if _, err := client.selectBundle(context.Background()); !errors.Is(err, ErrV3PreKey) {
		t.Fatalf("exhausted client prekey selection error = %v", err)
	}
}

func TestV3CookieRotationAndSourceBinding(t *testing.T) {
	listener := V3ListenerContext{Version: V3ProtocolVersion, Suite: V3SuiteX25519MLKEM768ChaCha20Poly1305, ServerID: "cookie-server", DeploymentScope: "cookie-scope"}
	now := time.Unix(1_700_000_000, 0)
	runtime := v3Runtime{now: func() time.Time { return now }, random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, 128))}
	keys, err := newV3CookieKeys(runtime)
	if err != nil {
		t.Fatal(err)
	}
	init := V3ClientInit{Version: listener.Version, Suite: listener.Suite, ServerID: listener.ServerID, DeploymentScope: listener.DeploymentScope, PreKeyID: PreKeyID{1}, BundleDigest: BundleDigest{2}, InitNonce: V3Nonce{3}, ClientNonce: V3Nonce{4}, CoreDigest: [32]byte{5}}
	source := SourceBinding("198.51.100.1:443")
	retry, err := keys.Mint(listener, init, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Verify(listener, init, retry, source); err != nil {
		t.Fatal(err)
	}
	if err := keys.Verify(listener, init, retry, SourceBinding("198.51.100.2:443")); !errors.Is(err, ErrV3Cookie) {
		t.Fatalf("wrong source error = %v", err)
	}
	if err := keys.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := keys.Verify(listener, init, retry, source); err != nil {
		t.Fatalf("previous cookie key was not accepted: %v", err)
	}
	now = now.Add(V3RetryLifetime + time.Second)
	if err := keys.Verify(listener, init, retry, source); !errors.Is(err, ErrV3Cookie) {
		t.Fatalf("expired cookie error = %v", err)
	}
}

func TestV3CookieRotationIsRaceSafe(t *testing.T) {
	listener := V3ListenerContext{Version: V3ProtocolVersion, Suite: V3SuiteX25519MLKEM768ChaCha20Poly1305, ServerID: "cookie-race-server", DeploymentScope: "cookie-race-scope"}
	now := time.Unix(1_700_000_000, 0)
	keys, err := newV3CookieKeys(v3Runtime{now: func() time.Time { return now }, random: bytes.NewReader(bytes.Repeat([]byte{0x6b}, 32*300))})
	if err != nil {
		t.Fatal(err)
	}
	init := V3ClientInit{Version: listener.Version, Suite: listener.Suite, ServerID: listener.ServerID, DeploymentScope: listener.DeploymentScope, PreKeyID: PreKeyID{1}, BundleDigest: BundleDigest{2}, InitNonce: V3Nonce{3}, ClientNonce: V3Nonce{4}, CoreDigest: [32]byte{5}, BundleGeneration: 1}
	source := SourceBinding("source")
	retry, err := keys.Mint(listener, init, source)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = keys.Verify(listener, init, retry, source)
			}
		}()
	}
	for i := 0; i < 8; i++ {
		if err := keys.Rotate(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestV3CookieKeyIDWrapsWithoutInvalidatingRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	keys, err := newV3CookieKeys(v3Runtime{now: func() time.Time { return now }, random: bytes.NewReader(bytes.Repeat([]byte{0x7a}, 32*300))})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		if err := keys.Rotate(); err != nil {
			t.Fatalf("rotation %d failed: %v", i, err)
		}
	}
	if keys.Current.ID != 1 || keys.Previous.ID != 0 || !keys.HasPrevious {
		t.Fatalf("wrapped key IDs = current %d previous %d hasPrevious %v", keys.Current.ID, keys.Previous.ID, keys.HasPrevious)
	}
}

func TestV3AdmissionLimitsAndKEMSemaphore(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	controller, err := newV3AdmissionController(1, 1, 1, 1, 1, 1, v3Runtime{now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	source := SourceBinding("source")
	var principal PrincipalID
	if !controller.AllowInit(source) || controller.AllowInit(source) {
		t.Fatal("init limit was not enforced")
	}
	now = now.Add(time.Second + time.Nanosecond)
	if !controller.AllowInit(source) {
		t.Fatal("init limit did not reset")
	}
	if !controller.AllowClientHello(source, principal) || controller.AllowClientHello(source, principal) {
		t.Fatal("hello limit was not enforced")
	}
	release, err := controller.AcquireKEM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := controller.AcquireKEM(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("full KEM semaphore error = %v", err)
	}
	release()
	if release2, err := controller.AcquireKEM(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		release2()
	}
}

func TestV3AdmissionTokenBucketsDoNotChargeRejectedDimensions(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	controller, err := newV3AdmissionController(2, 2, 1, 1, 1, 1, v3Runtime{now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !controller.AllowInit(SourceBinding("source-a")) {
		t.Fatal("first source was rejected")
	}
	if controller.AllowInit(SourceBinding("source-a")) {
		t.Fatal("source bucket allowed an immediate second request")
	}
	if !controller.AllowInit(SourceBinding("source-b")) {
		t.Fatal("global bucket was charged by source-level rejection")
	}

	now = now.Add(500 * time.Millisecond)
	fractional, err := newV3AdmissionController(1, 1, 1, 1, 1, 1, v3Runtime{now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !fractional.AllowInit(SourceBinding("source-c")) {
		t.Fatal("fractional test setup was rejected")
	}
	now = now.Add(500 * time.Millisecond)
	if fractional.AllowInit(SourceBinding("source-d")) {
		t.Fatal("token bucket refilled more than its configured rate")
	}
	now = now.Add(500 * time.Millisecond)
	if !fractional.AllowInit(SourceBinding("source-d")) {
		t.Fatal("token bucket did not refill after one second")
	}
}
