package ewp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type V3ClientHandshakeState struct {
	credential     ClientCredential
	serverIdentity Ed25519PublicKey
	bundle         V3PreKeyBundle
	plain          V3ClientHelloPlaintext

	init          V3ClientInit
	initBaseBytes []byte
	initBytes     []byte
	core          V3ClientHelloCore
	coreBytes     []byte
	retry         V3HelloRetry
	retryBytes    []byte
	helloBytes    []byte

	credentialPRK [32]byte
	outerPRK      [32]byte
	outerIKM      []byte
	tInit         [32]byte
	tClientHello  [32]byte

	dataX25519Private *ecdh.PrivateKey
	dataMLKEMPrivate  *mlkem.DecapsulationKey768
	runtime           v3Runtime
	closed            bool
}

type V3ClientHandshakeResult struct {
	Keys            V3SessionKeys
	Plaintext       V3ClientHelloPlaintext
	ServerPlaintext V3ServerHelloPlaintext
	Bundle          V3PreKeyBundle
	ServerHello     V3ServerHello
}

func startV3ClientHandshake(
	credential ClientCredential,
	serverIdentity Ed25519PublicKey,
	bundle V3PreKeyBundle,
	command Command,
	destination Address,
) (*V3ClientHandshakeState, []byte, error) {
	return startV3ClientHandshakeWithRuntime(credential, serverIdentity, bundle, command, destination, productionV3Runtime())
}

func startV3ClientHandshakeWithRuntime(
	credential ClientCredential,
	serverIdentity Ed25519PublicKey,
	bundle V3PreKeyBundle,
	command Command,
	destination Address,
	runtime v3Runtime,
) (*V3ClientHandshakeState, []byte, error) {
	var outerIKM []byte
	var credentialPRK, outerPRK [32]byte
	var dataX25519Private *ecdh.PrivateKey
	var dataMLKEMPrivate *mlkem.DecapsulationKey768
	var outerPrivate *ecdh.PrivateKey
	keepSecrets := false
	defer func() {
		if !keepSecrets {
			dataX25519Private = nil
			dataMLKEMPrivate = nil
			outerPrivate = nil
			zero(outerIKM)
			zero(credentialPRK[:])
			zero(outerPRK[:])
		}
	}()
	if err := credential.validate(); err != nil {
		return nil, nil, err
	}
	if isZeroEd25519PublicKey(serverIdentity) {
		return nil, nil, ErrV3Identity
	}
	if bundle.Version != credential.Listener.Version || bundle.Suite != credential.Listener.Suite ||
		bundle.ServerID != credential.Listener.ServerID || bundle.DeploymentScope != credential.Listener.DeploymentScope ||
		bundle.RouteEpoch != credential.RouteEpoch || !bundle.ValidAt(runtime.nowTime()) {
		return nil, nil, ErrV3PreKey
	}
	if err := bundle.Verify(serverIdentity); err != nil {
		return nil, nil, err
	}
	bundleDigest, err := bundle.Digest()
	if err != nil {
		return nil, nil, err
	}
	if command != CommandTCP && command != CommandUDP {
		return nil, nil, ErrCommand
	}

	dataX25519Private, err = ecdh.X25519().GenerateKey(runtime.reader())
	if err != nil {
		return nil, nil, err
	}
	dataMLKEMPrivate, err = generateV3MLKEM768(runtime.reader())
	if err != nil {
		return nil, nil, err
	}
	outerPrivate, err = ecdh.X25519().GenerateKey(runtime.reader())
	if err != nil {
		return nil, nil, err
	}
	var outerPublic [X25519PubLen]byte
	copy(outerPublic[:], outerPrivate.PublicKey().Bytes())
	prekeyX25519, err := ecdh.X25519().NewPublicKey(bundle.PreKeyX25519Public[:])
	if err != nil {
		return nil, nil, err
	}
	classical, err := outerPrivate.ECDH(prekeyX25519)
	if err != nil {
		return nil, nil, err
	}
	prekeyMLKEM, err := mlkem.NewEncapsulationKey768(bundle.PreKeyMLKEMPublic[:])
	if err != nil {
		return nil, nil, err
	}
	pqShared, outerCiphertext := prekeyMLKEM.Encapsulate()
	outerIKM, err = v3HybridIKM(classical, pqShared)
	zero(classical)
	zero(pqShared)
	if err != nil {
		return nil, nil, err
	}
	outerPrivate = nil

	var initNonce, clientNonce V3Nonce
	if err := v3ReadRandom(runtime.reader(), initNonce[:]); err != nil {
		return nil, nil, err
	}
	if err := v3ReadRandom(runtime.reader(), clientNonce[:]); err != nil {
		return nil, nil, err
	}
	listener := credential.Listener
	init := V3ClientInit{
		Version:          listener.Version,
		Suite:            listener.Suite,
		ServerID:         listener.ServerID,
		DeploymentScope:  listener.DeploymentScope,
		RouteTag:         ComputeV3RouteTag(credential.KAuth, listener, credential.RouteEpoch),
		RouteEpoch:       credential.RouteEpoch,
		PreKeyID:         bundle.PreKeyID,
		BundleGeneration: bundle.BundleGeneration,
		BundleDigest:     bundleDigest,
		InitNonce:        initNonce,
		ClientNonce:      clientNonce,
	}
	initBaseBytes, err := init.BaseBytes()
	if err != nil {
		return nil, nil, err
	}
	const clientInitPaddingFieldSize = v3FieldHeaderLen
	paddingLen := V3MinClientInitSize - (len(initBaseBytes) + v3FieldHeaderLen + 32 + clientInitPaddingFieldSize)
	if paddingLen > 0 {
		init.Padding = make([]byte, paddingLen)
		if err := v3ReadRandom(runtime.reader(), init.Padding); err != nil {
			return nil, nil, err
		}
		initBaseBytes, err = init.BaseBytes()
		if err != nil {
			return nil, nil, err
		}
	}
	tInit := v3Hash("ewp/v3/init", initBaseBytes)
	header := V3ClientHelloCoreHeader{
		PreKeyID:             bundle.PreKeyID,
		BundleGeneration:     bundle.BundleGeneration,
		BundleDigest:         bundleDigest,
		ClientNonce:          clientNonce,
		OuterX25519Public:    outerPublic,
		OuterMLKEMCiphertext: append([]byte(nil), outerCiphertext...),
	}
	headerBytes, err := header.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	credentialPRK, err = v3CredentialPRK(credential.KAuth, listener)
	if err != nil {
		return nil, nil, err
	}
	outerPRK, err = deriveV3OuterPRK(listener, credentialPRK, outerIKM, tInit, bundleDigest, headerBytes)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := v3Expand(outerPRK[:], "client-hello/key", listener, tInit[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0, AEADKeyLen)
	if err != nil {
		return nil, nil, err
	}
	nonceBytes, err := v3Expand(outerPRK[:], "client-hello/nonce", listener, tInit[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0, AEADNonceLen)
	if err != nil {
		return nil, nil, err
	}
	var clientHelloKey [AEADKeyLen]byte
	var clientHelloNonce [AEADNonceLen]byte
	copy(clientHelloKey[:], keyBytes)
	copy(clientHelloNonce[:], nonceBytes)
	zero(keyBytes)
	zero(nonceBytes)

	padding := make([]byte, 32)
	if err := v3ReadRandom(runtime.reader(), padding); err != nil {
		return nil, nil, err
	}
	var dataPublic [X25519PubLen]byte
	copy(dataPublic[:], dataX25519Private.PublicKey().Bytes())
	plain := V3ClientHelloPlaintext{
		Command:                command,
		Destination:            destination,
		ClientDataX25519Public: dataPublic,
		ClientDataMLKEMPublic:  append([]byte(nil), dataMLKEMPrivate.EncapsulationKey().Bytes()...),
		RandomPadding:          padding,
	}
	plainBytes, err := plain.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := v3Seal(clientHelloKey, clientHelloNonce, v3ClientHelloAAD(initBaseBytes, headerBytes), plainBytes)
	zero(plainBytes)
	if err != nil {
		return nil, nil, err
	}
	core := V3ClientHelloCore{Header: header, Ciphertext: ciphertext}
	coreBytes, err := core.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	init.CoreDigest = sha256.Sum256(coreBytes)
	initBytes, err := init.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	state := &V3ClientHandshakeState{
		credential:        credential,
		serverIdentity:    serverIdentity,
		bundle:            bundle,
		plain:             plain,
		init:              init,
		initBaseBytes:     initBaseBytes,
		initBytes:         initBytes,
		core:              core,
		coreBytes:         coreBytes,
		credentialPRK:     credentialPRK,
		outerPRK:          outerPRK,
		outerIKM:          outerIKM,
		tInit:             tInit,
		dataX25519Private: dataX25519Private,
		dataMLKEMPrivate:  dataMLKEMPrivate,
		runtime:           runtime,
	}
	keepSecrets = true
	return state, initBytes, nil
}

func (s *V3ClientHandshakeState) buildClientHello(retry V3HelloRetry) ([]byte, error) {
	if s == nil || s.closed {
		return nil, ErrV3State
	}
	if retry.Version != s.credential.Listener.Version || retry.Suite != s.credential.Listener.Suite || retry.InitNonce != s.init.InitNonce {
		return nil, ErrV3Cookie
	}
	if retry.ExpiresAt <= uint64(s.runtime.nowTime().Unix()) {
		return nil, ErrV3Cookie
	}
	retryBytes := append([]byte(nil), retry.wireBytes()...)
	if len(retryBytes) == 0 {
		return nil, ErrV3Malformed
	}
	tag, err := ComputeV3AdmissionTag(s.credential.KAuth, s.credential.Listener, s.initBytes, retryBytes, s.coreBytes)
	if err != nil {
		return nil, err
	}
	hello := V3ClientHello{Init: s.init, Retry: retry, Core: s.core, AdmissionTag: tag}
	helloBytes, err := hello.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.retry = retry
	s.retryBytes = retryBytes
	s.helloBytes = helloBytes
	s.tClientHello = v3Hash("ewp/v3/client-hello", s.initBytes, retryBytes, s.coreBytes, tag[:])
	return helloBytes, nil
}

func (s *V3ClientHandshakeState) completeServerHello(serverHelloBytes []byte) (V3ClientHandshakeResult, V3PendingHandshake, []byte, error) {
	if s == nil || s.closed || len(s.helloBytes) == 0 {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, ErrV3State
	}
	var material v3HandshakeMaterial
	defer zeroMaterial(&material)
	serverHello, err := ParseV3ServerHello(serverHelloBytes)
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	if serverHello.Header.Version != s.credential.Listener.Version || serverHello.Header.Suite != s.credential.Listener.Suite ||
		serverHello.Header.PreKeyID != s.bundle.PreKeyID || serverHello.Header.BundleGeneration != s.bundle.BundleGeneration ||
		serverHello.Header.BundleDigest != s.init.BundleDigest {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, ErrV3Transcript
	}
	headerBytes := serverHello.Header.wireBytes()
	if len(headerBytes) == 0 {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, ErrV3Malformed
	}
	signatureDigest := v3Hash("ewp/v3/server-hello-signature", s.tClientHello[:], headerBytes, serverHello.Ciphertext)
	if !ed25519.Verify(ed25519.PublicKey(s.serverIdentity[:]), signatureDigest[:], serverHello.Signature[:]) {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, ErrV3Signature
	}
	tServerHello := v3Hash("ewp/v3/server-hello", s.tClientHello[:], serverHelloBytes)
	serverPublic, err := ecdh.X25519().NewPublicKey(serverHello.Header.ServerDataX25519Public[:])
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	classical, err := s.dataX25519Private.ECDH(serverPublic)
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	pqShared, err := s.dataMLKEMPrivate.Decapsulate(serverHello.Header.DataMLKEMCiphertext)
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	dataIKM, err := v3HybridIKM(classical, pqShared)
	zero(classical)
	zero(pqShared)
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	material, err = deriveV3HandshakeMaterial(
		s.credential.Listener, s.credentialPRK, s.outerIKM, dataIKM,
		s.tInit, s.init.BundleDigest, s.coreHeaderBytes(), s.tClientHello,
		headerBytes, tServerHello,
	)
	zero(dataIKM)
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	plainBytes, err := v3Open(material.serverHelloKey, material.serverHelloNonce,
		v3ServerHelloAAD(s.credential.Listener, serverHello.Header.HandshakeID, s.tClientHello), serverHello.Ciphertext)
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	serverPlain, err := ParseV3ServerHelloPlaintext(plainBytes)
	zero(plainBytes)
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	clientFinishedBytes, err := buildV3ClientFinished(s.credential.Listener, serverHello.Header.HandshakeID, tServerHello, material)
	if err != nil {
		return V3ClientHandshakeResult{}, V3PendingHandshake{}, nil, err
	}
	return V3ClientHandshakeResult{
			Plaintext:       s.plain,
			ServerPlaintext: serverPlain,
			Bundle:          s.bundle,
			ServerHello:     serverHello,
		}, V3PendingHandshake{
			Listener:     s.credential.Listener,
			HandshakeID:  serverHello.Header.HandshakeID,
			TClientHello: s.tClientHello,
			TServerHello: tServerHello,
			Secrets:      v3FinishedSecrets(material),
		}, clientFinishedBytes, nil
}

func (s *V3ClientHandshakeState) coreHeaderBytes() []byte {
	if s == nil {
		return nil
	}
	return s.core.Header.wireBytes()
}

func (s *V3ClientHandshakeState) destroy() {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	if s.dataX25519Private != nil {
		s.dataX25519Private = nil
	}
	s.dataMLKEMPrivate = nil
	zero(s.credentialPRK[:])
	zero(s.outerPRK[:])
	zero(s.tInit[:])
	zero(s.tClientHello[:])
	zero(s.outerIKM)
	s.outerIKM = nil
	zero(s.initBaseBytes)
	zero(s.initBytes)
	zero(s.coreBytes)
	zero(s.retryBytes)
	zero(s.helloBytes)
	s.initBaseBytes = nil
	s.initBytes = nil
	s.coreBytes = nil
	s.retryBytes = nil
	s.helloBytes = nil
	s.plain.ClientDataMLKEMPublic = nil
	s.plain.NegotiatedParameters = nil
	s.plain.RandomPadding = nil
}

func v3ClientHelloAAD(initBase, header []byte) []byte {
	return v3Domain("ewp/v3/client-hello-aad", initBase, header)
}

func v3ServerHelloAAD(listener V3ListenerContext, id HandshakeID, transcript [32]byte) []byte {
	return v3Domain("ewp/v3/server-hello-aad", v3Uint16Bytes(listener.Version), v3Uint16Bytes(uint16(listener.Suite)), []byte(listener.ServerID), []byte(listener.DeploymentScope), id[:], transcript[:])
}

func v3FinishedAAD(label string, listener V3ListenerContext, id HandshakeID, transcript [32]byte) []byte {
	return v3Domain(label, v3Uint16Bytes(listener.Version), v3Uint16Bytes(uint16(listener.Suite)), []byte(listener.ServerID), []byte(listener.DeploymentScope), id[:], transcript[:])
}

func v3Seal(key [AEADKeyLen]byte, nonce [AEADNonceLen]byte, aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

func v3Open(key [AEADKeyLen]byte, nonce [AEADNonceLen]byte, aad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, ErrV3Finished
	}
	return plaintext, nil
}

func buildV3ClientFinished(listener V3ListenerContext, id HandshakeID, tServerHello [32]byte, material v3HandshakeMaterial) ([]byte, error) {
	verifyData := v3FinishedVerify(material.clientFinishedVerifyKey, "ewp/v3/client-finished-verify", tServerHello)
	ciphertext, err := v3Seal(material.clientFinishedKey, material.clientFinishedNonce, v3FinishedAAD("ewp/v3/client-finished-aad", listener, id, tServerHello), verifyData[:])
	zero(verifyData[:])
	if err != nil {
		return nil, err
	}
	return (V3ClientFinished{Version: listener.Version, Suite: listener.Suite, HandshakeID: id, Ciphertext: ciphertext}).MarshalBinary()
}

func buildV3ServerFinished(pending V3PendingHandshake, tClientFinished [32]byte) ([]byte, error) {
	verifyData := v3FinishedVerify(pending.Secrets.ServerFinishedVerifyKey, "ewp/v3/server-finished-verify", tClientFinished)
	ciphertext, err := v3Seal(pending.Secrets.ServerFinishedKey, pending.Secrets.ServerFinishedNonce, v3FinishedAAD("ewp/v3/server-finished-aad", pending.Listener, pending.HandshakeID, tClientFinished), verifyData[:])
	zero(verifyData[:])
	if err != nil {
		return nil, err
	}
	return (V3ServerFinished{Version: pending.Listener.Version, Suite: pending.Listener.Suite, HandshakeID: pending.HandshakeID, Ciphertext: ciphertext}).MarshalBinary()
}

func v3FinishedSecrets(material v3HandshakeMaterial) V3FinishedSecrets {
	return V3FinishedSecrets{
		HandshakePRK:            material.handshakePRK,
		ClientFinishedKey:       material.clientFinishedKey,
		ClientFinishedNonce:     material.clientFinishedNonce,
		ClientFinishedVerifyKey: material.clientFinishedVerifyKey,
		ServerFinishedKey:       material.serverFinishedKey,
		ServerFinishedNonce:     material.serverFinishedNonce,
		ServerFinishedVerifyKey: material.serverFinishedVerifyKey,
	}
}

func v3MaterialFromFinishedSecrets(secrets V3FinishedSecrets) v3HandshakeMaterial {
	return v3HandshakeMaterial{
		handshakePRK:            secrets.HandshakePRK,
		clientFinishedKey:       secrets.ClientFinishedKey,
		clientFinishedNonce:     secrets.ClientFinishedNonce,
		clientFinishedVerifyKey: secrets.ClientFinishedVerifyKey,
		serverFinishedKey:       secrets.ServerFinishedKey,
		serverFinishedNonce:     secrets.ServerFinishedNonce,
		serverFinishedVerifyKey: secrets.ServerFinishedVerifyKey,
	}
}

func (s *ServiceV3) makeServerHello(ctx context.Context, firstInit V3ClientInit, firstInitBytes []byte, retry V3HelloRetry, source SourceBinding, helloBytes []byte) (V3PendingHandshake, []byte, error) {
	if s == nil {
		return V3PendingHandshake{}, nil, ErrV3State
	}
	var outerIKM, dataIKM []byte
	var credentialPRK, outerPRK [32]byte
	var serverDataPrivate *ecdh.PrivateKey
	defer func() {
		serverDataPrivate = nil
		zero(outerIKM)
		zero(dataIKM)
		zero(credentialPRK[:])
		zero(outerPRK[:])
	}()
	hello, err := ParseV3ClientHello(helloBytes)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	if !sameV3ClientInit(hello.Init, firstInit) || !sameV3HelloRetry(hello.Retry, retry) || !bytes.Equal(hello.Init.wireBytes(), firstInitBytes) {
		return V3PendingHandshake{}, nil, ErrV3Transcript
	}
	if err := s.cookieKeys.verifyAt(s.listener, hello.Init, hello.Retry, source, s.runtime.nowTime()); err != nil {
		return V3PendingHandshake{}, nil, err
	}
	coreBytes := hello.Core.wireBytes()
	if len(coreBytes) == 0 {
		return V3PendingHandshake{}, nil, ErrV3Malformed
	}
	if hello.Core.Header.PreKeyID != hello.Init.PreKeyID ||
		hello.Core.Header.BundleGeneration != hello.Init.BundleGeneration ||
		hello.Core.Header.BundleDigest != hello.Init.BundleDigest ||
		hello.Core.Header.ClientNonce != hello.Init.ClientNonce {
		return V3PendingHandshake{}, nil, ErrV3Transcript
	}
	digest := sha256.Sum256(coreBytes)
	if subtle.ConstantTimeCompare(digest[:], hello.Init.CoreDigest[:]) != 1 {
		return V3PendingHandshake{}, nil, ErrV3Transcript
	}
	principal, ok := s.resolver.LookupRouteTag(ctx, s.listener, hello.Init.RouteTag, hello.Init.RouteEpoch)
	if !ok {
		return V3PendingHandshake{}, nil, ErrV3Admission
	}
	retryBytes := hello.Retry.wireBytes()
	if len(retryBytes) == 0 {
		return V3PendingHandshake{}, nil, ErrV3Malformed
	}
	initBytes := append([]byte(nil), firstInitBytes...)
	wantAdmission, err := ComputeV3AdmissionTag(principal.KAuth, s.listener, initBytes, retryBytes, coreBytes)
	if err != nil || subtle.ConstantTimeCompare(wantAdmission[:], hello.AdmissionTag[:]) != 1 {
		return V3PendingHandshake{}, nil, ErrV3Admission
	}
	claim := V3PreKeyClaim{
		Version:          hello.Init.Version,
		Suite:            hello.Init.Suite,
		ServerID:         hello.Init.ServerID,
		DeploymentScope:  hello.Init.DeploymentScope,
		RouteEpoch:       hello.Init.RouteEpoch,
		BundleGeneration: hello.Init.BundleGeneration,
		PreKeyID:         hello.Init.PreKeyID,
		BundleDigest:     hello.Init.BundleDigest,
		InitNonce:        hello.Init.InitNonce,
		ClientNonce:      hello.Init.ClientNonce,
		CoreDigest:       hello.Init.CoreDigest,
		Principal:        principal.ID,
		RouteTag:         hello.Init.RouteTag,
		Source:           source,
		Expiry:           time.Unix(int64(hello.Retry.ExpiresAt), 0).Add(DefaultHandshakeTimeout),
	}
	replayKey, err := ComputeV3ReplayKey(principal.KAuth, s.listener, principal.ID, claim)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	claim.ReplayKey = replayKey
	admissionRelease, err := s.reserveClientHello(ctx, claim.Source, claim.Principal)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	admissionRelease = onceV3Release(admissionRelease)
	handedOff := false
	defer func() {
		if !handedOff {
			admissionRelease()
		}
	}()
	releaseKEM, err := s.admission.AcquireKEM(ctx)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	defer releaseKEM()
	consumed, err := s.prekeys.ClaimAndBurn(ctx, s.listener, claim)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	defer consumed.Destroy()
	if err := consumed.Bundle.Verify(s.identity.Public); err != nil {
		return V3PendingHandshake{}, nil, err
	}
	claimedDigest, err := consumed.Bundle.Digest()
	if err != nil || claimedDigest != claim.BundleDigest || consumed.Bundle.BundleGeneration != claim.BundleGeneration || consumed.Bundle.RouteEpoch != claim.RouteEpoch {
		return V3PendingHandshake{}, nil, ErrV3PreKey
	}
	outerPublic, err := ecdh.X25519().NewPublicKey(hello.Core.Header.OuterX25519Public[:])
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	classical, err := consumed.X25519Private.ECDH(outerPublic)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	pqShared, err := consumed.MLKEMPrivate.Decapsulate(hello.Core.Header.OuterMLKEMCiphertext)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	outerIKM, err = v3HybridIKM(classical, pqShared)
	zero(classical)
	zero(pqShared)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	initBaseBytes := hello.Init.baseWireBytes()
	if len(initBaseBytes) == 0 {
		return V3PendingHandshake{}, nil, ErrV3Malformed
	}
	tInit := v3Hash("ewp/v3/init", initBaseBytes)
	credentialPRK, err = v3CredentialPRK(principal.KAuth, s.listener)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	headerBytes := hello.Core.Header.wireBytes()
	if len(headerBytes) == 0 {
		return V3PendingHandshake{}, nil, ErrV3Malformed
	}
	outerPRK, err = deriveV3OuterPRK(s.listener, credentialPRK, outerIKM, tInit, hello.Init.BundleDigest, headerBytes)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	keyBytes, err := v3Expand(outerPRK[:], "client-hello/key", s.listener, tInit[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0, AEADKeyLen)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	nonceBytes, err := v3Expand(outerPRK[:], "client-hello/nonce", s.listener, tInit[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0, AEADNonceLen)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	var clientHelloKey [AEADKeyLen]byte
	var clientHelloNonce [AEADNonceLen]byte
	copy(clientHelloKey[:], keyBytes)
	copy(clientHelloNonce[:], nonceBytes)
	zero(keyBytes)
	zero(nonceBytes)
	plainBytes, err := v3Open(clientHelloKey, clientHelloNonce, v3ClientHelloAAD(initBaseBytes, headerBytes), hello.Core.Ciphertext)
	zero(clientHelloKey[:])
	zero(clientHelloNonce[:])
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	plain, err := ParseV3ClientHelloPlaintext(plainBytes)
	zero(plainBytes)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	serverDataPrivate, err = ecdh.X25519().GenerateKey(s.runtime.reader())
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	clientDataPublic, err := ecdh.X25519().NewPublicKey(plain.ClientDataX25519Public[:])
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	classical, err = serverDataPrivate.ECDH(clientDataPublic)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	clientDataMLKEM, err := mlkem.NewEncapsulationKey768(plain.ClientDataMLKEMPublic)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	pqShared, dataCiphertext := clientDataMLKEM.Encapsulate()
	dataIKM, err = v3HybridIKM(classical, pqShared)
	zero(classical)
	zero(pqShared)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	serverNonce, err := randomV3Nonce(s.runtime.reader())
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	handshakeID, err := randomV3HandshakeID(s.runtime.reader())
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	var serverDataPublic [X25519PubLen]byte
	copy(serverDataPublic[:], serverDataPrivate.PublicKey().Bytes())
	serverHeader := V3ServerHelloHeader{
		Version:                s.listener.Version,
		Suite:                  s.listener.Suite,
		PreKeyID:               hello.Init.PreKeyID,
		BundleGeneration:       hello.Init.BundleGeneration,
		BundleDigest:           hello.Init.BundleDigest,
		ServerNonce:            serverNonce,
		HandshakeID:            handshakeID,
		ServerDataX25519Public: serverDataPublic,
		DataMLKEMCiphertext:    append([]byte(nil), dataCiphertext...),
	}
	serverHeaderBytes, err := serverHeader.MarshalBinary()
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	tClientHello := v3Hash("ewp/v3/client-hello", initBytes, retryBytes, coreBytes, hello.AdmissionTag[:])
	serverHelloPRK, err := deriveV3ServerHelloPRK(s.listener, credentialPRK, outerPRK, dataIKM, tClientHello, serverHeaderBytes)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	serverKeyBytes, err := v3Expand(serverHelloPRK[:], "server-hello/key", s.listener, tClientHello[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0, AEADKeyLen)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	serverNonceBytes, err := v3Expand(serverHelloPRK[:], "server-hello/nonce", s.listener, tClientHello[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0, AEADNonceLen)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	var serverHelloKey [AEADKeyLen]byte
	var serverHelloAEADNonce [AEADNonceLen]byte
	copy(serverHelloKey[:], serverKeyBytes)
	copy(serverHelloAEADNonce[:], serverNonceBytes)
	zero(serverKeyBytes)
	zero(serverNonceBytes)
	serverPadding := make([]byte, 32)
	if err := v3ReadRandom(s.runtime.reader(), serverPadding); err != nil {
		return V3PendingHandshake{}, nil, err
	}
	serverPlainBytes, err := (V3ServerHelloPlaintext{RandomPadding: serverPadding}).MarshalBinary()
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	serverCiphertext, err := v3Seal(serverHelloKey, serverHelloAEADNonce, v3ServerHelloAAD(s.listener, handshakeID, tClientHello), serverPlainBytes)
	zero(serverPlainBytes)
	zero(serverHelloKey[:])
	zero(serverHelloAEADNonce[:])
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	signatureDigest := v3Hash("ewp/v3/server-hello-signature", tClientHello[:], serverHeaderBytes, serverCiphertext)
	signature := ed25519.Sign(s.identity.Private, signatureDigest[:])
	var signatureArray [V3SignatureLen]byte
	copy(signatureArray[:], signature)
	serverHello := V3ServerHello{Header: serverHeader, Ciphertext: serverCiphertext, Signature: signatureArray}
	serverHelloBytes, err := serverHello.MarshalBinary()
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	tServerHello := v3Hash("ewp/v3/server-hello", tClientHello[:], serverHelloBytes)
	var material v3HandshakeMaterial
	defer zeroMaterial(&material)
	material, err = deriveV3HandshakeMaterial(s.listener, credentialPRK, outerIKM, dataIKM, tInit, hello.Init.BundleDigest, headerBytes, tClientHello, serverHeaderBytes, tServerHello)
	zero(outerIKM)
	zero(dataIKM)
	if err != nil {
		return V3PendingHandshake{}, nil, err
	}
	pending := V3PendingHandshake{
		Listener:     s.listener,
		Source:       source,
		Principal:    principal.ID,
		HandshakeID:  handshakeID,
		TClientHello: tClientHello,
		TServerHello: tServerHello,
		Secrets:      v3FinishedSecrets(material),
		Command:      plain.Command,
		Destination:  plain.Destination,
	}
	pending.admissionRelease = admissionRelease
	handedOff = true
	return pending, serverHelloBytes, nil
}

func randomV3Nonce(reader ...io.Reader) (V3Nonce, error) {
	var nonce V3Nonce
	r := productionV3Runtime().reader()
	if len(reader) != 0 && reader[0] != nil {
		r = reader[0]
	}
	err := v3ReadRandom(r, nonce[:])
	return nonce, err
}

func randomV3HandshakeID(reader ...io.Reader) (HandshakeID, error) {
	r := productionV3Runtime().reader()
	if len(reader) != 0 && reader[0] != nil {
		r = reader[0]
	}
	for {
		var id HandshakeID
		if err := v3ReadRandom(r, id[:]); err != nil {
			return HandshakeID{}, err
		}
		if id != (HandshakeID{}) {
			return id, nil
		}
	}
}

func isZeroEd25519PublicKey(key Ed25519PublicKey) bool {
	var zeroKey Ed25519PublicKey
	return subtle.ConstantTimeCompare(key[:], zeroKey[:]) == 1
}

func zeroMaterial(material *v3HandshakeMaterial) {
	if material == nil {
		return
	}
	zero(material.outerPRK[:])
	zero(material.serverHelloPRK[:])
	zero(material.handshakePRK[:])
	zero(material.clientHelloKey[:])
	zero(material.clientHelloNonce[:])
	zero(material.serverHelloKey[:])
	zero(material.serverHelloNonce[:])
	zero(material.clientFinishedKey[:])
	zero(material.clientFinishedNonce[:])
	zero(material.clientFinishedVerifyKey[:])
	zero(material.serverFinishedKey[:])
	zero(material.serverFinishedNonce[:])
	zero(material.serverFinishedVerifyKey[:])
}

func v3VerifyClientFinished(pending V3PendingHandshake, message []byte) ([32]byte, error) {
	finished, err := ParseV3ClientFinished(message)
	if err != nil {
		return [32]byte{}, err
	}
	if finished.Version != pending.Listener.Version || finished.Suite != pending.Listener.Suite || finished.HandshakeID != pending.HandshakeID {
		return [32]byte{}, ErrV3Finished
	}
	tClientFinished := v3Hash("ewp/v3/client-finished", pending.TServerHello[:], message)
	material := v3MaterialFromFinishedSecrets(pending.Secrets)
	plaintext, err := v3Open(material.clientFinishedKey, material.clientFinishedNonce, v3FinishedAAD("ewp/v3/client-finished-aad", pending.Listener, pending.HandshakeID, pending.TServerHello), finished.Ciphertext)
	zeroMaterial(&material)
	if err != nil || len(plaintext) != sha256.Size {
		zero(plaintext)
		return [32]byte{}, ErrV3Finished
	}
	want := v3FinishedVerify(pending.Secrets.ClientFinishedVerifyKey, "ewp/v3/client-finished-verify", pending.TServerHello)
	valid := subtle.ConstantTimeCompare(plaintext, want[:]) == 1
	zero(plaintext)
	zero(want[:])
	if !valid {
		return [32]byte{}, ErrV3Finished
	}
	return tClientFinished, nil
}

func verifyV3ServerFinished(listener V3ListenerContext, pending V3PendingHandshake, message []byte, tClientFinished [32]byte) ([32]byte, error) {
	finished, err := ParseV3ServerFinished(message)
	if err != nil || finished.Version != listener.Version || finished.Suite != listener.Suite || finished.HandshakeID != pending.HandshakeID {
		return [32]byte{}, ErrV3Finished
	}
	material := v3MaterialFromFinishedSecrets(pending.Secrets)
	plaintext, err := v3Open(material.serverFinishedKey, material.serverFinishedNonce, v3FinishedAAD("ewp/v3/server-finished-aad", listener, pending.HandshakeID, tClientFinished), finished.Ciphertext)
	zeroMaterial(&material)
	if err != nil || len(plaintext) != sha256.Size {
		zero(plaintext)
		return [32]byte{}, ErrV3Finished
	}
	want := v3FinishedVerify(pending.Secrets.ServerFinishedVerifyKey, "ewp/v3/server-finished-verify", tClientFinished)
	valid := subtle.ConstantTimeCompare(plaintext, want[:]) == 1
	zero(plaintext)
	zero(want[:])
	if !valid {
		return [32]byte{}, ErrV3Finished
	}
	return v3Hash("ewp/v3/server-finished", tClientFinished[:], message), nil
}

func deriveV3ClientSession(pending V3PendingHandshake, tServerFinished [32]byte) (V3SessionKeys, error) {
	material := v3MaterialFromFinishedSecrets(pending.Secrets)
	defer zeroMaterial(&material)
	return deriveV3SessionKeys(material, pending.Listener, tServerFinished)
}
