package ewp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	v3RoleClient   = "client"
	v3RoleServer   = "server"
	v3DirectionC2S = "c2s"
	v3DirectionS2C = "s2c"
)

// V3SessionKeys contains only the post-Finished traffic material. Handshake
// and Finished keys stay in the handshake state and are destroyed once the
// session is established or aborted.
type V3SessionKeys struct {
	C2SKey            [AEADKeyLen]byte
	S2CKey            [AEADKeyLen]byte
	C2SNonce          [NoncePrefixLen]byte
	S2CNonce          [NoncePrefixLen]byte
	C2SUpdateSecret   [32]byte
	S2CUpdateSecret   [32]byte
	TrafficTranscript [32]byte
	SessionID         [V3HandshakeIDLen]byte
	listener          V3ListenerContext
}

func zeroV3SessionKeys(keys *V3SessionKeys) {
	if keys == nil {
		return
	}
	zero(keys.C2SKey[:])
	zero(keys.S2CKey[:])
	zero(keys.C2SNonce[:])
	zero(keys.S2CNonce[:])
	zero(keys.C2SUpdateSecret[:])
	zero(keys.S2CUpdateSecret[:])
	zero(keys.TrafficTranscript[:])
	zero(keys.SessionID[:])
}

type v3HandshakeMaterial struct {
	outerPRK       [32]byte
	serverHelloPRK [32]byte
	handshakePRK   [32]byte

	clientHelloKey   [AEADKeyLen]byte
	clientHelloNonce [AEADNonceLen]byte
	serverHelloKey   [AEADKeyLen]byte
	serverHelloNonce [AEADNonceLen]byte

	clientFinishedKey       [AEADKeyLen]byte
	clientFinishedNonce     [AEADNonceLen]byte
	clientFinishedVerifyKey [32]byte
	serverFinishedKey       [AEADKeyLen]byte
	serverFinishedNonce     [AEADNonceLen]byte
	serverFinishedVerifyKey [32]byte
}

var ErrV3ShortKDF = errors.New("ewp/v3: HKDF output was truncated")

func v3CredentialPRK(credential [V3KAuthLen]byte, listener V3ListenerContext) ([32]byte, error) {
	if err := listener.validate(); err != nil {
		return [32]byte{}, err
	}
	salt := v3Hash(
		"ewp/v3/credential-salt",
		v3Uint16Bytes(listener.Version),
		v3Uint16Bytes(uint16(listener.Suite)),
		[]byte(listener.ServerID),
		[]byte(listener.DeploymentScope),
	)
	prk := hkdf.Extract(sha256.New, credential[:], salt[:])
	var result [32]byte
	copy(result[:], prk)
	zero(prk)
	return result, nil
}

func v3HybridIKM(classical, pq []byte) ([]byte, error) {
	if len(classical) != X25519PubLen || len(pq) != 32 {
		return nil, fmt.Errorf("%w: hybrid component length", ErrV3Malformed)
	}
	return v3LengthDelimited(classical, pq), nil
}

func v3LengthDelimited(parts ...[]byte) []byte {
	total := 0
	for _, part := range parts {
		total += 4 + len(part)
	}
	out := make([]byte, 0, total)
	for _, part := range parts {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		out = append(out, length[:]...)
		out = append(out, part...)
	}
	return out
}

func v3ExpandRaw(prk []byte, label string, length int) ([]byte, error) {
	if length < 0 {
		return nil, ErrV3Malformed
	}
	result := make([]byte, length)
	reader := hkdf.Expand(sha256.New, prk, []byte(label))
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, ErrV3ShortKDF
	}
	return result, nil
}

func v3Expand(prk []byte, label string, listener V3ListenerContext, transcript []byte, sender, receiver, direction string, epoch uint64, length int) ([]byte, error) {
	if err := listener.validate(); err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, ErrV3Malformed
	}
	info := v3Domain(
		"ewp/v3/expand",
		[]byte(label),
		v3Uint16Bytes(listener.Version),
		v3Uint16Bytes(uint16(listener.Suite)),
		[]byte(listener.ServerID),
		[]byte(listener.DeploymentScope),
		transcript,
		[]byte(sender),
		[]byte(receiver),
		[]byte(direction),
		v3Uint64Bytes(epoch),
	)
	result := make([]byte, length)
	reader := hkdf.Expand(sha256.New, prk, info)
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, ErrV3ShortKDF
	}
	return result, nil
}

func v3ExpandInto(dst []byte, prk []byte, label string, listener V3ListenerContext, transcript []byte, sender, receiver, direction string, epoch uint64) error {
	value, err := v3Expand(prk, label, listener, transcript, sender, receiver, direction, epoch, len(dst))
	if err != nil {
		return err
	}
	copy(dst, value)
	zero(value)
	return nil
}

func deriveV3OuterPRK(
	listener V3ListenerContext,
	credentialPRK [32]byte,
	outerIKM []byte,
	tInit [32]byte,
	bundleDigest BundleDigest,
	clientHelloHeader []byte,
) ([32]byte, error) {
	if err := listener.validate(); err != nil {
		return [32]byte{}, err
	}
	if len(outerIKM) == 0 || len(clientHelloHeader) == 0 {
		return [32]byte{}, ErrV3Malformed
	}
	salt := v3Hash("ewp/v3/outer-salt", tInit[:], bundleDigest[:], clientHelloHeader)
	ikm := v3LengthDelimited(outerIKM, credentialPRK[:])
	defer zero(ikm)
	prk := hkdf.Extract(sha256.New, ikm, salt[:])
	var result [32]byte
	copy(result[:], prk)
	zero(prk)
	return result, nil
}

func deriveV3ServerHelloPRK(
	listener V3ListenerContext,
	credentialPRK [32]byte,
	outerPRK [32]byte,
	dataIKM []byte,
	tClientHello [32]byte,
	serverHelloHeader []byte,
) ([32]byte, error) {
	if err := listener.validate(); err != nil {
		return [32]byte{}, err
	}
	if len(dataIKM) == 0 || len(serverHelloHeader) == 0 {
		return [32]byte{}, ErrV3Malformed
	}
	salt := v3Hash("ewp/v3/server-hello-salt", tClientHello[:], serverHelloHeader)
	ikm := v3LengthDelimited(outerPRK[:], dataIKM, credentialPRK[:])
	defer zero(ikm)
	prk := hkdf.Extract(sha256.New, ikm, salt[:])
	var result [32]byte
	copy(result[:], prk)
	zero(prk)
	return result, nil
}

func v3Extract(label string, saltParts [][]byte, ikmParts ...[]byte) [32]byte {
	salt := v3Hash(label, saltParts...)
	ikm := v3LengthDelimited(ikmParts...)
	defer zero(ikm)
	prk := hkdf.Extract(sha256.New, ikm, salt[:])
	var result [32]byte
	copy(result[:], prk)
	return result
}

func deriveV3HandshakeMaterial(
	listener V3ListenerContext,
	credentialPRK [32]byte,
	outerIKM, dataIKM []byte,
	tInit [32]byte,
	bundleDigest BundleDigest,
	clientHelloHeader []byte,
	tClientHello [32]byte,
	serverHelloHeader []byte,
	tServerHello [32]byte,
) (v3HandshakeMaterial, error) {
	if err := listener.validate(); err != nil {
		return v3HandshakeMaterial{}, err
	}
	if len(outerIKM) == 0 || len(dataIKM) == 0 {
		return v3HandshakeMaterial{}, ErrV3Malformed
	}
	outerSalt := v3Hash("ewp/v3/outer-salt", tInit[:], bundleDigest[:], clientHelloHeader)
	outerPRK := hkdf.Extract(sha256.New, v3LengthDelimited(outerIKM, credentialPRK[:]), outerSalt[:])
	defer zero(outerPRK)
	serverHelloSalt := v3Hash("ewp/v3/server-hello-salt", tClientHello[:], serverHelloHeader)
	serverHelloPRK := hkdf.Extract(sha256.New, v3LengthDelimited(outerPRK, dataIKM, credentialPRK[:]), serverHelloSalt[:])
	defer zero(serverHelloPRK)
	handshakeSalt := v3Hash("ewp/v3/handshake-salt", tServerHello[:])
	handshakePRK := hkdf.Extract(sha256.New, v3LengthDelimited(outerPRK, dataIKM, credentialPRK[:]), handshakeSalt[:])
	defer zero(handshakePRK)

	result := v3HandshakeMaterial{}
	copy(result.outerPRK[:], outerPRK)
	copy(result.serverHelloPRK[:], serverHelloPRK)
	copy(result.handshakePRK[:], handshakePRK)
	if err := v3ExpandInto(result.clientHelloKey[:], outerPRK, "client-hello/key", listener, tInit[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.clientHelloNonce[:], outerPRK, "client-hello/nonce", listener, tInit[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.serverHelloKey[:], serverHelloPRK, "server-hello/key", listener, tClientHello[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.serverHelloNonce[:], serverHelloPRK, "server-hello/nonce", listener, tClientHello[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.clientFinishedKey[:], handshakePRK, "finished/client/key", listener, tServerHello[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.clientFinishedNonce[:], handshakePRK, "finished/client/nonce", listener, tServerHello[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.clientFinishedVerifyKey[:], handshakePRK, "finished/client/verify", listener, tServerHello[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.serverFinishedKey[:], handshakePRK, "finished/server/key", listener, tServerHello[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.serverFinishedNonce[:], handshakePRK, "finished/server/nonce", listener, tServerHello[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.serverFinishedVerifyKey[:], handshakePRK, "finished/server/verify", listener, tServerHello[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0); err != nil {
		return result, err
	}
	return result, nil
}

func v3FinishedVerify(key [32]byte, label string, transcript [32]byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(v3Domain(label, transcript[:]))
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func deriveV3SessionKeys(material v3HandshakeMaterial, listener V3ListenerContext, tServerFinished [32]byte) (V3SessionKeys, error) {
	masterSalt := v3Hash("ewp/v3/master-salt", tServerFinished[:])
	masterPRK := hkdf.Extract(sha256.New, material.handshakePRK[:], masterSalt[:])
	defer zero(masterPRK)
	var result V3SessionKeys
	result.TrafficTranscript = tServerFinished
	result.listener = listener
	if err := v3ExpandInto(result.C2SKey[:], masterPRK, "traffic/c2s/key", listener, tServerFinished[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.S2CKey[:], masterPRK, "traffic/s2c/key", listener, tServerFinished[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.C2SNonce[:], masterPRK, "traffic/c2s/nonce-prefix", listener, tServerFinished[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.S2CNonce[:], masterPRK, "traffic/s2c/nonce-prefix", listener, tServerFinished[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.SessionID[:], masterPRK, "session-id", listener, tServerFinished[:], v3RoleServer, v3RoleClient, "session", 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.C2SUpdateSecret[:], masterPRK, "traffic/c2s/update-secret", listener, tServerFinished[:], v3RoleClient, v3RoleServer, v3DirectionC2S, 0); err != nil {
		return result, err
	}
	if err := v3ExpandInto(result.S2CUpdateSecret[:], masterPRK, "traffic/s2c/update-secret", listener, tServerFinished[:], v3RoleServer, v3RoleClient, v3DirectionS2C, 0); err != nil {
		return result, err
	}
	return result, nil
}

func ComputeV3AdmissionTag(credential [V3KAuthLen]byte, listener V3ListenerContext, initBytes, retryBytes, coreBytes []byte) ([32]byte, error) {
	credentialPRK, err := v3CredentialPRK(credential, listener)
	if err != nil {
		return [32]byte{}, err
	}
	key, err := v3ExpandRaw(credentialPRK[:], "ewp/v3/admission", 32)
	if err != nil {
		return [32]byte{}, err
	}
	input := v3Hash("ewp/v3/admission-input", initBytes, retryBytes, coreBytes)
	mac := hmac.New(sha256.New, key)
	mac.Write(input[:])
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func ComputeV3ReplayKey(key [32]byte, listener V3ListenerContext, principal PrincipalID, claim V3PreKeyClaim) (ReplayKey, error) {
	if err := listener.validate(); err != nil {
		return ReplayKey{}, err
	}
	input := v3Domain(
		"ewp/v3/replay",
		v3Uint16Bytes(listener.Version),
		v3Uint16Bytes(uint16(listener.Suite)),
		[]byte(listener.ServerID),
		[]byte(listener.DeploymentScope),
		principal[:],
		claim.PreKeyID[:],
		claim.InitNonce[:],
		claim.ClientNonce[:],
		claim.CoreDigest[:],
	)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(input)
	var result ReplayKey
	copy(result[:], mac.Sum(nil))
	return result, nil
}
