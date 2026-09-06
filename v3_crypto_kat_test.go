package ewp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

type v3VectorFile struct {
	Listener struct {
		Version         uint16 `json:"version"`
		Suite           uint16 `json:"suite"`
		ServerID        string `json:"server_id"`
		DeploymentScope string `json:"deployment_scope"`
	} `json:"listener"`
	CredentialHex        string `json:"credential_hex"`
	OuterIKMHex          string `json:"outer_ikm_hex"`
	DataIKMHex           string `json:"data_ikm_hex"`
	TInitHex             string `json:"t_init_hex"`
	BundleDigestHex      string `json:"bundle_digest_hex"`
	ClientHeader         string `json:"client_hello_header"`
	TClientHelloHex      string `json:"t_client_hello_hex"`
	ServerHeader         string `json:"server_hello_header"`
	TServerHelloHex      string `json:"t_server_hello_hex"`
	Source               string `json:"source"`
	ExpiresAt            uint64 `json:"expires_at"`
	PreKeyIDHex          string `json:"prekey_id_hex"`
	BundleGeneration     uint64 `json:"bundle_generation"`
	InitNonceHex         string `json:"init_nonce_hex"`
	ClientNonceHex       string `json:"client_nonce_hex"`
	CoreDigestHex        string `json:"core_digest_hex"`
	PrincipalHex         string `json:"principal_hex"`
	CookieKeyHex         string `json:"cookie_key_hex"`
	ReplayKeyMaterialHex string `json:"replay_key_material_hex"`
	Admission            struct {
		Init  string `json:"init"`
		Retry string `json:"retry"`
		Core  string `json:"core"`
	} `json:"admission"`
	Record struct {
		KeyHex         string `json:"key_hex"`
		NoncePrefixHex string `json:"nonce_prefix_hex"`
		Type           uint8  `json:"type"`
		MetaHex        string `json:"meta_hex"`
		PayloadHex     string `json:"payload_hex"`
		PaddingHex     string `json:"padding_hex"`
		WireHex        string `json:"wire_hex"`
	} `json:"record"`
	Messages struct {
		ClientInitBaseHex string `json:"client_init_base_hex"`
		ClientInitHex     string `json:"client_init_hex"`
		HelloRetryHex     string `json:"hello_retry_hex"`
	} `json:"messages"`
	BundleKAT struct {
		Ed25519SeedHex    string `json:"ed25519_seed_hex"`
		Ed25519PublicHex  string `json:"ed25519_public_hex"`
		SignatureHex      string `json:"signature_hex"`
		DigestHex         string `json:"digest_hex"`
		UnsignedSHA256Hex string `json:"unsigned_sha256_hex"`
	} `json:"bundle_kat"`
	Expected map[string]string `json:"expected"`
}

func loadV3Vectors(t *testing.T) v3VectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/v3_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors v3VectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func v3Hex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode vector %q: %v", value, err)
	}
	return decoded
}

func v3Expected(t *testing.T, vectors v3VectorFile, name string) []byte {
	t.Helper()
	value, ok := vectors.Expected[name]
	if !ok {
		t.Fatalf("missing expected vector %q", name)
	}
	return v3Hex(t, value)
}

func v3Fixed32(t *testing.T, value string) (out [32]byte) {
	t.Helper()
	decoded := v3Hex(t, value)
	if len(decoded) != len(out) {
		t.Fatalf("vector length = %d, want %d", len(decoded), len(out))
	}
	copy(out[:], decoded)
	return out
}

func TestV3CryptoKAT(t *testing.T) {
	vectors := loadV3Vectors(t)
	listener := V3ListenerContext{
		Version:         vectors.Listener.Version,
		Suite:           SuiteID(vectors.Listener.Suite),
		ServerID:        vectors.Listener.ServerID,
		DeploymentScope: vectors.Listener.DeploymentScope,
	}
	credential := v3Fixed32(t, vectors.CredentialHex)
	route := ComputeV3RouteTag(credential, listener, 7)
	if !bytes.Equal(route[:], v3Expected(t, vectors, "route_tag_hex")) {
		t.Fatal("route tag KAT mismatch")
	}
	outerIKM := v3Hex(t, vectors.OuterIKMHex)
	dataIKM := v3Hex(t, vectors.DataIKMHex)
	tInit := v3Fixed32(t, vectors.TInitHex)
	bundleDigest := v3Fixed32(t, vectors.BundleDigestHex)
	tClientHello := v3Fixed32(t, vectors.TClientHelloHex)
	tServerHello := v3Fixed32(t, vectors.TServerHelloHex)

	credentialSalt := v3Hash("ewp/v3/credential-salt", v3Uint16Bytes(listener.Version), v3Uint16Bytes(uint16(listener.Suite)), []byte(listener.ServerID), []byte(listener.DeploymentScope))
	if string(credentialSalt[:]) != string(v3Expected(t, vectors, "credential_salt_hex")) {
		t.Fatal("credential salt KAT mismatch")
	}
	credentialPRK, err := v3CredentialPRK(credential, listener)
	if err != nil {
		t.Fatal(err)
	}
	if string(credentialPRK[:]) != string(v3Expected(t, vectors, "credential_prk_hex")) {
		t.Fatal("credential PRK KAT mismatch")
	}
	outerPRK, err := deriveV3OuterPRK(listener, credentialPRK, outerIKM, tInit, BundleDigest(bundleDigest), []byte(vectors.ClientHeader))
	if err != nil {
		t.Fatal(err)
	}
	if string(outerPRK[:]) != string(v3Expected(t, vectors, "outer_prk_hex")) {
		t.Fatal("outer PRK KAT mismatch")
	}
	serverPRK, err := deriveV3ServerHelloPRK(listener, credentialPRK, outerPRK, dataIKM, tClientHello, []byte(vectors.ServerHeader))
	if err != nil {
		t.Fatal(err)
	}
	if string(serverPRK[:]) != string(v3Expected(t, vectors, "server_hello_prk_hex")) {
		t.Fatal("server hello PRK KAT mismatch")
	}
	material, err := deriveV3HandshakeMaterial(listener, credentialPRK, outerIKM, dataIKM, tInit, BundleDigest(bundleDigest), []byte(vectors.ClientHeader), tClientHello, []byte(vectors.ServerHeader), tServerHello)
	if err != nil {
		t.Fatal(err)
	}
	if string(material.handshakePRK[:]) != string(v3Expected(t, vectors, "handshake_prk_hex")) {
		t.Fatal("handshake PRK KAT mismatch")
	}
	checks := map[string][]byte{
		"client_hello_key_hex":           material.clientHelloKey[:],
		"client_hello_nonce_hex":         material.clientHelloNonce[:],
		"server_hello_key_hex":           material.serverHelloKey[:],
		"server_hello_nonce_hex":         material.serverHelloNonce[:],
		"client_finished_key_hex":        material.clientFinishedKey[:],
		"client_finished_nonce_hex":      material.clientFinishedNonce[:],
		"client_finished_verify_key_hex": material.clientFinishedVerifyKey[:],
		"server_finished_key_hex":        material.serverFinishedKey[:],
		"server_finished_nonce_hex":      material.serverFinishedNonce[:],
		"server_finished_verify_key_hex": material.serverFinishedVerifyKey[:],
	}
	for name, got := range checks {
		if string(got) != string(v3Expected(t, vectors, name)) {
			t.Fatalf("%s KAT mismatch", name)
		}
	}
	clientVerify := v3FinishedVerify(material.clientFinishedVerifyKey, "ewp/v3/client-finished-verify", tServerHello)
	if string(clientVerify[:]) != string(v3Expected(t, vectors, "client_verify_data_hex")) {
		t.Fatal("client Finished verify KAT mismatch")
	}
	serverVerify := v3FinishedVerify(material.serverFinishedVerifyKey, "ewp/v3/server-finished-verify", v3Fixed32(t, vectors.Expected["client_finished_transcript_hex"]))
	if string(serverVerify[:]) != string(v3Expected(t, vectors, "server_verify_data_hex")) {
		t.Fatal("server Finished verify KAT mismatch")
	}
	serverFinishedTranscript := v3Fixed32(t, vectors.Expected["server_finished_transcript_hex"])
	session, err := deriveV3SessionKeys(material, listener, serverFinishedTranscript)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{
		"c2s_key_hex":    session.C2SKey[:],
		"s2c_key_hex":    session.S2CKey[:],
		"c2s_nonce_hex":  session.C2SNonce[:],
		"s2c_nonce_hex":  session.S2CNonce[:],
		"session_id_hex": session.SessionID[:],
	} {
		if string(got) != string(v3Expected(t, vectors, name)) {
			t.Fatalf("%s KAT mismatch", name)
		}
	}

	var preKeyID PreKeyID
	copy(preKeyID[:], v3Hex(t, vectors.PreKeyIDHex))
	var initNonce, clientNonce V3Nonce
	copy(initNonce[:], v3Hex(t, vectors.InitNonceHex))
	copy(clientNonce[:], v3Hex(t, vectors.ClientNonceHex))
	var coreDigest [32]byte
	copy(coreDigest[:], v3Hex(t, vectors.CoreDigestHex))
	var principal PrincipalID
	copy(principal[:], v3Hex(t, vectors.PrincipalHex))
	var cookieKey [32]byte
	copy(cookieKey[:], v3Hex(t, vectors.CookieKeyHex))
	init := V3ClientInit{
		Version: vectors.Listener.Version, Suite: SuiteID(vectors.Listener.Suite), ServerID: listener.ServerID,
		DeploymentScope: listener.DeploymentScope, PreKeyID: preKeyID, BundleGeneration: vectors.BundleGeneration,
		BundleDigest: BundleDigest(bundleDigest), InitNonce: initNonce, ClientNonce: clientNonce, CoreDigest: coreDigest,
		RouteTag: route, RouteEpoch: 7,
	}
	baseBytes, err := init.BaseBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(baseBytes, v3Hex(t, vectors.Messages.ClientInitBaseHex)) {
		t.Fatal("ClientInitBase canonical KAT mismatch")
	}
	initBytes, err := init.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initBytes, v3Hex(t, vectors.Messages.ClientInitHex)) {
		t.Fatal("ClientInit canonical KAT mismatch")
	}
	parsedRetry, err := ParseV3HelloRetry(v3Hex(t, vectors.Messages.HelloRetryHex))
	if err != nil {
		t.Fatal(err)
	}
	reencodedRetry, err := parsedRetry.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencodedRetry, v3Hex(t, vectors.Messages.HelloRetryHex)) {
		t.Fatal("HelloRetry canonical KAT mismatch")
	}
	seed := v3Hex(t, vectors.BundleKAT.Ed25519SeedHex)
	identity, err := NewServerSigningIdentity(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(identity.Public[:], v3Hex(t, vectors.BundleKAT.Ed25519PublicHex)) {
		t.Fatal("Ed25519 public key KAT mismatch")
	}
	var bundlePreKeyID PreKeyID
	copy(bundlePreKeyID[:], v3Hex(t, vectors.PreKeyIDHex))
	var bundleX25519 [X25519PubLen]byte
	for i := range bundleX25519 {
		bundleX25519[i] = byte(0x20 + i)
	}
	var bundleMLKEM [MLKEM768PubLen]byte
	for i := range bundleMLKEM {
		bundleMLKEM[i] = byte(0x40 + i)
	}
	bundle := V3PreKeyBundle{
		Version: vectors.Listener.Version, Suite: SuiteID(vectors.Listener.Suite),
		ServerID: listener.ServerID, DeploymentScope: listener.DeploymentScope,
		RouteEpoch: 7, BundleGeneration: 9, PreKeyID: bundlePreKeyID,
		NotBefore: 1700000000, NotAfter: 1800000000,
		PreKeyX25519Public: bundleX25519, PreKeyMLKEMPublic: bundleMLKEM,
	}
	unsigned, err := bundle.MarshalUnsigned()
	if err != nil {
		t.Fatal(err)
	}
	unsignedDigest := sha256.Sum256(unsigned)
	if !bytes.Equal(unsignedDigest[:], v3Hex(t, vectors.BundleKAT.UnsignedSHA256Hex)) {
		t.Fatal("prekey unsigned encoding KAT mismatch")
	}
	if err := bundle.Sign(identity); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.Signature[:], v3Hex(t, vectors.BundleKAT.SignatureHex)) {
		t.Fatal("prekey signature KAT mismatch")
	}
	if err := bundle.Verify(identity.Public); err != nil {
		t.Fatal(err)
	}
	bundleDigestKAT, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundleDigestKAT[:], v3Hex(t, vectors.BundleKAT.DigestHex)) {
		t.Fatal("prekey digest KAT mismatch")
	}
	bundleBytes, err := bundle.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsedBundle, err := ParseV3PreKeyBundle(bundleBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !sameV3PreKeyBundle(parsedBundle, bundle) {
		t.Fatal("prekey bundle parse changed KAT fields")
	}
	retry := V3HelloRetry{Version: listener.Version, Suite: listener.Suite, InitNonce: initNonce, ExpiresAt: vectors.ExpiresAt}
	keys := V3CookieKeys{Current: V3CookieKey{ID: 3, Key: cookieKey}}
	cookie := keys.cookie(listener, init, retry, SourceBinding(vectors.Source), cookieKey)
	if string(cookie[:]) != string(v3Expected(t, vectors, "cookie_hex")) {
		t.Fatal("cookie KAT mismatch")
	}
	admission, err := ComputeV3AdmissionTag(credential, listener, []byte(vectors.Admission.Init), []byte(vectors.Admission.Retry), []byte(vectors.Admission.Core))
	if err != nil {
		t.Fatal(err)
	}
	if string(admission[:]) != string(v3Expected(t, vectors, "admission_tag_hex")) {
		t.Fatal("admission tag KAT mismatch")
	}
	var replayMaterial [32]byte
	copy(replayMaterial[:], v3Hex(t, vectors.ReplayKeyMaterialHex))
	replay, err := ComputeV3ReplayKey(replayMaterial, listener, principal, V3PreKeyClaim{
		Version: listener.Version, Suite: listener.Suite, ServerID: listener.ServerID, DeploymentScope: listener.DeploymentScope,
		PreKeyID: preKeyID, InitNonce: initNonce, ClientNonce: clientNonce, CoreDigest: coreDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(replay[:]) != string(v3Expected(t, vectors, "replay_key_hex")) {
		t.Fatal("replay key KAT mismatch")
	}

	// Check the Finished value independently through the public hash contract.
	if !bytes.Equal(clientVerify[:], v3Expected(t, vectors, "client_verify_data_hex")) {
		t.Fatal("client verify comparison failed")
	}

	var recordKey [AEADKeyLen]byte
	var recordPrefix [NoncePrefixLen]byte
	copy(recordKey[:], v3Hex(t, vectors.Record.KeyHex))
	copy(recordPrefix[:], v3Hex(t, vectors.Record.NoncePrefixHex))
	encoder, err := NewFrameAEAD(recordKey, recordPrefix)
	if err != nil {
		t.Fatal(err)
	}
	padding := v3Hex(t, vectors.Record.PaddingHex)
	var wire bytes.Buffer
	if err := encodeRecordWithReader(&wire, encoder, FrameType(vectors.Record.Type), v3Hex(t, vectors.Record.MetaHex), v3Hex(t, vectors.Record.PayloadHex), len(padding), &v3FixedReader{data: padding}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), v3Hex(t, vectors.Record.WireHex)) {
		t.Fatal("opaque record KAT mismatch")
	}
	decoder, err := NewFrameAEAD(recordKey, recordPrefix)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRecord(bytes.NewReader(wire.Bytes()), decoder)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != FrameType(vectors.Record.Type) || !bytes.Equal(decoded.Meta, v3Hex(t, vectors.Record.MetaHex)) || !bytes.Equal(decoded.Payload, v3Hex(t, vectors.Record.PayloadHex)) {
		t.Fatalf("decoded record = %#v", decoded)
	}
}

type v3FixedReader struct {
	data []byte
	off  int
}

func (r *v3FixedReader) Read(dst []byte) (int, error) {
	if r.off+len(dst) > len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	copy(dst, r.data[r.off:r.off+len(dst)])
	r.off += len(dst)
	return len(dst), nil
}
