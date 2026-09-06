package ewp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// v23VectorFile is the JSON schema of testdata/v23_vectors.json. Every
// value is generated once by the oracle in testdata/v23_kat_oracle.py and
// then frozen; tests must not derive new expected values at run time.
type v23VectorFile struct {
	ServerID   string `json:"server_id"`
	RouteEpoch uint64 `json:"route_epoch"`

	UUIDHex       string `json:"uuid_hex"`
	CookieKeyHex  string `json:"cookie_key_hex"`
	SigningSeedHex string `json:"signing_seed_hex"`

	ClientNonceHex string `json:"client_nonce_hex"`
	ServerNonceHex string `json:"server_nonce_hex"`
	ExpiresAt      uint64 `json:"expires_at"`
	Source         string `json:"source"`

	OuterKeyIDHex string `json:"outer_key_id_hex"`
	OuterPubHex   string `json:"outer_pub_hex"`

	RouteTagHex     string `json:"route_tag_hex"`
	CookieHex       string `json:"cookie_hex"`
	ClientInitHex   string `json:"client_init_hex"`
	HelloRetryHex   string `json:"hello_retry_hex"`
	TCIHex          string `json:"t_ci_hex"`
	THRHex          string `json:"t_hr_hex"`
	OuterKeySigHex  string `json:"outer_key_sig_hex"`
}

func v23Hex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func v23B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// TestV23CryptoKAT verifies every v2.3 crypto step against frozen vectors.
func TestV23CryptoKAT(t *testing.T) {
	data, err := os.ReadFile("testdata/v23_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v (run testdata/v23_kat_oracle.py first)", err)
	}
	var v v23VectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}

	var uuid [UUIDLen]byte
	copy(uuid[:], v23Hex(t, v.UUIDHex))
	var cookieKey [32]byte
	copy(cookieKey[:], v23Hex(t, v.CookieKeyHex))
	signingSeed := v23Hex(t, v.SigningSeedHex)
	signing := ed25519.NewKeyFromSeed(signingSeed)

	// Route tag.
	wantRoute := v23Hex(t, v.RouteTagHex)
	gotRoute := v23RouteTag(uuid, v.ServerID, v.RouteEpoch)
	if !bytes.Equal(gotRoute[:], wantRoute) {
		t.Fatalf("route tag mismatch:\n got %x\nwant %x", gotRoute, wantRoute)
	}

	// ClientInit wire.
	var ci V23ClientInit
	copy(ci.ClientNonce[:], v23Hex(t, v.ClientNonceHex))
	copy(ci.RouteTag[:], wantRoute)
	if got := ci.marshal(); !bytes.Equal(got, v23Hex(t, v.ClientInitHex)) {
		t.Fatalf("ClientInit wire mismatch:\n got %x\nwant %x", got, v.ClientInitHex)
	}
	parsedCI, err := parseV23ClientInit(v23Hex(t, v.ClientInitHex))
	if err != nil || parsedCI.ClientNonce != ci.ClientNonce {
		t.Fatalf("ClientInit parse: %v", err)
	}

	// Transcript T_ci.
	tCI := v23Transcript(v23Suite.labelTCI, ci.marshal())
	if got := tCI[:]; !bytes.Equal(got, v23Hex(t, v.TCIHex)) {
		t.Fatalf("T_ci mismatch:\n got %x\nwant %x", got, v.TCIHex)
	}

	// HelloRetry wire + cookie.
	var hr V23HelloRetry
	copy(hr.ClientNonce[:], v23Hex(t, v.ClientNonceHex))
	copy(hr.ServerNonce[:], v23Hex(t, v.ServerNonceHex))
	hr.ExpiresAt = v.ExpiresAt
	copy(hr.OuterKeyID[:], v23Hex(t, v.OuterKeyIDHex))
	copy(hr.OuterX25519[:], v23Hex(t, v.OuterPubHex))
	hr.NotBefore = v.ExpiresAt - 3600
	hr.NotAfter = v.ExpiresAt + 3600
	hr.Cookie = v23Cookie(cookieKey, v.ServerID, v.Source, &ci, hr.ServerNonce, hr.ExpiresAt, hr.OuterKeyID)
	if got := hr.Cookie[:]; !bytes.Equal(got, v23Hex(t, v.CookieHex)) {
		t.Fatalf("cookie mismatch:\n got %x\nwant %x", got, v.CookieHex)
	}

	// Outer-key signature.
	copy(hr.Signature[:], v23Hex(t, v.OuterKeySigHex))
	pub := signing.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, v23OuterKeySignPayload(v.ServerID, &hr), hr.Signature[:]) {
		t.Fatal("outer key signature does not verify")
	}
	// Independently recompute the signature from the seed.
	recomputed := ed25519.Sign(signing, v23OuterKeySignPayload(v.ServerID, &hr))
	if !bytes.Equal(recomputed, hr.Signature[:]) {
		t.Fatal("recomputed signature differs from frozen vector")
	}

	// T_hr covers ClientInit + the full HelloRetry including its signature.
	hrWire := hr.marshal()
	tHR := v23Transcript(v23Suite.labelTHR, tCI[:], hrWire)
	if got := tHR[:]; !bytes.Equal(got, v23Hex(t, v.THRHex)) {
		t.Fatalf("T_hr mismatch:\n got %x\nwant %x", got, v.THRHex)
	}
}

// v23OuterKeySignPayload is the exact byte sequence signed for a short-term
// outer key. It is factored out so the KAT can recompute it independently.
func v23OuterKeySignPayload(serverID string, hr *V23HelloRetry) []byte {
	h := sha256.New()
	h.Write([]byte(v23Suite.labelOuterKeyID))
	h.Write([]byte(serverID))
	h.Write(hr.OuterKeyID[:])
	var buf [8]byte
	buf[0] = byte(hr.NotBefore >> 56)
	buf[1] = byte(hr.NotBefore >> 48)
	buf[2] = byte(hr.NotBefore >> 40)
	buf[3] = byte(hr.NotBefore >> 32)
	buf[4] = byte(hr.NotBefore >> 24)
	buf[5] = byte(hr.NotBefore >> 16)
	buf[6] = byte(hr.NotBefore >> 8)
	buf[7] = byte(hr.NotBefore)
	h.Write(buf[:])
	buf[0] = byte(hr.NotAfter >> 56)
	buf[1] = byte(hr.NotAfter >> 48)
	buf[2] = byte(hr.NotAfter >> 40)
	buf[3] = byte(hr.NotAfter >> 32)
	buf[4] = byte(hr.NotAfter >> 24)
	buf[5] = byte(hr.NotAfter >> 16)
	buf[6] = byte(hr.NotAfter >> 8)
	buf[7] = byte(hr.NotAfter)
	h.Write(buf[:])
	h.Write(hr.OuterX25519[:])
	return h.Sum(nil)
}
