package ewp

import (
	"bytes"
	"net/netip"
	"testing"
)

// FuzzDecodeAddress covers the shared address codec used by every version.
func FuzzDecodeAddress(f *testing.F) {
	f.Add([]byte{byte(AddrTypeIPv4), 127, 0, 0, 1, 0, 53})
	f.Add([]byte{byte(AddrTypeDomain), 3, 'w', 'e', 'b', 1, 187})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxDomainLen+32 {
			t.Skip()
		}
		address, consumed, err := DecodeAddress(data)
		if err != nil {
			return
		}
		encoded, err := address.Append(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, data[:consumed]) {
			t.Fatal("address prefix changed during round trip")
		}
		if _, _, err := DecodeAddress(encoded); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzAddressRoundTrip covers domain round-trips.
func FuzzAddressRoundTrip(f *testing.F) {
	f.Add(uint16(53), []byte("example.com"))
	f.Fuzz(func(t *testing.T, port uint16, domain []byte) {
		if len(domain) == 0 || len(domain) > MaxDomainLen {
			t.Skip()
		}
		address := Address{Domain: string(domain), Port: port}
		encoded, err := address.Append(nil)
		if err != nil {
			return
		}
		decoded, consumed, err := DecodeAddress(encoded)
		if err != nil || consumed != len(encoded) {
			t.Fatal(err)
		}
		if decoded.Domain != address.Domain || decoded.Port != address.Port {
			t.Fatal("domain address changed during round trip")
		}
	})
}

// FuzzDecodeIPAddr covers the IP-literal address path.
func FuzzDecodeIPAddr(f *testing.F) {
	f.Add(uint16(443), byte(4))
	f.Fuzz(func(t *testing.T, port uint16, last byte) {
		address := Address{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, last}), port)}
		encoded, err := address.Append(nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, consumed, err := DecodeAddress(encoded)
		if err != nil || consumed != len(encoded) {
			t.Fatal(err)
		}
		if decoded.Addr != address.Addr {
			t.Fatal("ip address changed during round trip")
		}
	})
}

// FuzzDecodeV22Record throws arbitrary bytes at the v2.2 opaque record
// decoder. The decoder must never panic, never allocate unboundedly, and
// must reject non-canonical input.
func FuzzDecodeV22Record(f *testing.F) {
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range prefix {
		prefix[i] = byte(0xa0 + i)
	}
	encoder, err := NewFrameAEAD(key, prefix)
	if err != nil {
		f.Fatalf("encoder: %v", err)
	}
	var seed bytes.Buffer
	if err := encodeFrameV22WithPad(&seed, encoder, FrameTCPData, nil, []byte("seed"), 0); err != nil {
		f.Fatalf("seed record: %v", err)
	}
	f.Add(seed.Bytes())
	f.Add([]byte{0, 0, 0, 16})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxV22RecordSize+64 {
			t.Skip()
		}
		decoder, err := NewFrameAEAD(key, prefix)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = DecodeFrameV22(bytes.NewReader(data), decoder)
	})
}

// FuzzV23HandshakeMessages fuzzes the v2.3 message parsers: ClientInit and
// HelloRetry must reject malformed input without panic.
func FuzzV23ClientInit(f *testing.F) {
	f.Add(make([]byte, V23ClientNonceLen+V23RouteTagLen))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256 {
			t.Skip()
		}
		m, err := parseV23ClientInit(data)
		if err != nil {
			return
		}
		// A successful parse must round-trip byte-exact.
		if !bytes.Equal(m.marshal(), data) {
			t.Fatal("ClientInit round trip changed bytes")
		}
	})
}

func FuzzV23HelloRetry(f *testing.F) {
	var m V23HelloRetry
	f.Add(m.marshal())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 512 {
			t.Skip()
		}
		parsed, err := parseV23HelloRetry(data)
		if err != nil {
			return
		}
		if !bytes.Equal(parsed.marshal(), data) {
			t.Fatal("HelloRetry round trip changed bytes")
		}
	})
}

// FuzzV23Cookie verifies the cookie HMAC never panics on adversarial
// source strings.
func FuzzV23Cookie(f *testing.F) {
	var key [32]byte
	var ci V23ClientInit
	f.Add("127.0.0.1:443", uint64(1700000000))
	f.Fuzz(func(t *testing.T, source string, expiresAt uint64) {
		if len(source) > 512 {
			t.Skip()
		}
		var snonce [V23ServerNonceLen]byte
		var keyID [V23OuterKeyIDLen]byte
		_ = v23Cookie(key, "srv", source, &ci, snonce, expiresAt, keyID)
	})
}
