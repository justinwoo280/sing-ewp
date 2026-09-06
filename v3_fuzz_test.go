package ewp

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func FuzzParseV3PreKeyBundle(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x42}, 256))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxV3MessageSize+32 {
			t.Skip()
		}
		parsed, err := ParseV3PreKeyBundle(data)
		if err != nil {
			return
		}
		encoded, err := parsed.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseV3PreKeyBundle(encoded); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzDecodeV3Address(f *testing.F) {
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

func FuzzV3AddressRoundTrip(f *testing.F) {
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

func FuzzDecodeV3IPAddr(f *testing.F) {
	f.Add(uint16(443), byte(4))
	f.Fuzz(func(t *testing.T, port uint16, last byte) {
		address := Address{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, last}), port)}
		encoded, err := address.Append(nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, consumed, err := DecodeAddress(encoded)
		if err != nil || consumed != len(encoded) || decoded.Addr != address.Addr {
			t.Fatal(err)
		}
	})
}

func FuzzParseV3ClientInit(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 0, 2, 0, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxV3MessageSize+32 {
			t.Skip()
		}
		parsed, err := ParseV3ClientInit(data)
		if err != nil {
			return
		}
		encoded, err := parsed.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseV3ClientInit(encoded); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzParseV3HelloRetry(f *testing.F) {
	seed, err := testHelloRetry().MarshalBinary()
	if err != nil {
		f.Fatalf("seed: %v", err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxV3MessageSize+32 {
			t.Skip()
		}
		parsed, err := ParseV3HelloRetry(data)
		if err != nil {
			return
		}
		encoded, err := parsed.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseV3HelloRetry(encoded); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzParseV3ClientHelloCore(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x42}, 32))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxV3MessageSize+32 {
			t.Skip()
		}
		parsed, err := ParseV3ClientHelloCore(data)
		if err != nil {
			return
		}
		encoded, err := parsed.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseV3ClientHelloCore(encoded); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzParseV3ClientHello(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxV3MessageSize+32 {
			t.Skip()
		}
		_, _ = ParseV3ClientHello(data)
	})
}

func FuzzParseV3ServerHello(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxV3MessageSize+32 {
			t.Skip()
		}
		_, _ = ParseV3ServerHello(data)
	})
}

func FuzzParseV3Finished(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxV3MessageSize+32 {
			t.Skip()
		}
		_, _ = ParseV3ClientFinished(data)
		_, _ = ParseV3ServerFinished(data)
	})
}

func FuzzDecodeV3Record(f *testing.F) {
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
	if err := encodeRecordWithReader(&seed, encoder, FrameTCPData, nil, []byte("seed"), 0, bytes.NewReader(bytes.Repeat([]byte{0x11}, 64))); err != nil {
		f.Fatalf("seed record: %v", err)
	}
	f.Add(seed.Bytes())
	f.Add([]byte{0, 0, 0, 16})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxFrameSize+64 {
			t.Skip()
		}
		decoder, err := NewFrameAEAD(key, prefix)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = DecodeRecord(bytes.NewReader(data), decoder)
	})
}

func FuzzV3HandshakeActions(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Fuzz(func(t *testing.T, actions []byte) {
		if len(actions) > 256 {
			t.Skip()
		}
		// Action bytes are deliberately interpreted only as bounded wire
		// mutations. The decoder is the terminal state for malformed input;
		// no fuzz case may reach an unbounded allocation or panic.
		for offset := 0; offset+6 <= len(actions); offset += 6 {
			data := append([]byte(nil), actions[offset:]...)
			if len(data) >= 6 {
				binary.BigEndian.PutUint32(data[2:6], uint32(len(data)))
			}
			_, _ = ParseV3HelloRetry(data)
		}
	})
}
