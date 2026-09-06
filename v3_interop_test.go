package ewp_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	ewp "github.com/justinwoo280/sing-ewp"
)

func referenceField(tag uint16, value []byte) []byte {
	result := make([]byte, 6+len(value))
	binary.BigEndian.PutUint16(result[:2], tag)
	binary.BigEndian.PutUint32(result[2:6], uint32(len(value)))
	copy(result[6:], value)
	return result
}

func referenceU16(tag, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return referenceField(tag, encoded[:])
}

func referenceU64(tag uint16, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return referenceField(tag, encoded[:])
}

func referenceAddress(address ewp.Address) []byte {
	if address.Domain != "" {
		result := []byte{byte(ewp.AddrTypeDomain), byte(len(address.Domain))}
		result = append(result, address.Domain...)
		return append(result, byte(address.Port>>8), byte(address.Port))
	}
	if address.Addr.Addr().Is4() {
		result := []byte{byte(ewp.AddrTypeIPv4)}
		ip := address.Addr.Addr().As4()
		result = append(result, ip[:]...)
		return append(result, byte(address.Addr.Port()>>8), byte(address.Addr.Port()))
	}
	result := []byte{byte(ewp.AddrTypeIPv6)}
	ip := address.Addr.Addr().As16()
	result = append(result, ip[:]...)
	return append(result, byte(address.Addr.Port()>>8), byte(address.Addr.Port()))
}

func TestV3DifferentialHelloRetryEncoding(t *testing.T) {
	var initNonce, retryNonce ewp.V3Nonce
	var cookie ewp.V3CookieKey
	for i := range initNonce {
		initNonce[i] = byte(i + 1)
		retryNonce[i] = byte(0x40 + i)
	}
	for i := range cookie.Key {
		cookie.Key[i] = byte(0x80 + i)
	}
	message := ewp.V3HelloRetry{
		Version:     ewp.V3ProtocolVersion,
		Suite:       ewp.V3SuiteX25519MLKEM768ChaCha20Poly1305,
		InitNonce:   initNonce,
		RetryNonce:  retryNonce,
		CookieKeyID: 3,
		ExpiresAt:   1_900_000_000,
	}
	copy(message.Cookie[:], cookie.Key[:])

	reference := make([]byte, 0, 128)
	reference = append(reference, referenceU16(1, message.Version)...)
	reference = append(reference, referenceU16(2, uint16(message.Suite))...)
	reference = append(reference, referenceField(10, message.InitNonce[:])...)
	reference = append(reference, referenceField(13, message.RetryNonce[:])...)
	reference = append(reference, referenceField(14, []byte{message.CookieKeyID})...)
	reference = append(reference, referenceU64(15, message.ExpiresAt)...)
	reference = append(reference, referenceField(16, message.Cookie[:])...)
	encoded, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reference) {
		t.Fatalf("HelloRetry differs from independent codec:\n got %x\nwant %x", encoded, reference)
	}
}

func TestV3DifferentialAddressEncoding(t *testing.T) {
	cases := []ewp.Address{
		{Addr: netip.MustParseAddrPort("192.0.2.10:443")},
		{Addr: netip.MustParseAddrPort("[2001:db8::10]:8443")},
		{Domain: "reference.example", Port: 5353},
	}
	for _, address := range cases {
		encoded, err := address.Append(nil)
		if err != nil {
			t.Fatal(err)
		}
		reference := referenceAddress(address)
		if !bytes.Equal(encoded, reference) {
			t.Fatalf("address %v differs from independent codec: got %x want %x", address, encoded, reference)
		}
		decoded, consumed, err := ewp.DecodeAddress(reference)
		if err != nil || consumed != len(reference) || decoded.String() != address.String() {
			t.Fatalf("reference address did not decode: got %v/%d/%v want %v", decoded, consumed, err, address)
		}
	}
}
