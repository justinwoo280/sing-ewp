// Package ewp implements the EWP v2 protocol as specified in doc/EWP_V2.md.
//
// EWP v2 has no compatibility with v1. Implementations of this package
// MUST conform to doc/EWP_V2.md byte-for-byte. Discrepancies are bugs in
// the code, not in the spec.
package ewp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// AddressType identifies the wire encoding of an Address.
type AddressType byte

const (
	AddrTypeIPv4   AddressType = 0x01
	AddrTypeIPv6   AddressType = 0x02
	AddrTypeDomain AddressType = 0x03
)

// MaxDomainLen is the maximum permitted domain label length in bytes.
// 253 matches RFC 1123 (255 minus the wire-format leading length and
// trailing zero on the equivalent DNS encoding).
const MaxDomainLen = 253

// ErrAddrTooShort is returned when there are not enough bytes to decode
// a complete Address.
var ErrAddrTooShort = errors.New("ewp/v2: address truncated")

// ErrAddrType is returned when the AddrType byte is not in {1,2,3}.
var ErrAddrType = errors.New("ewp/v2: unknown address type")

// ErrDomainLen is returned when a domain label is empty or exceeds
// MaxDomainLen.
var ErrDomainLen = errors.New("ewp/v2: invalid domain length")

// Address is the unified destination/source representation used by
// EWP v2. Exactly one of (Addr, Domain) is meaningful.
//
// Domain takes precedence on the wire whenever non-empty.
type Address struct {
	Addr   netip.AddrPort // valid when Domain == ""
	Domain string         // non-empty selects domain encoding
	Port   uint16         // used together with Domain
}

// IsDomain reports whether this Address is a domain target.
func (a Address) IsDomain() bool { return a.Domain != "" }

// String returns a human-readable form for logs only. The output is not
// the wire format and MUST NOT be parsed.
func (a Address) String() string {
	if a.IsDomain() {
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	}
	return a.Addr.String()
}

// EncodedLen returns the number of bytes Append will write for a.
func (a Address) EncodedLen() int {
	if a.IsDomain() {
		// type(1) + domainLen(1) + domain + port(2)
		return 1 + 1 + len(a.Domain) + 2
	}
	if a.Addr.Addr().Is6() {
		return 1 + 16 + 2
	}
	return 1 + 4 + 2
}

// Append serialises a to dst and returns the extended slice.
//
// For an invalid Address (no domain and no valid Addr) Append returns
// dst unchanged and a non-nil error.
func (a Address) Append(dst []byte) ([]byte, error) {
	switch {
	case a.IsDomain():
		if len(a.Domain) == 0 || len(a.Domain) > MaxDomainLen {
			return dst, ErrDomainLen
		}
		dst = append(dst, byte(AddrTypeDomain), byte(len(a.Domain)))
		dst = append(dst, a.Domain...)
		dst = append(dst, byte(a.Port>>8), byte(a.Port))
		return dst, nil
	case a.Addr.IsValid() && a.Addr.Addr().Is4():
		dst = append(dst, byte(AddrTypeIPv4))
		ip4 := a.Addr.Addr().As4()
		dst = append(dst, ip4[:]...)
		port := a.Addr.Port()
		dst = append(dst, byte(port>>8), byte(port))
		return dst, nil
	case a.Addr.IsValid() && a.Addr.Addr().Is6():
		dst = append(dst, byte(AddrTypeIPv6))
		ip6 := a.Addr.Addr().As16()
		dst = append(dst, ip6[:]...)
		port := a.Addr.Port()
		dst = append(dst, byte(port>>8), byte(port))
		return dst, nil
	default:
		return dst, fmt.Errorf("ewp/v2: invalid address: %+v", a)
	}
}

// DecodeAddress parses a single Address from the front of buf and
// returns the parsed value, the number of bytes consumed, and any
// error.
func DecodeAddress(buf []byte) (Address, int, error) {
	if len(buf) < 1 {
		return Address{}, 0, ErrAddrTooShort
	}
	switch AddressType(buf[0]) {
	case AddrTypeIPv4:
		if len(buf) < 1+4+2 {
			return Address{}, 0, ErrAddrTooShort
		}
		var ip [4]byte
		copy(ip[:], buf[1:5])
		port := binary.BigEndian.Uint16(buf[5:7])
		addr := netip.AddrPortFrom(netip.AddrFrom4(ip), port)
		return Address{Addr: addr}, 7, nil
	case AddrTypeIPv6:
		if len(buf) < 1+16+2 {
			return Address{}, 0, ErrAddrTooShort
		}
		var ip [16]byte
		copy(ip[:], buf[1:17])
		port := binary.BigEndian.Uint16(buf[17:19])
		addr := netip.AddrPortFrom(netip.AddrFrom16(ip), port)
		return Address{Addr: addr}, 19, nil
	case AddrTypeDomain:
		if len(buf) < 2 {
			return Address{}, 0, ErrAddrTooShort
		}
		dlen := int(buf[1])
		if dlen == 0 || dlen > MaxDomainLen {
			return Address{}, 0, ErrDomainLen
		}
		if len(buf) < 2+dlen+2 {
			return Address{}, 0, ErrAddrTooShort
		}
		domain := string(buf[2 : 2+dlen])
		port := binary.BigEndian.Uint16(buf[2+dlen : 2+dlen+2])
		return Address{Domain: domain, Port: port}, 2 + dlen + 2, nil
	default:
		return Address{}, 0, ErrAddrType
	}
}
