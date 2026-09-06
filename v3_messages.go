package ewp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// The numeric tags are part of the v3 wire format. They intentionally remain
// stable when optional fields are added; new critical fields use the high tag
// bit and are rejected by older implementations.
const (
	v3TagVersion          uint16 = 1
	v3TagSuite            uint16 = 2
	v3TagServerID         uint16 = 3
	v3TagDeploymentScope  uint16 = 4
	v3TagRouteTag         uint16 = 5
	v3TagRouteEpoch       uint16 = 6
	v3TagPreKeyID         uint16 = 7
	v3TagBundleGeneration uint16 = 8
	v3TagBundleDigest     uint16 = 9
	v3TagInitNonce        uint16 = 10
	v3TagClientNonce      uint16 = 11
	v3TagCoreDigest       uint16 = 12

	v3TagRetryNonce  uint16 = 13
	v3TagCookieKeyID uint16 = 14
	v3TagExpiresAt   uint16 = 15
	v3TagCookie      uint16 = 16

	v3TagOuterX25519Public uint16 = 17
	v3TagOuterMLKEMCipher  uint16 = 18
	v3TagCoreCiphertext    uint16 = 19

	v3TagClientInit      uint16 = 20
	v3TagHelloRetry      uint16 = 21
	v3TagClientHelloCore uint16 = 22
	v3TagAdmissionTag    uint16 = 23

	v3TagServerNonce       uint16 = 24
	v3TagHandshakeID       uint16 = 25
	v3TagServerDataX25519  uint16 = 26
	v3TagDataMLKEMCipher   uint16 = 27
	v3TagServerHelloHeader uint16 = 28

	v3TagCommand                uint16 = 29
	v3TagDestination            uint16 = 30
	v3TagClientDataX25519Public uint16 = 31
	v3TagClientDataMLKEMPublic  uint16 = 32
	v3TagNegotiatedParameters   uint16 = 33
	v3TagRandomPadding          uint16 = 34

	v3TagServerHelloCiphertext uint16 = 35
	v3TagSignature             uint16 = 36

	v3TagFinishedVersion     uint16 = 37
	v3TagFinishedSuite       uint16 = 38
	v3TagFinishedHandshakeID uint16 = 39
	v3TagFinishedCiphertext  uint16 = 40
	v3TagClientInitPadding   uint16 = 46
)

func v3KnownTags(tags ...uint16) map[uint16]struct{} {
	known := make(map[uint16]struct{}, len(tags))
	for _, tag := range tags {
		known[tag] = struct{}{}
	}
	return known
}

var (
	clientInitTags = v3KnownTags(
		v3TagVersion, v3TagSuite, v3TagServerID, v3TagDeploymentScope,
		v3TagRouteTag, v3TagRouteEpoch, v3TagPreKeyID, v3TagBundleGeneration,
		v3TagBundleDigest, v3TagInitNonce, v3TagClientNonce, v3TagCoreDigest,
		v3TagClientInitPadding,
	)
	clientHelloCoreHeaderTags = v3KnownTags(
		v3TagPreKeyID, v3TagBundleGeneration, v3TagBundleDigest,
		v3TagClientNonce, v3TagOuterX25519Public, v3TagOuterMLKEMCipher,
	)
	clientHelloCoreTags = v3KnownTags(
		v3TagPreKeyID, v3TagBundleGeneration, v3TagBundleDigest,
		v3TagClientNonce, v3TagOuterX25519Public, v3TagOuterMLKEMCipher,
		v3TagCoreCiphertext,
	)
	clientHelloTags = v3KnownTags(
		v3TagClientInit, v3TagHelloRetry, v3TagClientHelloCore,
		v3TagAdmissionTag,
	)
	serverHelloHeaderTags = v3KnownTags(
		v3TagVersion, v3TagSuite, v3TagPreKeyID, v3TagBundleGeneration,
		v3TagBundleDigest, v3TagServerNonce, v3TagHandshakeID,
		v3TagServerDataX25519, v3TagDataMLKEMCipher,
	)
	serverHelloTags = v3KnownTags(
		v3TagServerHelloHeader, v3TagServerHelloCiphertext, v3TagSignature,
	)
	clientHelloPlaintextTags = v3KnownTags(
		v3TagCommand, v3TagDestination, v3TagClientDataX25519Public,
		v3TagClientDataMLKEMPublic, v3TagNegotiatedParameters, v3TagRandomPadding,
	)
	serverHelloPlaintextTags = v3KnownTags(v3TagNegotiatedParameters, v3TagRandomPadding)
	finishedTags             = v3KnownTags(
		v3TagFinishedVersion, v3TagFinishedSuite,
		v3TagFinishedHandshakeID, v3TagFinishedCiphertext,
	)
)

// V3ClientInit is the first EWP/v3 message. Its CoreDigest commits to the
// complete encrypted ClientHelloCore before the server spends asymmetric work.
type V3ClientInit struct {
	Version            uint16
	Suite              SuiteID
	ServerID           string
	DeploymentScope    string
	RouteTag           RouteTag
	RouteEpoch         uint64
	PreKeyID           PreKeyID
	BundleGeneration   uint64
	BundleDigest       BundleDigest
	InitNonce          V3Nonce
	ClientNonce        V3Nonce
	CoreDigest         [32]byte
	Padding            []byte
	rawBytes           string
	rawCoreDigestStart int
	rawCoreDigestEnd   int
}

func (m V3ClientInit) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ClientInit([]byte(m.rawBytes)); err == nil && sameV3ClientInit(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func (m V3ClientInit) baseWireBytes() []byte {
	if m.rawBytes != "" && m.rawCoreDigestEnd > m.rawCoreDigestStart {
		if parsed, err := ParseV3ClientInit([]byte(m.rawBytes)); err == nil && sameV3ClientInit(parsed, m) {
			result := make([]byte, 0, len(m.rawBytes)-(m.rawCoreDigestEnd-m.rawCoreDigestStart))
			result = append(result, m.rawBytes[:m.rawCoreDigestStart]...)
			result = append(result, m.rawBytes[m.rawCoreDigestEnd:]...)
			return result
		}
	}
	value, _ := m.BaseBytes()
	return value
}

func sameV3ClientInit(a, b V3ClientInit) bool {
	return a.Version == b.Version && a.Suite == b.Suite && a.ServerID == b.ServerID &&
		a.DeploymentScope == b.DeploymentScope && a.RouteTag == b.RouteTag && a.RouteEpoch == b.RouteEpoch &&
		a.PreKeyID == b.PreKeyID && a.BundleGeneration == b.BundleGeneration && a.BundleDigest == b.BundleDigest &&
		a.InitNonce == b.InitNonce && a.ClientNonce == b.ClientNonce && a.CoreDigest == b.CoreDigest &&
		bytes.Equal(a.Padding, b.Padding)
}

func (m V3ClientInit) BaseBytes() ([]byte, error) {
	if m.rawBytes != "" && m.rawCoreDigestEnd > m.rawCoreDigestStart {
		if parsed, err := ParseV3ClientInit([]byte(m.rawBytes)); err == nil && sameV3ClientInit(parsed, m) {
			result := make([]byte, 0, len(m.rawBytes)-(m.rawCoreDigestEnd-m.rawCoreDigestStart))
			result = append(result, m.rawBytes[:m.rawCoreDigestStart]...)
			result = append(result, m.rawBytes[m.rawCoreDigestEnd:]...)
			return result, nil
		}
	}
	return m.baseBytesCanonical()
}

func (m V3ClientInit) baseBytesCanonical() ([]byte, error) {
	if err := validateV3VersionSuite(m.Version, m.Suite); err != nil {
		return nil, err
	}
	if len(m.ServerID) == 0 || len(m.ServerID) > V3MaxServerIDLen || len(m.DeploymentScope) > V3MaxScopeLen {
		return nil, ErrV3Malformed
	}
	if m.PreKeyID.isZero() || m.BundleDigest.isZero() || m.BundleGeneration == 0 ||
		v3AllZero(m.InitNonce[:]) || v3AllZero(m.ClientNonce[:]) {
		return nil, ErrV3Malformed
	}
	if len(m.Padding) > MaxV3MessageSize {
		return nil, ErrV3FieldTooLarge
	}
	fields := []v3Field{
		v3U16(v3TagVersion, m.Version),
		v3U16(v3TagSuite, uint16(m.Suite)),
		v3Bytes(v3TagServerID, []byte(m.ServerID)),
		v3Bytes(v3TagDeploymentScope, []byte(m.DeploymentScope)),
		v3Bytes(v3TagRouteTag, m.RouteTag[:]),
		v3U64(v3TagRouteEpoch, m.RouteEpoch),
		v3Bytes(v3TagPreKeyID, m.PreKeyID[:]),
		v3U64(v3TagBundleGeneration, m.BundleGeneration),
		v3Bytes(v3TagBundleDigest, m.BundleDigest[:]),
		v3Bytes(v3TagInitNonce, m.InitNonce[:]),
		v3Bytes(v3TagClientNonce, m.ClientNonce[:]),
	}
	if len(m.Padding) != 0 {
		fields = append(fields, v3Bytes(v3TagClientInitPadding, m.Padding))
	}
	return encodeV3Fields(fields...)
}

func (m V3ClientInit) MarshalBinary() ([]byte, error) {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ClientInit([]byte(m.rawBytes)); err == nil && sameV3ClientInit(parsed, m) {
			return []byte(m.rawBytes), nil
		}
	}
	if _, err := m.baseBytesCanonical(); err != nil {
		return nil, err
	}
	fields := []v3Field{
		v3U16(v3TagVersion, m.Version),
		v3U16(v3TagSuite, uint16(m.Suite)),
		v3Bytes(v3TagServerID, []byte(m.ServerID)),
		v3Bytes(v3TagDeploymentScope, []byte(m.DeploymentScope)),
		v3Bytes(v3TagRouteTag, m.RouteTag[:]),
		v3U64(v3TagRouteEpoch, m.RouteEpoch),
		v3Bytes(v3TagPreKeyID, m.PreKeyID[:]),
		v3U64(v3TagBundleGeneration, m.BundleGeneration),
		v3Bytes(v3TagBundleDigest, m.BundleDigest[:]),
		v3Bytes(v3TagInitNonce, m.InitNonce[:]),
		v3Bytes(v3TagClientNonce, m.ClientNonce[:]),
		v3Bytes(v3TagCoreDigest, m.CoreDigest[:]),
	}
	if len(m.Padding) != 0 {
		fields = append(fields, v3Bytes(v3TagClientInitPadding, m.Padding))
	}
	return encodeV3Fields(fields...)
}

func ParseV3ClientInit(data []byte) (V3ClientInit, error) {
	fields, err := decodeV3Fields(data, clientInitTags)
	if err != nil {
		return V3ClientInit{}, err
	}
	version, err := v3ReadU16(&fields, v3TagVersion)
	if err != nil {
		return V3ClientInit{}, err
	}
	suite, err := v3ReadU16(&fields, v3TagSuite)
	if err != nil {
		return V3ClientInit{}, err
	}
	if err := validateV3VersionSuite(version, SuiteID(suite)); err != nil {
		return V3ClientInit{}, err
	}
	serverID, err := v3Required(&fields, v3TagServerID)
	if err != nil || len(serverID) == 0 || len(serverID) > V3MaxServerIDLen {
		return V3ClientInit{}, ErrV3Malformed
	}
	scope, err := v3Required(&fields, v3TagDeploymentScope)
	if err != nil || len(scope) > V3MaxScopeLen {
		return V3ClientInit{}, ErrV3Malformed
	}
	var result V3ClientInit
	result.Version = version
	result.Suite = SuiteID(suite)
	result.ServerID = string(serverID)
	result.DeploymentScope = string(scope)
	routeTag, err := v3Exact(&fields, v3TagRouteTag, V3RouteTagLen)
	if err != nil {
		return V3ClientInit{}, err
	}
	copy(result.RouteTag[:], routeTag)
	if result.RouteEpoch, err = v3ReadU64(&fields, v3TagRouteEpoch); err != nil {
		return V3ClientInit{}, err
	}
	preKeyID, err := v3Exact(&fields, v3TagPreKeyID, V3PreKeyIDLen)
	if err != nil {
		return V3ClientInit{}, err
	}
	copy(result.PreKeyID[:], preKeyID)
	if result.BundleGeneration, err = v3ReadU64(&fields, v3TagBundleGeneration); err != nil {
		return V3ClientInit{}, err
	}
	bundleDigest, err := v3Exact(&fields, v3TagBundleDigest, V3BundleDigestLen)
	if err != nil {
		return V3ClientInit{}, err
	}
	copy(result.BundleDigest[:], bundleDigest)
	initNonce, err := v3Exact(&fields, v3TagInitNonce, V3NonceLen)
	if err != nil {
		return V3ClientInit{}, err
	}
	copy(result.InitNonce[:], initNonce)
	clientNonce, err := v3Exact(&fields, v3TagClientNonce, V3NonceLen)
	if err != nil {
		return V3ClientInit{}, err
	}
	copy(result.ClientNonce[:], clientNonce)
	coreDigest, err := v3Exact(&fields, v3TagCoreDigest, 32)
	if err != nil {
		return V3ClientInit{}, err
	}
	copy(result.CoreDigest[:], coreDigest)
	if padding, ok := fields.get(v3TagClientInitPadding); ok {
		result.Padding = append([]byte(nil), padding...)
	}
	if result.PreKeyID.isZero() || result.BundleDigest.isZero() || result.BundleGeneration == 0 ||
		v3AllZero(result.InitNonce[:]) || v3AllZero(result.ClientNonce[:]) {
		return V3ClientInit{}, ErrV3Malformed
	}
	baseStart, baseEnd, err := v3FieldRegion(data, v3TagCoreDigest)
	if err != nil {
		return V3ClientInit{}, err
	}
	result.rawBytes = string(data)
	result.rawCoreDigestStart = baseStart
	result.rawCoreDigestEnd = baseEnd
	return result, nil
}

// V3HelloRetry is stateless and can be regenerated by any service instance
// that has the current cookie key.
type V3HelloRetry struct {
	Version     uint16
	Suite       SuiteID
	InitNonce   V3Nonce
	RetryNonce  V3Nonce
	CookieKeyID uint8
	ExpiresAt   uint64
	Cookie      [V3CookieLen]byte
	rawBytes    string
}

func (m V3HelloRetry) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := ParseV3HelloRetry([]byte(m.rawBytes)); err == nil && sameV3HelloRetry(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func sameV3HelloRetry(a, b V3HelloRetry) bool {
	return a.Version == b.Version && a.Suite == b.Suite && a.InitNonce == b.InitNonce &&
		a.RetryNonce == b.RetryNonce && a.CookieKeyID == b.CookieKeyID && a.ExpiresAt == b.ExpiresAt &&
		a.Cookie == b.Cookie
}

func (m V3HelloRetry) MarshalBinary() ([]byte, error) {
	if m.rawBytes != "" {
		if parsed, err := ParseV3HelloRetry([]byte(m.rawBytes)); err == nil && sameV3HelloRetry(parsed, m) {
			return []byte(m.rawBytes), nil
		}
	}
	if err := validateV3VersionSuite(m.Version, m.Suite); err != nil {
		return nil, err
	}
	if v3AllZero(m.InitNonce[:]) || v3AllZero(m.RetryNonce[:]) || m.ExpiresAt == 0 || v3AllZero(m.Cookie[:]) {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3U16(v3TagVersion, m.Version),
		v3U16(v3TagSuite, uint16(m.Suite)),
		v3Bytes(v3TagInitNonce, m.InitNonce[:]),
		v3Bytes(v3TagRetryNonce, m.RetryNonce[:]),
		v3U8(v3TagCookieKeyID, m.CookieKeyID),
		v3U64(v3TagExpiresAt, m.ExpiresAt),
		v3Bytes(v3TagCookie, m.Cookie[:]),
	)
}

func ParseV3HelloRetry(data []byte) (V3HelloRetry, error) {
	return parseV3HelloRetryFast(data)
}

func parseV3HelloRetryFast(data []byte) (V3HelloRetry, error) {
	if len(data) > MaxV3MessageSize {
		return V3HelloRetry{}, ErrV3MessageTooLarge
	}
	original := data
	var values [7][]byte
	var present [7]bool
	var previous uint16
	count := 0
	for len(data) > 0 {
		if len(data) < v3FieldHeaderLen {
			return V3HelloRetry{}, ErrV3Malformed
		}
		count++
		if count > MaxV3FieldCount {
			return V3HelloRetry{}, ErrV3Malformed
		}
		tag := binary.BigEndian.Uint16(data[:2])
		length := binary.BigEndian.Uint32(data[2:6])
		if tag == 0 || (count > 1 && tag <= previous) {
			return V3HelloRetry{}, ErrV3NonCanonical
		}
		data = data[v3FieldHeaderLen:]
		if uint64(length) > uint64(len(data)) {
			return V3HelloRetry{}, ErrV3Malformed
		}
		value := data[:int(length)]
		switch tag {
		case v3TagVersion:
			values[0], present[0] = value, true
		case v3TagSuite:
			values[1], present[1] = value, true
		case v3TagInitNonce:
			values[2], present[2] = value, true
		case v3TagRetryNonce:
			values[3], present[3] = value, true
		case v3TagCookieKeyID:
			values[4], present[4] = value, true
		case v3TagExpiresAt:
			values[5], present[5] = value, true
		case v3TagCookie:
			values[6], present[6] = value, true
		default:
			if tag&v3CriticalTag != 0 {
				return V3HelloRetry{}, fmt.Errorf("%w: 0x%04x", ErrV3UnknownField, tag)
			}
		}
		data = data[int(length):]
		previous = tag
	}

	var result V3HelloRetry
	version, err := v3HelloRetryExact(values[0], present[0], v3TagVersion, 2)
	if err != nil {
		return result, err
	}
	result.Version = binary.BigEndian.Uint16(version)
	suite, err := v3HelloRetryExact(values[1], present[1], v3TagSuite, 2)
	if err != nil {
		return result, err
	}
	result.Suite = SuiteID(binary.BigEndian.Uint16(suite))
	if err := validateV3VersionSuite(result.Version, result.Suite); err != nil {
		return result, err
	}
	initNonce, err := v3HelloRetryExact(values[2], present[2], v3TagInitNonce, V3NonceLen)
	if err != nil {
		return result, err
	}
	copy(result.InitNonce[:], initNonce)
	retryNonce, err := v3HelloRetryExact(values[3], present[3], v3TagRetryNonce, V3NonceLen)
	if err != nil {
		return result, err
	}
	copy(result.RetryNonce[:], retryNonce)
	cookieKeyID, err := v3HelloRetryExact(values[4], present[4], v3TagCookieKeyID, 1)
	if err != nil {
		return result, err
	}
	result.CookieKeyID = cookieKeyID[0]
	expiresAt, err := v3HelloRetryExact(values[5], present[5], v3TagExpiresAt, 8)
	if err != nil {
		return result, err
	}
	result.ExpiresAt = binary.BigEndian.Uint64(expiresAt)
	cookie, err := v3HelloRetryExact(values[6], present[6], v3TagCookie, V3CookieLen)
	if err != nil {
		return result, err
	}
	copy(result.Cookie[:], cookie)
	if v3AllZero(result.InitNonce[:]) || v3AllZero(result.RetryNonce[:]) || result.ExpiresAt == 0 || v3AllZero(result.Cookie[:]) {
		return V3HelloRetry{}, ErrV3Malformed
	}
	result.rawBytes = string(original)
	return result, nil
}

func v3HelloRetryExact(value []byte, present bool, tag uint16, length int) ([]byte, error) {
	if !present {
		return nil, fmt.Errorf("%w: missing field 0x%04x", ErrV3Malformed, tag)
	}
	if len(value) != length {
		return nil, fmt.Errorf("%w: field 0x%04x length %d, want %d", ErrV3Malformed, tag, len(value), length)
	}
	return value, nil
}

type V3ClientHelloCoreHeader struct {
	PreKeyID             PreKeyID
	BundleGeneration     uint64
	BundleDigest         BundleDigest
	ClientNonce          V3Nonce
	OuterX25519Public    [X25519PubLen]byte
	OuterMLKEMCiphertext []byte
	rawBytes             string
}

func (m V3ClientHelloCoreHeader) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := parseV3ClientHelloCoreHeaderWire([]byte(m.rawBytes)); err == nil && sameV3ClientHelloCoreHeader(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func parseV3ClientHelloCoreHeaderWire(data []byte) (V3ClientHelloCoreHeader, error) {
	fields, err := decodeV3Fields(data, clientHelloCoreHeaderTags)
	if err != nil {
		return V3ClientHelloCoreHeader{}, err
	}
	return parseV3ClientHelloCoreHeader(&fields)
}

func sameV3ClientHelloCoreHeader(a, b V3ClientHelloCoreHeader) bool {
	return a.PreKeyID == b.PreKeyID && a.BundleGeneration == b.BundleGeneration && a.BundleDigest == b.BundleDigest &&
		a.ClientNonce == b.ClientNonce && a.OuterX25519Public == b.OuterX25519Public &&
		bytes.Equal(a.OuterMLKEMCiphertext, b.OuterMLKEMCiphertext)
}

func (m V3ClientHelloCoreHeader) MarshalBinary() ([]byte, error) {
	if m.rawBytes != "" {
		if parsed, err := parseV3ClientHelloCoreHeaderWire([]byte(m.rawBytes)); err == nil && sameV3ClientHelloCoreHeader(parsed, m) {
			return []byte(m.rawBytes), nil
		}
	}
	if m.PreKeyID.isZero() || m.BundleDigest.isZero() || m.BundleGeneration == 0 ||
		v3AllZero(m.ClientNonce[:]) || v3AllZero(m.OuterX25519Public[:]) {
		return nil, ErrV3Malformed
	}
	if len(m.OuterMLKEMCiphertext) != MLKEM768CipherL {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3Bytes(v3TagPreKeyID, m.PreKeyID[:]),
		v3U64(v3TagBundleGeneration, m.BundleGeneration),
		v3Bytes(v3TagBundleDigest, m.BundleDigest[:]),
		v3Bytes(v3TagClientNonce, m.ClientNonce[:]),
		v3Bytes(v3TagOuterX25519Public, m.OuterX25519Public[:]),
		v3Bytes(v3TagOuterMLKEMCipher, m.OuterMLKEMCiphertext),
	)
}

func parseV3ClientHelloCoreHeader(fields *v3FieldSet) (V3ClientHelloCoreHeader, error) {
	var result V3ClientHelloCoreHeader
	preKeyID, err := v3Exact(fields, v3TagPreKeyID, V3PreKeyIDLen)
	if err != nil {
		return result, err
	}
	copy(result.PreKeyID[:], preKeyID)
	if result.BundleGeneration, err = v3ReadU64(fields, v3TagBundleGeneration); err != nil {
		return result, err
	}
	bundleDigest, err := v3Exact(fields, v3TagBundleDigest, V3BundleDigestLen)
	if err != nil {
		return result, err
	}
	copy(result.BundleDigest[:], bundleDigest)
	clientNonce, err := v3Exact(fields, v3TagClientNonce, V3NonceLen)
	if err != nil {
		return result, err
	}
	copy(result.ClientNonce[:], clientNonce)
	outerPublic, err := v3Exact(fields, v3TagOuterX25519Public, X25519PubLen)
	if err != nil {
		return result, err
	}
	copy(result.OuterX25519Public[:], outerPublic)
	outerCipher, err := v3Exact(fields, v3TagOuterMLKEMCipher, MLKEM768CipherL)
	if err != nil {
		return result, err
	}
	result.OuterMLKEMCiphertext = append([]byte(nil), outerCipher...)
	if result.BundleGeneration == 0 || result.PreKeyID.isZero() || result.BundleDigest.isZero() ||
		v3AllZero(result.ClientNonce[:]) || v3AllZero(result.OuterX25519Public[:]) {
		return result, ErrV3Malformed
	}
	return result, nil
}

type V3ClientHelloCore struct {
	Header     V3ClientHelloCoreHeader
	Ciphertext []byte
	rawBytes   string
}

func (m V3ClientHelloCore) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ClientHelloCore([]byte(m.rawBytes)); err == nil && sameV3ClientHelloCore(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func sameV3ClientHelloCore(a, b V3ClientHelloCore) bool {
	return sameV3ClientHelloCoreHeader(a.Header, b.Header) && bytes.Equal(a.Ciphertext, b.Ciphertext)
}

func (m V3ClientHelloCore) MarshalBinary() ([]byte, error) {
	if _, err := m.Header.MarshalBinary(); err != nil {
		return nil, err
	}
	if len(m.Ciphertext) < 16 || len(m.Ciphertext) > MaxV3MessageSize {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3Bytes(v3TagPreKeyID, m.Header.PreKeyID[:]),
		v3U64(v3TagBundleGeneration, m.Header.BundleGeneration),
		v3Bytes(v3TagBundleDigest, m.Header.BundleDigest[:]),
		v3Bytes(v3TagClientNonce, m.Header.ClientNonce[:]),
		v3Bytes(v3TagOuterX25519Public, m.Header.OuterX25519Public[:]),
		v3Bytes(v3TagOuterMLKEMCipher, m.Header.OuterMLKEMCiphertext),
		v3Bytes(v3TagCoreCiphertext, m.Ciphertext),
	)
}

func ParseV3ClientHelloCore(data []byte) (V3ClientHelloCore, error) {
	fields, err := decodeV3Fields(data, clientHelloCoreTags)
	if err != nil {
		return V3ClientHelloCore{}, err
	}
	header, err := parseV3ClientHelloCoreHeader(&fields)
	if err != nil {
		return V3ClientHelloCore{}, err
	}
	ciphertext, err := v3Required(&fields, v3TagCoreCiphertext)
	if err != nil || len(ciphertext) < 16 {
		return V3ClientHelloCore{}, ErrV3Malformed
	}
	rawHeader, err := v3WithoutField(data, v3TagCoreCiphertext)
	if err != nil {
		return V3ClientHelloCore{}, err
	}
	header.rawBytes = string(rawHeader)
	return V3ClientHelloCore{Header: header, Ciphertext: append([]byte(nil), ciphertext...), rawBytes: string(data)}, nil
}

type V3ClientHello struct {
	Init         V3ClientInit
	Retry        V3HelloRetry
	Core         V3ClientHelloCore
	AdmissionTag [32]byte
	rawBytes     string
}

func (m V3ClientHello) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ClientHello([]byte(m.rawBytes)); err == nil && sameV3ClientHello(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func sameV3ClientHello(a, b V3ClientHello) bool {
	return bytes.Equal(a.Init.wireBytes(), b.Init.wireBytes()) && bytes.Equal(a.Retry.wireBytes(), b.Retry.wireBytes()) &&
		bytes.Equal(a.Core.wireBytes(), b.Core.wireBytes()) && a.AdmissionTag == b.AdmissionTag
}

func (m V3ClientHello) MarshalBinary() ([]byte, error) {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ClientHello([]byte(m.rawBytes)); err == nil && sameV3ClientHello(parsed, m) {
			return []byte(m.rawBytes), nil
		}
	}
	initBytes := m.Init.wireBytes()
	if len(initBytes) == 0 {
		return nil, ErrV3Malformed
	}
	retryBytes := m.Retry.wireBytes()
	if len(retryBytes) == 0 {
		return nil, ErrV3Malformed
	}
	coreBytes := m.Core.wireBytes()
	if len(coreBytes) == 0 {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3Bytes(v3TagClientInit, initBytes),
		v3Bytes(v3TagHelloRetry, retryBytes),
		v3Bytes(v3TagClientHelloCore, coreBytes),
		v3Bytes(v3TagAdmissionTag, m.AdmissionTag[:]),
	)
}

func ParseV3ClientHello(data []byte) (V3ClientHello, error) {
	fields, err := decodeV3Fields(data, clientHelloTags)
	if err != nil {
		return V3ClientHello{}, err
	}
	initBytes, err := v3Required(&fields, v3TagClientInit)
	if err != nil {
		return V3ClientHello{}, err
	}
	init, err := ParseV3ClientInit(initBytes)
	if err != nil {
		return V3ClientHello{}, err
	}
	retryBytes, err := v3Required(&fields, v3TagHelloRetry)
	if err != nil {
		return V3ClientHello{}, err
	}
	retry, err := ParseV3HelloRetry(retryBytes)
	if err != nil {
		return V3ClientHello{}, err
	}
	coreBytes, err := v3Required(&fields, v3TagClientHelloCore)
	if err != nil {
		return V3ClientHello{}, err
	}
	core, err := ParseV3ClientHelloCore(coreBytes)
	if err != nil {
		return V3ClientHello{}, err
	}
	tag, err := v3Exact(&fields, v3TagAdmissionTag, 32)
	if err != nil {
		return V3ClientHello{}, err
	}
	var result V3ClientHello
	result.Init, result.Retry, result.Core = init, retry, core
	copy(result.AdmissionTag[:], tag)
	result.rawBytes = string(data)
	return result, nil
}

func (m V3ClientHello) CoreDigest() ([32]byte, error) {
	core := m.Core.wireBytes()
	if core == nil {
		return [32]byte{}, ErrV3Malformed
	}
	return sha256.Sum256(core), nil
}

type V3ClientHelloPlaintext struct {
	Command                Command
	Destination            Address
	ClientDataX25519Public [X25519PubLen]byte
	ClientDataMLKEMPublic  []byte
	NegotiatedParameters   []byte
	RandomPadding          []byte
}

func (m V3ClientHelloPlaintext) MarshalBinary() ([]byte, error) {
	if m.Command != CommandTCP && m.Command != CommandUDP {
		return nil, ErrCommand
	}
	destination, err := m.Destination.Append(nil)
	if err != nil {
		return nil, err
	}
	if v3AllZero(m.ClientDataX25519Public[:]) || len(m.ClientDataMLKEMPublic) != MLKEM768PubLen || len(m.NegotiatedParameters) > V3MaxParameterLen {
		return nil, ErrV3Malformed
	}
	if len(m.RandomPadding) > MaxV3MessageSize {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3U8(v3TagCommand, byte(m.Command)),
		v3Bytes(v3TagDestination, destination),
		v3Bytes(v3TagClientDataX25519Public, m.ClientDataX25519Public[:]),
		v3Bytes(v3TagClientDataMLKEMPublic, m.ClientDataMLKEMPublic),
		v3Bytes(v3TagNegotiatedParameters, m.NegotiatedParameters),
		v3Bytes(v3TagRandomPadding, m.RandomPadding),
	)
}

func ParseV3ClientHelloPlaintext(data []byte) (V3ClientHelloPlaintext, error) {
	fields, err := decodeV3Fields(data, clientHelloPlaintextTags)
	if err != nil {
		return V3ClientHelloPlaintext{}, err
	}
	command, err := v3ReadU8(&fields, v3TagCommand)
	if err != nil || (Command(command) != CommandTCP && Command(command) != CommandUDP) {
		return V3ClientHelloPlaintext{}, ErrCommand
	}
	destinationBytes, err := v3Required(&fields, v3TagDestination)
	if err != nil {
		return V3ClientHelloPlaintext{}, err
	}
	destination, consumed, err := DecodeAddress(destinationBytes)
	if err != nil || consumed != len(destinationBytes) {
		return V3ClientHelloPlaintext{}, fmt.Errorf("%w: destination", ErrV3Malformed)
	}
	dataPublic, err := v3Exact(&fields, v3TagClientDataX25519Public, X25519PubLen)
	if err != nil {
		return V3ClientHelloPlaintext{}, err
	}
	pqPublic, err := v3Exact(&fields, v3TagClientDataMLKEMPublic, MLKEM768PubLen)
	if err != nil {
		return V3ClientHelloPlaintext{}, err
	}
	params, err := v3Required(&fields, v3TagNegotiatedParameters)
	if err != nil || len(params) > V3MaxParameterLen {
		return V3ClientHelloPlaintext{}, ErrV3Malformed
	}
	padding, err := v3Required(&fields, v3TagRandomPadding)
	if err != nil {
		return V3ClientHelloPlaintext{}, err
	}
	var result V3ClientHelloPlaintext
	result.Command = Command(command)
	result.Destination = destination
	copy(result.ClientDataX25519Public[:], dataPublic)
	if v3AllZero(result.ClientDataX25519Public[:]) {
		return V3ClientHelloPlaintext{}, ErrV3Malformed
	}
	result.ClientDataMLKEMPublic = append([]byte(nil), pqPublic...)
	result.NegotiatedParameters = append([]byte(nil), params...)
	result.RandomPadding = append([]byte(nil), padding...)
	return result, nil
}

type V3ServerHelloHeader struct {
	Version                uint16
	Suite                  SuiteID
	PreKeyID               PreKeyID
	BundleGeneration       uint64
	BundleDigest           BundleDigest
	ServerNonce            V3Nonce
	HandshakeID            HandshakeID
	ServerDataX25519Public [X25519PubLen]byte
	DataMLKEMCiphertext    []byte
	rawBytes               string
}

func (m V3ServerHelloHeader) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ServerHelloHeader([]byte(m.rawBytes)); err == nil && sameV3ServerHelloHeader(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func sameV3ServerHelloHeader(a, b V3ServerHelloHeader) bool {
	return a.Version == b.Version && a.Suite == b.Suite && a.PreKeyID == b.PreKeyID &&
		a.BundleGeneration == b.BundleGeneration && a.BundleDigest == b.BundleDigest && a.ServerNonce == b.ServerNonce &&
		a.HandshakeID == b.HandshakeID && a.ServerDataX25519Public == b.ServerDataX25519Public &&
		bytes.Equal(a.DataMLKEMCiphertext, b.DataMLKEMCiphertext)
}

func (m V3ServerHelloHeader) MarshalBinary() ([]byte, error) {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ServerHelloHeader([]byte(m.rawBytes)); err == nil && sameV3ServerHelloHeader(parsed, m) {
			return []byte(m.rawBytes), nil
		}
	}
	if err := validateV3VersionSuite(m.Version, m.Suite); err != nil {
		return nil, err
	}
	if m.PreKeyID.isZero() || m.BundleDigest.isZero() || m.BundleGeneration == 0 ||
		v3AllZero(m.ServerNonce[:]) || v3AllZero(m.HandshakeID[:]) || v3AllZero(m.ServerDataX25519Public[:]) {
		return nil, ErrV3Malformed
	}
	if len(m.DataMLKEMCiphertext) != MLKEM768CipherL {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3U16(v3TagVersion, m.Version),
		v3U16(v3TagSuite, uint16(m.Suite)),
		v3Bytes(v3TagPreKeyID, m.PreKeyID[:]),
		v3U64(v3TagBundleGeneration, m.BundleGeneration),
		v3Bytes(v3TagBundleDigest, m.BundleDigest[:]),
		v3Bytes(v3TagServerNonce, m.ServerNonce[:]),
		v3Bytes(v3TagHandshakeID, m.HandshakeID[:]),
		v3Bytes(v3TagServerDataX25519, m.ServerDataX25519Public[:]),
		v3Bytes(v3TagDataMLKEMCipher, m.DataMLKEMCiphertext),
	)
}

func ParseV3ServerHelloHeader(data []byte) (V3ServerHelloHeader, error) {
	fields, err := decodeV3Fields(data, serverHelloHeaderTags)
	if err != nil {
		return V3ServerHelloHeader{}, err
	}
	var result V3ServerHelloHeader
	if result.Version, err = v3ReadU16(&fields, v3TagVersion); err != nil {
		return result, err
	}
	suite, err := v3ReadU16(&fields, v3TagSuite)
	if err != nil {
		return result, err
	}
	result.Suite = SuiteID(suite)
	if err := validateV3VersionSuite(result.Version, result.Suite); err != nil {
		return result, err
	}
	preKeyID, err := v3Exact(&fields, v3TagPreKeyID, V3PreKeyIDLen)
	if err != nil {
		return result, err
	}
	copy(result.PreKeyID[:], preKeyID)
	if result.BundleGeneration, err = v3ReadU64(&fields, v3TagBundleGeneration); err != nil {
		return result, err
	}
	digest, err := v3Exact(&fields, v3TagBundleDigest, V3BundleDigestLen)
	if err != nil {
		return result, err
	}
	copy(result.BundleDigest[:], digest)
	nonce, err := v3Exact(&fields, v3TagServerNonce, V3NonceLen)
	if err != nil {
		return result, err
	}
	copy(result.ServerNonce[:], nonce)
	handshakeID, err := v3Exact(&fields, v3TagHandshakeID, V3HandshakeIDLen)
	if err != nil {
		return result, err
	}
	copy(result.HandshakeID[:], handshakeID)
	dataPublic, err := v3Exact(&fields, v3TagServerDataX25519, X25519PubLen)
	if err != nil {
		return result, err
	}
	copy(result.ServerDataX25519Public[:], dataPublic)
	dataCipher, err := v3Exact(&fields, v3TagDataMLKEMCipher, MLKEM768CipherL)
	if err != nil {
		return result, err
	}
	result.DataMLKEMCiphertext = append([]byte(nil), dataCipher...)
	if result.PreKeyID.isZero() || result.BundleDigest.isZero() || result.BundleGeneration == 0 ||
		v3AllZero(result.ServerNonce[:]) || v3AllZero(result.HandshakeID[:]) || v3AllZero(result.ServerDataX25519Public[:]) {
		return result, ErrV3Malformed
	}
	result.rawBytes = string(data)
	return result, nil
}

type V3ServerHello struct {
	Header     V3ServerHelloHeader
	Ciphertext []byte
	Signature  [V3SignatureLen]byte
	rawBytes   string
}

func (m V3ServerHello) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ServerHello([]byte(m.rawBytes)); err == nil && sameV3ServerHello(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func sameV3ServerHello(a, b V3ServerHello) bool {
	return bytes.Equal(a.Header.wireBytes(), b.Header.wireBytes()) && bytes.Equal(a.Ciphertext, b.Ciphertext) && a.Signature == b.Signature
}

func (m V3ServerHello) MarshalBinary() ([]byte, error) {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ServerHello([]byte(m.rawBytes)); err == nil && sameV3ServerHello(parsed, m) {
			return []byte(m.rawBytes), nil
		}
	}
	header := m.Header.wireBytes()
	if len(header) == 0 {
		return nil, ErrV3Malformed
	}
	if len(m.Ciphertext) < 16 || len(m.Ciphertext) > MaxV3MessageSize {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3Bytes(v3TagServerHelloHeader, header),
		v3Bytes(v3TagServerHelloCiphertext, m.Ciphertext),
		v3Bytes(v3TagSignature, m.Signature[:]),
	)
}

func ParseV3ServerHello(data []byte) (V3ServerHello, error) {
	fields, err := decodeV3Fields(data, serverHelloTags)
	if err != nil {
		return V3ServerHello{}, err
	}
	headerBytes, err := v3Required(&fields, v3TagServerHelloHeader)
	if err != nil {
		return V3ServerHello{}, err
	}
	header, err := ParseV3ServerHelloHeader(headerBytes)
	if err != nil {
		return V3ServerHello{}, err
	}
	ciphertext, err := v3Required(&fields, v3TagServerHelloCiphertext)
	if err != nil || len(ciphertext) < 16 {
		return V3ServerHello{}, ErrV3Malformed
	}
	signature, err := v3Exact(&fields, v3TagSignature, V3SignatureLen)
	if err != nil {
		return V3ServerHello{}, err
	}
	var result V3ServerHello
	result.Header, result.Ciphertext = header, append([]byte(nil), ciphertext...)
	copy(result.Signature[:], signature)
	result.rawBytes = string(data)
	return result, nil
}

type V3ServerHelloPlaintext struct {
	NegotiatedParameters []byte
	RandomPadding        []byte
}

func (m V3ServerHelloPlaintext) MarshalBinary() ([]byte, error) {
	if len(m.NegotiatedParameters) > V3MaxParameterLen || len(m.RandomPadding) > MaxV3MessageSize {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3Bytes(v3TagNegotiatedParameters, m.NegotiatedParameters),
		v3Bytes(v3TagRandomPadding, m.RandomPadding),
	)
}

func ParseV3ServerHelloPlaintext(data []byte) (V3ServerHelloPlaintext, error) {
	fields, err := decodeV3Fields(data, serverHelloPlaintextTags)
	if err != nil {
		return V3ServerHelloPlaintext{}, err
	}
	params, err := v3Required(&fields, v3TagNegotiatedParameters)
	if err != nil || len(params) > V3MaxParameterLen {
		return V3ServerHelloPlaintext{}, ErrV3Malformed
	}
	padding, err := v3Required(&fields, v3TagRandomPadding)
	if err != nil {
		return V3ServerHelloPlaintext{}, err
	}
	return V3ServerHelloPlaintext{
		NegotiatedParameters: append([]byte(nil), params...),
		RandomPadding:        append([]byte(nil), padding...),
	}, nil
}

type V3ClientFinished struct {
	Version     uint16
	Suite       SuiteID
	HandshakeID HandshakeID
	Ciphertext  []byte
	rawBytes    string
}

func (m V3ClientFinished) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ClientFinished([]byte(m.rawBytes)); err == nil && sameV3ClientFinished(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func sameV3ClientFinished(a, b V3ClientFinished) bool {
	return a.Version == b.Version && a.Suite == b.Suite && a.HandshakeID == b.HandshakeID && bytes.Equal(a.Ciphertext, b.Ciphertext)
}

func (m V3ClientFinished) MarshalBinary() ([]byte, error) {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ClientFinished([]byte(m.rawBytes)); err == nil && sameV3ClientFinished(parsed, m) {
			return []byte(m.rawBytes), nil
		}
	}
	if err := validateV3VersionSuite(m.Version, m.Suite); err != nil {
		return nil, err
	}
	if v3AllZero(m.HandshakeID[:]) || len(m.Ciphertext) < 16 || len(m.Ciphertext) > MaxV3MessageSize {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3U16(v3TagFinishedVersion, m.Version),
		v3U16(v3TagFinishedSuite, uint16(m.Suite)),
		v3Bytes(v3TagFinishedHandshakeID, m.HandshakeID[:]),
		v3Bytes(v3TagFinishedCiphertext, m.Ciphertext),
	)
}

func ParseV3ClientFinished(data []byte) (V3ClientFinished, error) {
	fields, err := decodeV3Fields(data, finishedTags)
	if err != nil {
		return V3ClientFinished{}, err
	}
	var result V3ClientFinished
	if result.Version, err = v3ReadU16(&fields, v3TagFinishedVersion); err != nil {
		return result, err
	}
	suite, err := v3ReadU16(&fields, v3TagFinishedSuite)
	if err != nil {
		return result, err
	}
	result.Suite = SuiteID(suite)
	if err := validateV3VersionSuite(result.Version, result.Suite); err != nil {
		return result, err
	}
	id, err := v3Exact(&fields, v3TagFinishedHandshakeID, V3HandshakeIDLen)
	if err != nil {
		return result, err
	}
	copy(result.HandshakeID[:], id)
	ciphertext, err := v3Required(&fields, v3TagFinishedCiphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > MaxV3MessageSize || v3AllZero(result.HandshakeID[:]) {
		return V3ClientFinished{}, ErrV3Malformed
	}
	result.Ciphertext = append([]byte(nil), ciphertext...)
	result.rawBytes = string(data)
	return result, nil
}

type V3ServerFinished struct {
	Version     uint16
	Suite       SuiteID
	HandshakeID HandshakeID
	Ciphertext  []byte
	rawBytes    string
}

func (m V3ServerFinished) wireBytes() []byte {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ServerFinished([]byte(m.rawBytes)); err == nil && sameV3ServerFinished(parsed, m) {
			return []byte(m.rawBytes)
		}
	}
	value, _ := m.MarshalBinary()
	return value
}

func sameV3ServerFinished(a, b V3ServerFinished) bool {
	return a.Version == b.Version && a.Suite == b.Suite && a.HandshakeID == b.HandshakeID && bytes.Equal(a.Ciphertext, b.Ciphertext)
}

func (m V3ServerFinished) MarshalBinary() ([]byte, error) {
	if m.rawBytes != "" {
		if parsed, err := ParseV3ServerFinished([]byte(m.rawBytes)); err == nil && sameV3ServerFinished(parsed, m) {
			return []byte(m.rawBytes), nil
		}
	}
	if err := validateV3VersionSuite(m.Version, m.Suite); err != nil {
		return nil, err
	}
	if v3AllZero(m.HandshakeID[:]) || len(m.Ciphertext) < 16 || len(m.Ciphertext) > MaxV3MessageSize {
		return nil, ErrV3Malformed
	}
	return encodeV3Fields(
		v3U16(v3TagFinishedVersion, m.Version),
		v3U16(v3TagFinishedSuite, uint16(m.Suite)),
		v3Bytes(v3TagFinishedHandshakeID, m.HandshakeID[:]),
		v3Bytes(v3TagFinishedCiphertext, m.Ciphertext),
	)
}

func ParseV3ServerFinished(data []byte) (V3ServerFinished, error) {
	fields, err := decodeV3Fields(data, finishedTags)
	if err != nil {
		return V3ServerFinished{}, err
	}
	var result V3ServerFinished
	if result.Version, err = v3ReadU16(&fields, v3TagFinishedVersion); err != nil {
		return result, err
	}
	suite, err := v3ReadU16(&fields, v3TagFinishedSuite)
	if err != nil {
		return result, err
	}
	result.Suite = SuiteID(suite)
	if err := validateV3VersionSuite(result.Version, result.Suite); err != nil {
		return result, err
	}
	id, err := v3Exact(&fields, v3TagFinishedHandshakeID, V3HandshakeIDLen)
	if err != nil {
		return result, err
	}
	copy(result.HandshakeID[:], id)
	ciphertext, err := v3Required(&fields, v3TagFinishedCiphertext)
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > MaxV3MessageSize || v3AllZero(result.HandshakeID[:]) {
		return V3ServerFinished{}, ErrV3Malformed
	}
	result.Ciphertext = append([]byte(nil), ciphertext...)
	result.rawBytes = string(data)
	return result, nil
}
