package ewp

import "errors"

// protocolVersion selects a cryptographic and record-format suite. It is kept
// inside SessionKeys so a v2.2 handshake cannot accidentally instantiate the
// legacy clear-header frame codec.
type protocolVersion uint8

const (
	protocolVersionLegacy protocolVersion = iota
	protocolVersionV21
	protocolVersionV22
)

// protocolSuite contains every domain-separation label that changes between
// v2.1 and v2.2. The handshake bytes remain structurally similar, so distinct
// labels are required to make cross-version handshakes fail at authentication.
type protocolSuite struct {
	version protocolVersion
	name    string

	outerAEAD     string
	outerMAC      string
	outerAEADSalt string
	outerMACSalt  string

	sessionSalt string
	c2sKey      string
	s2cKey      string
	c2sNonce    string
	s2cNonce    string
	sessionID   string
	rekeyLabel  string
}

const (
	v22LabelOuterAEAD     = "ewp/v2.2 outer aead"
	v22LabelOuterMAC      = "ewp/v2.2 outer mac"
	v22LabelOuterAEADSalt = "ewp/v2.2 outer-aead-salt"
	v22LabelOuterMACSalt  = "ewp/v2.2 outer-mac-salt"
	v22LabelSessionSalt   = "ewp/v2.2 session salt"
	v22LabelC2SKey        = "ewp/v2.2 c2s key"
	v22LabelS2CKey        = "ewp/v2.2 s2c key"
	v22LabelC2SNonce      = "ewp/v2.2 c2s nonce"
	v22LabelS2CNonce      = "ewp/v2.2 s2c nonce"
	v22LabelSessionID     = "ewp/v2.2 sid"
	v22LabelRekey         = "ewp/v2.2 key evolution"
)

var (
	v21Suite = protocolSuite{
		version:       protocolVersionV21,
		name:          "ewp/v2.1",
		outerAEAD:     v21LabelOuterAEAD,
		outerMAC:      v21LabelOuterMAC,
		outerAEADSalt: v21LabelOuterAEADSalt,
		outerMACSalt:  v21LabelOuterMACSalt,
		sessionSalt:   infoSaltPrefix,
		c2sKey:        infoC2SKey,
		s2cKey:        infoS2CKey,
		c2sNonce:      infoC2SNonce,
		s2cNonce:      infoS2CNonce,
		sessionID:     infoSessionID,
		rekeyLabel:    rekeyLabel,
	}
	v22Suite = protocolSuite{
		version:       protocolVersionV22,
		name:          "ewp/v2.2",
		outerAEAD:     v22LabelOuterAEAD,
		outerMAC:      v22LabelOuterMAC,
		outerAEADSalt: v22LabelOuterAEADSalt,
		outerMACSalt:  v22LabelOuterMACSalt,
		sessionSalt:   v22LabelSessionSalt,
		c2sKey:        v22LabelC2SKey,
		s2cKey:        v22LabelS2CKey,
		c2sNonce:      v22LabelC2SNonce,
		s2cNonce:      v22LabelS2CNonce,
		sessionID:     v22LabelSessionID,
		rekeyLabel:    v22LabelRekey,
	}
)

// ErrProtocolVersion is returned when handshake keys are supplied to a stream
// constructor for a different record-format suite.
var ErrProtocolVersion = errors.New("ewp: session keys do not match stream protocol version")

func suiteForVersion(version protocolVersion) *protocolSuite {
	if version == protocolVersionV22 {
		return &v22Suite
	}
	return &v21Suite
}
