package ewp

import "errors"

// protocolVersion selects a cryptographic and record-format suite. v2.3
// keeps the v2.2 opaque record format but replaces the handshake; the suite
// therefore shares record labels with v2.2 and overrides the handshake and
// session derivation labels.
type protocolSuiteV23 struct {
	name string

	// Handshake-stage KDF labels (v2.3 transcript-bound chain).
	labelRoute      string
	labelCookie     string
	labelOuterKey   string
	labelHelloKey   string
	labelOuterKeyID string
	labelTraffic    string
	labelFinC       string
	labelFinS       string
	labelTCI        string
	labelTHR        string
	labelTCH        string
	labelTSH        string
	labelTCF        string
	labelTSF        string

	// Session labels: same wire bytes as v2.2 but derived under the v2.3
	// transcript PRK, so a v2.2 peer cannot produce matching keys.
	c2sKey     string
	s2cKey     string
	c2sNonce   string
	s2cNonce   string
	sessionID  string
	rekeyLabel string
}

const v23Name = "ewp/v2.3"

var v23Suite = protocolSuiteV23{
	name:            v23Name,
	labelRoute:      v23Name + "/route",
	labelCookie:     v23Name + "/cookie",
	labelOuterKey:   v23Name + "/outer",
	labelOuterKeyID: v23Name + "/outer-key",
	labelHelloKey:   v23Name + "/hello",
	labelTraffic:    v23Name + "/traffic",
	labelFinC:       v23Name + "/fin-c",
	labelFinS:       v23Name + "/fin-s",
	labelTCI:        v23Name + "/t-ci",
	labelTHR:        v23Name + "/t-hr",
	labelTCH:        v23Name + "/t-ch",
	labelTSH:        v23Name + "/t-sh",
	labelTCF:        v23Name + "/t-cf",
	labelTSF:        v23Name + "/t-sf",
	c2sKey:          v23Name + " c2s key",
	s2cKey:          v23Name + " s2c key",
	c2sNonce:        v23Name + " c2s nonce",
	s2cNonce:        v23Name + " s2c nonce",
	sessionID:       v23Name + " sid",
	rekeyLabel:      v23Name + " key evolution",
}

// v2.3 handshake wire sizes.
const (
	V23ClientNonceLen  = 16
	V23ServerNonceLen  = 16
	V23RouteTagLen     = 16
	V23CookieLen       = 32
	V23OuterKeyIDLen   = 8
	V23FinishedVrfLen  = 32
	V23CookieLifetimeS = 10

	// Default short-term outer key lifetime and the overlap during which
	// the previous key is still accepted for in-flight handshakes.
	V23OuterKeyDefaultLifetimeS = 3600
	V23OuterKeyOverlapS         = 300
)

var (
	// ErrV23Cookie rejects a ClientHello whose HelloRetry cookie fails
	// verification or is expired.
	ErrV23Cookie = errors.New("ewp/v2.3: retry cookie rejected")
	// ErrV23Route rejects a ClientInit whose route tag is unknown.
	ErrV23Route = errors.New("ewp/v2.3: route tag rejected")
	// ErrV23Admission rejects a handshake that exceeded admission limits.
	ErrV23Admission = errors.New("ewp/v2.3: admission rejected")
	// ErrV23Finished rejects a Finished whose verify_data does not match.
	ErrV23Finished = errors.New("ewp/v2.3: finished verification failed")
	// ErrV23Signature rejects an outer-key or ServerHello signature.
	ErrV23Signature = errors.New("ewp/v2.3: signature rejected")
	// ErrV23State reports an out-of-order handshake state transition.
	ErrV23State = errors.New("ewp/v2.3: invalid handshake state")
)
