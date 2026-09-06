package ewp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	V3ProtocolVersion                     uint16  = 3
	V3SuiteX25519MLKEM768ChaCha20Poly1305 SuiteID = 1

	V3NonceLen          = 16
	V3HandshakeIDLen    = 16
	V3PreKeyIDLen       = 16
	V3RouteTagLen       = 16
	V3BundleDigestLen   = 32
	V3KAuthLen          = 32
	V3ReplayKeyLen      = 32
	V3SignatureLen      = ed25519.SignatureSize
	V3CookieLen         = 32
	V3MaxServerIDLen    = 255
	V3MaxScopeLen       = 255
	V3MaxParameterLen   = 4096
	V3MaxSourceLen      = 512
	MaxV3ReplayClaims   = 65536
	MaxV3Principals     = 65536
	MaxV3PreKeys        = 65536
	MaxV3HandshakeBytes = 256 << 10
	V3MinClientInitSize = 256
	V3RetryLifetime     = 10 * time.Second
)

var (
	ErrV3Version             = errors.New("ewp/v3: unsupported version")
	ErrV3Suite               = errors.New("ewp/v3: unsupported suite")
	ErrV3Identity            = errors.New("ewp/v3: invalid server identity")
	ErrV3Credential          = errors.New("ewp/v3: invalid client credential")
	ErrV3Route               = errors.New("ewp/v3: route tag rejected")
	ErrV3Cookie              = errors.New("ewp/v3: retry cookie rejected")
	ErrV3Admission           = errors.New("ewp/v3: admission rejected")
	ErrV3Replay              = errors.New("ewp/v3: replay rejected")
	ErrV3PreKey              = errors.New("ewp/v3: prekey unavailable")
	ErrV3State               = errors.New("ewp/v3: invalid handshake state")
	ErrV3Finished            = errors.New("ewp/v3: finished verification failed")
	ErrV3Signature           = errors.New("ewp/v3: server signature rejected")
	ErrV3Transcript          = errors.New("ewp/v3: transcript mismatch")
	ErrV3Source              = errors.New("ewp/v3: source binding required")
	ErrV3DeadlineUnsupported = errors.New("ewp/v3: transport deadline unsupported")
)

type SuiteID uint16
type PrincipalID [16]byte
type PreKeyID [V3PreKeyIDLen]byte
type V3Nonce [V3NonceLen]byte
type HandshakeID [V3HandshakeIDLen]byte
type BundleDigest [V3BundleDigestLen]byte
type RouteTag [V3RouteTagLen]byte
type ReplayKey [V3ReplayKeyLen]byte

// SourceBinding is the normalized source identity used by cookies, quotas, and
// the current handshake. It is deliberately opaque to the protocol.
type SourceBinding string

func SourceBindingFromAddr(addr net.Addr) SourceBinding {
	if addr == nil {
		return ""
	}
	network, address := addr.Network(), addr.String()
	if network == "" && address == "" {
		return ""
	}
	value := network + "\x00" + address
	if len(value) > V3MaxSourceLen {
		digest := sha256.Sum256([]byte(value))
		return SourceBinding(string(digest[:]))
	}
	return SourceBinding(value)
}

type V3ListenerContext struct {
	Version         uint16
	Suite           SuiteID
	ServerID        string
	DeploymentScope string
}

func (c V3ListenerContext) validate() error {
	if c.Version != V3ProtocolVersion {
		return ErrV3Version
	}
	if c.Suite != V3SuiteX25519MLKEM768ChaCha20Poly1305 {
		return ErrV3Suite
	}
	if len(c.ServerID) == 0 || len(c.ServerID) > V3MaxServerIDLen || len(c.DeploymentScope) > V3MaxScopeLen {
		return ErrV3Malformed
	}
	return nil
}

func validateV3VersionSuite(version uint16, suite SuiteID) error {
	if version != V3ProtocolVersion {
		return ErrV3Version
	}
	if suite != V3SuiteX25519MLKEM768ChaCha20Poly1305 {
		return ErrV3Suite
	}
	return nil
}

func v3AllZero(value []byte) bool {
	var result byte
	for _, b := range value {
		result |= b
	}
	return result == 0
}

// ClientCredential carries the v3 random authentication secret and the
// configured principal identity. Neither value is a legacy wire credential.
type ClientCredential struct {
	Principal  PrincipalID
	KAuth      [V3KAuthLen]byte
	Listener   V3ListenerContext
	RouteEpoch uint64
}

func (c ClientCredential) validate() error {
	if err := c.Listener.validate(); err != nil {
		return err
	}
	var zero [V3KAuthLen]byte
	if c.KAuth == zero {
		return ErrV3Credential
	}
	return nil
}

type Ed25519PublicKey [ed25519.PublicKeySize]byte

type ServerSigningIdentity struct {
	Private ed25519.PrivateKey
	Public  Ed25519PublicKey
}

func NewServerSigningIdentity(private ed25519.PrivateKey) (ServerSigningIdentity, error) {
	if len(private) != ed25519.PrivateKeySize {
		return ServerSigningIdentity{}, ErrV3Identity
	}
	var public Ed25519PublicKey
	copy(public[:], private.Public().(ed25519.PublicKey))
	return ServerSigningIdentity{Private: append(ed25519.PrivateKey(nil), private...), Public: public}, nil
}

func GenerateServerSigningIdentity() (ServerSigningIdentity, error) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return ServerSigningIdentity{}, err
	}
	var key Ed25519PublicKey
	copy(key[:], public)
	return ServerSigningIdentity{Private: private, Public: key}, nil
}

func (i ServerSigningIdentity) validate() error {
	if len(i.Private) != ed25519.PrivateKeySize {
		return ErrV3Identity
	}
	if len(i.Public) != ed25519.PublicKeySize {
		return ErrV3Identity
	}
	if !bytes.Equal(i.Public[:], i.Private.Public().(ed25519.PublicKey)) {
		return ErrV3Identity
	}
	return nil
}

func (id PreKeyID) isZero() bool {
	var zero PreKeyID
	return id == zero
}

func (d BundleDigest) isZero() bool {
	var zero BundleDigest
	return d == zero
}

func (c V3ListenerContext) String() string {
	return fmt.Sprintf("v%d/%d:%s/%s", c.Version, c.Suite, c.ServerID, c.DeploymentScope)
}
