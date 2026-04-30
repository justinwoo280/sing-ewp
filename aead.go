package ewp

import "golang.org/x/crypto/chacha20poly1305"

// aead is a narrow interface over cipher.AEAD so the rest of this
// package never imports the concrete chacha20poly1305 type. There is
// only one implementation; this exists purely to keep imports tidy and
// to make swapping the primitive in a future major version a one-file
// change rather than a fan-out across handshake/frame/securestream.
type aead interface {
	Seal(dst, nonce, plaintext, aad []byte) []byte
	Open(dst, nonce, ciphertext, aad []byte) ([]byte, error)
}

// newChaChaAEAD constructs a ChaCha20-Poly1305 AEAD from a 32-byte
// key. Returns an error only on bad key length, which the type system
// already prevents at this entry point — kept for symmetry with stdlib
// idioms.
func newChaChaAEAD(key [AEADKeyLen]byte) (aead, error) {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return a, nil
}
