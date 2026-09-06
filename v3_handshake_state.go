package ewp

// V3FinishedSecrets are the handshake secrets needed to verify ClientFinished
// and derive the traffic keys for the current carrier. They live only for the
// lifetime of one handshake goroutine and are never serialized.
type V3FinishedSecrets struct {
	HandshakePRK            [32]byte
	ClientFinishedKey       [AEADKeyLen]byte
	ClientFinishedNonce     [AEADNonceLen]byte
	ClientFinishedVerifyKey [32]byte
	ServerFinishedKey       [AEADKeyLen]byte
	ServerFinishedNonce     [AEADNonceLen]byte
	ServerFinishedVerifyKey [32]byte
}

// V3PendingHandshake is local handshake state. It is deliberately not a
// persistence or handoff record: a carrier close discards it and the client
// starts a fresh handshake on the next carrier.
type V3PendingHandshake struct {
	Listener     V3ListenerContext
	Source       SourceBinding
	Principal    PrincipalID
	HandshakeID  HandshakeID
	TClientHello [32]byte
	TServerHello [32]byte
	Secrets      V3FinishedSecrets
	Command      Command
	Destination  Address

	// admissionRelease is process-local ownership transferred by the service
	// after ServerHello has been written.
	admissionRelease func()
}

func clearPendingSecrets(pending *V3PendingHandshake) {
	if pending == nil {
		return
	}
	zero(pending.Secrets.HandshakePRK[:])
	zero(pending.Secrets.ClientFinishedKey[:])
	zero(pending.Secrets.ClientFinishedNonce[:])
	zero(pending.Secrets.ClientFinishedVerifyKey[:])
	zero(pending.Secrets.ServerFinishedKey[:])
	zero(pending.Secrets.ServerFinishedNonce[:])
	zero(pending.Secrets.ServerFinishedVerifyKey[:])
}
