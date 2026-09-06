package ewp

import "testing"

func TestV3DecodersRejectTruncatedMessages(t *testing.T) {
	decoders := []struct {
		name string
		fn   func([]byte) error
	}{
		{name: "client-init", fn: func(data []byte) error { _, err := ParseV3ClientInit(data); return err }},
		{name: "hello-retry", fn: func(data []byte) error { _, err := ParseV3HelloRetry(data); return err }},
		{name: "client-hello-core", fn: func(data []byte) error { _, err := ParseV3ClientHelloCore(data); return err }},
		{name: "client-hello", fn: func(data []byte) error { _, err := ParseV3ClientHello(data); return err }},
		{name: "server-hello-header", fn: func(data []byte) error { _, err := ParseV3ServerHelloHeader(data); return err }},
		{name: "server-hello", fn: func(data []byte) error { _, err := ParseV3ServerHello(data); return err }},
		{name: "client-finished", fn: func(data []byte) error { _, err := ParseV3ClientFinished(data); return err }},
		{name: "server-finished", fn: func(data []byte) error { _, err := ParseV3ServerFinished(data); return err }},
		{name: "client-plaintext", fn: func(data []byte) error { _, err := ParseV3ClientHelloPlaintext(data); return err }},
		{name: "server-plaintext", fn: func(data []byte) error { _, err := ParseV3ServerHelloPlaintext(data); return err }},
	}
	for _, decoder := range decoders {
		t.Run(decoder.name, func(t *testing.T) {
			for length := 0; length <= 8; length++ {
				if err := decoder.fn(make([]byte, length)); err == nil {
					t.Fatalf("accepted zero-filled truncated input of length %d", length)
				}
			}
		})
	}
}
