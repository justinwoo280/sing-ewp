package ewp

import (
	crand "crypto/rand"
	"io"
	"time"
)

type v3Runtime struct {
	now    func() time.Time
	random io.Reader
}

func productionV3Runtime() v3Runtime {
	return v3Runtime{now: time.Now, random: crand.Reader}
}

func (r v3Runtime) nowTime() time.Time {
	if r.now == nil {
		return time.Now()
	}
	return r.now()
}

func (r v3Runtime) reader() io.Reader {
	if r.random == nil {
		return crand.Reader
	}
	return r.random
}

func v3ReadRandom(r io.Reader, dst []byte) error {
	if r == nil {
		r = crand.Reader
	}
	_, err := io.ReadFull(r, dst)
	return err
}
