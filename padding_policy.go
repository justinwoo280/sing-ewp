package ewp

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
)

// v3 records use a bounded bucket ladder with a small random offset. The
// policy is deliberately independent of the v3 handshake message sizes.
var recordBuckets = []int{256, 512, 1024, 1500, 2048, 4096, 8192, 12288, 16384}

const (
	recordHandshakeFrames = 16
	recordBucketUpBP      = 4500
	recordJitterMax       = 64
)

func suggestStreamPadRecord(rawWireLen, phase int, random ...io.Reader) int {
	if phase < recordHandshakeFrames {
		floor := []int{512, 1500, 8192, 12288, 8192, 1500, 1500, 1024, 1024}[minInt(phase, 8)]
		if floor > rawWireLen {
			rawWireLen = minInt(rawWireLen+MaxFramePad, floor)
		}
	}
	return padToRecordBucket(rawWireLen, MaxFrameSize, random...)
}

func padToRecordBucket(rawWireLen, maxWire int, random ...io.Reader) int {
	if rawWireLen < 0 || rawWireLen >= maxWire {
		return 0
	}
	idx := -1
	for i, bucket := range recordBuckets {
		if bucket >= rawWireLen && bucket-rawWireLen <= MaxFramePad {
			idx = i
			break
		}
	}
	target := rawWireLen
	if idx >= 0 {
		target = recordBuckets[idx]
		if idx+1 < len(recordBuckets) && recordBuckets[idx+1] < maxWire &&
			recordBuckets[idx+1]-rawWireLen <= MaxFramePad && secureRandIntn(recordBucketUpBP+5500, random...) < recordBucketUpBP {
			target = recordBuckets[idx+1]
		}
	} else {
		target = ((rawWireLen + 1023) / 1024) * 1024
	}
	if target+recordJitterMax <= maxWire && target-rawWireLen+recordJitterMax <= MaxFramePad {
		target += secureRandIntn(recordJitterMax, random...)
	}
	if target > maxWire {
		target = maxWire
	}
	pad := target - rawWireLen
	if pad < 0 {
		return 0
	}
	if pad > MaxFramePad {
		return MaxFramePad
	}
	return pad
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func secureRandIntn(n int, random ...io.Reader) int {
	if n <= 1 {
		return 0
	}
	bound := uint64(n)
	threshold := -bound % bound
	for {
		var b [8]byte
		reader := crand.Reader
		if len(random) > 0 && random[0] != nil {
			reader = random[0]
		}
		if _, err := io.ReadFull(reader, b[:]); err != nil {
			return 0
		}
		value := binary.BigEndian.Uint64(b[:])
		if value >= threshold {
			return int(value % bound)
		}
	}
}
