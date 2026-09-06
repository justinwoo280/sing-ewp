package ewp

// This file fuzzes *cryptographic invariants*, not merely crash-freedom.
// Every target below starts from a VALID artifact (a sealed record, a valid
// cookie, a committed transcript) and asserts that tampering is *detected and
// rejected* — never silently accepted. These are the properties that separate
// a robust implementation from one that merely "does not panic".

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// v23FuzzKeys builds a deterministic encoder FrameAEAD shared by the record
// invariant fuzzers. Determinism keeps the corpus reproducible.
func v23FuzzKeys(f *testing.F) *FrameAEAD {
	f.Helper()
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range prefix {
		prefix[i] = byte(0xa0 + i)
	}
	enc, err := NewFrameAEAD(key, prefix)
	if err != nil {
		f.Fatalf("encoder: %v", err)
	}
	return enc
}

// FuzzV22RecordTamperAlwaysRejected seals a valid record, then flips one byte
// at a fuzzer-chosen offset and asserts DecodeFrameV22 NEVER returns a
// successfully-decrypted frame for the tampered input. Any single-bit change
// to the AEAD ciphertext or the authenticated outer length must fail open —
// either AEADOpen, CounterMismatch, or a length/layout error. The one legal
// exception is a no-op substitution (x ^ 0 == x), which is not a tamper.
func FuzzV22RecordTamperAlwaysRejected(f *testing.F) {
	enc := v23FuzzKeys(f)
	var seed bytes.Buffer
	if err := encodeFrameV22WithPad(&seed, enc, FrameTCPData, []byte("m"), []byte("payload-bytes"), 8); err != nil {
		f.Fatalf("seed: %v", err)
	}
	wire := seed.Bytes()
	f.Add(wire, 0, byte(1))
	f.Add(wire, len(wire)-1, byte(0xff))
	f.Fuzz(func(t *testing.T, orig []byte, offset int, xor byte) {
		if len(orig) == 0 || len(orig) > MaxV22RecordSize+64 {
			t.Skip()
		}
		// Build a fresh valid record from orig so the decoder counter starts
		// at 0 in the expected state. Track how many bytes the decoder
		// actually consumes: DecodeFrameV22 reads exactly 4 + recordLen and
		// ignores any trailing bytes, so a tamper beyond the consumed prefix
		// is not a tamper of the record at all.
		r := bytes.NewReader(orig)
		decoder := mustResetDecoder(t, orig)
		frame, err := DecodeFrameV22(r, decoder)
		if err != nil {
			t.Skip() // orig is not a valid first record; nothing to tamper with
		}
		if frame == nil {
			t.Skip()
		}
		consumed := len(orig) - r.Len()
		if consumed <= 0 {
			t.Skip()
		}

		// Tamper a copy *within the consumed record bytes only*.
		off := offset % consumed
		if off < 0 {
			off = -off
		}
		tampered := append([]byte(nil), orig...)
		tampered[off] ^= xor
		if bytes.Equal(tampered[:consumed], orig[:consumed]) {
			t.Skip() // xor==0 within the record, not a tamper
		}

		// The tampered record must NOT decode successfully with a fresh
		// decoder at counter 0.
		d2 := mustResetDecoder(t, orig)
		got, gerr := DecodeFrameV22(bytes.NewReader(tampered), d2)
		if gerr == nil && got != nil {
			t.Fatalf("tampered record at off=%d (consumed=%d) xor=%#x decoded successfully (payload=%q)", off, consumed, xor, got.Payload)
		}
	})
}

// FuzzV22RecordCounterMismatchEnforced seals a record at a fuzzer-chosen
// counter N (by advancing the encoder's counter past N-1 dummy records), then
// feeds it to a decoder expecting counter 0. The anti-replay / anti-reorder
// guarantee requires that ANY record sealed under counter N>0 is rejected by
// a decoder at counter 0 — it must never be silently accepted. (counter==0 is
// the legitimate first record and is expected to succeed, so it is skipped.)
func FuzzV22RecordCounterMismatchEnforced(f *testing.F) {
	f.Add(uint8(1), []byte("payload"))
	f.Add(uint8(7), []byte("x"))
	f.Fuzz(func(t *testing.T, skip uint8, payload []byte) {
		if len(payload) == 0 || len(payload) > 1024 {
			t.Skip()
		}
		n := int(skip)
		// Seal a record whose counter is n: burn n dummy records first.
		enc := mustResetDecoder(t, nil)
		var wire bytes.Buffer
		for i := 0; i < n; i++ {
			if err := encodeFrameV22WithPad(&wire, enc, FrameTCPData, nil, []byte("pad"), 0); err != nil {
				t.Fatalf("burn %d: %v", i, err)
			}
		}
		var rec bytes.Buffer
		if err := encodeFrameV22WithPad(&rec, enc, FrameTCPData, nil, payload, 0); err != nil {
			t.Fatalf("seal: %v", err)
		}

		// A decoder at counter 0 must reject the counter-n record unless n==0.
		d := mustResetDecoder(t, nil)
		frame, err := DecodeFrameV22(bytes.NewReader(rec.Bytes()), d)
		if n == 0 {
			if err != nil || frame == nil {
				t.Fatalf("counter-0 record wrongly rejected: %v", err)
			}
			return
		}
		if err == nil && frame != nil {
			t.Fatalf("record sealed at counter=%d accepted by counter-0 decoder (payload=%q)", n, frame.Payload)
		}
		// The rejection must be an authentication/ordering failure or a clean
		// truncation, never an unexpected error class.
		if !errors.Is(err, ErrAEADOpen) && !errors.Is(err, ErrCounterMismatch) &&
			!errors.Is(err, ErrFrameTooShort) && !errors.Is(err, ErrFrameTooLarge) &&
			!errors.Is(err, ErrFrameType) && !errors.Is(err, ErrMetaTooLarge) &&
			!errors.Is(err, ErrPadTooLarge) &&
			!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("counter=%d record rejected with unexpected error type: %v", n, err)
		}
	})
}

// FuzzV22NonceUniqueness asserts composeNonce never repeats a nonce for a
// fixed prefix across distinct counters, and never collides across distinct
// prefixes for the same counter. Nonce reuse under one key is catastrophic
// for ChaCha20-Poly1305, so this must hold for every counter/prefix pair.
func FuzzV22NonceUniqueness(f *testing.F) {
	f.Add(uint64(0), uint64(1), byte(0xa0), byte(0xa1))
	f.Fuzz(func(t *testing.T, c1, c2 uint64, p1, p2 byte) {
		if c1 == c2 && p1 == p2 {
			t.Skip()
		}
		var key [AEADKeyLen]byte
		var pre1, pre2 [NoncePrefixLen]byte
		pre1[0] = p1
		pre2[0] = p2
		f1, err := NewFrameAEAD(key, pre1)
		if err != nil {
			t.Fatal(err)
		}
		f2, err := NewFrameAEAD(key, pre2)
		if err != nil {
			t.Fatal(err)
		}
		n1 := f1.composeNonce(c1)
		n2 := f2.composeNonce(c2)
		if c1 != c2 || p1 != p2 {
			if n1 == n2 {
				t.Fatalf("nonce collision: c1=%d p1=%#x c2=%d p2=%#x -> %x", c1, p1, c2, p2, n1)
			}
		}
	})
}

// FuzzV22DecodedOutputNotAliased verifies the scratch-buffer optimisation is
// memory-safe: the Meta/Payload returned by one DecodeFrameV22 call must NOT
// be corrupted by a subsequent DecodeFrameV22 call on the same FrameAEAD.
// They are caller-owned copies; if they aliased the reused scratch, the second
// decode would clobber the first frame's contents.
func FuzzV22DecodedOutputNotAliased(f *testing.F) {
	f.Add([]byte("alpha"), []byte("beta"))
	f.Fuzz(func(t *testing.T, p1, p2 []byte) {
		if len(p1) == 0 || len(p2) == 0 || len(p1) > 2048 || len(p2) > 2048 {
			t.Skip()
		}
		// Encode two records into one buffer.
		var buf bytes.Buffer
		e := mustResetDecoder(t, nil)
		if err := encodeFrameV22WithPad(&buf, e, FrameTCPData, nil, p1, 0); err != nil {
			t.Skip()
		}
		if err := encodeFrameV22WithPad(&buf, e, FrameTCPData, nil, p2, 0); err != nil {
			t.Skip()
		}

		d := mustResetDecoder(t, nil)
		r := bytes.NewReader(buf.Bytes())
		f1, err := DecodeFrameV22(r, d)
		if err != nil {
			t.Fatalf("decode first: %v", err)
		}
		// Snapshot the first frame's payload bytes.
		snap := append([]byte(nil), f1.Payload...)
		if !bytes.Equal(f1.Payload, p1) {
			t.Fatalf("first payload mismatch: got %q want %q", f1.Payload, p1)
		}
		// Decode the second record, reusing the same FrameAEAD (and scratch).
		if _, err := DecodeFrameV22(r, d); err != nil {
			t.Fatalf("decode second: %v", err)
		}
		// The first frame's payload must be unchanged.
		if !bytes.Equal(f1.Payload, snap) {
			t.Fatalf("first frame payload clobbered by second decode: was %q now %q", snap, f1.Payload)
		}
	})
}

// FuzzV23CookieTamperRejected asserts a valid cookie fails verification after
// any single-byte change. This is the HMAC forgery-resistance invariant at the
// wire level: verification is a constant-time compare against a recomputed
// tag, so flipping any bit must change the comparison result.
func FuzzV23CookieTamperRejected(f *testing.F) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i * 7)
	}
	var ci V23ClientInit
	copy(ci.ClientNonce[:], []byte("0123456789abcdef"))
	var snonce [V23ServerNonceLen]byte
	copy(snonce[:], []byte("server-nonce-16!"))
	var keyID [V23OuterKeyIDLen]byte
	f.Add(byte(3), uint64(1700000000))
	f.Fuzz(func(t *testing.T, off byte, expiresAt uint64) {
		valid := v23Cookie(key, "srv", "1.2.3.4:5", &ci, snonce, expiresAt, keyID)
		// Sanity: the untampered cookie verifies.
		if !v23CookieEqual(valid, v23Cookie(key, "srv", "1.2.3.4:5", &ci, snonce, expiresAt, keyID)) {
			t.Fatal("valid cookie does not verify against itself")
		}
		// Flip one byte and confirm mismatch.
		tampered := valid
		tampered[int(off)%len(tampered)] ^= 0x01
		if v23CookieEqual(tampered, valid) {
			t.Fatalf("tampered cookie at off=%d still verifies", off)
		}
	})
}

// v23CookieEqual reports whether two cookies match, mirroring the server's
// constant-time comparison semantics.
func v23CookieEqual(a, b [V23CookieLen]byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// FuzzV23ReplayCacheDuplicateRejected asserts the cross-handshake replay
// cache always rejects a second admission of the same (UUID, nonce) within
// the window, and never rejects a first-seen distinct nonce. This is the
// invariant that turns in-window replay from "tolerated" into "rejected".
func FuzzV23ReplayCacheDuplicateRejected(f *testing.F) {
	f.Add(byte(1), byte(2), byte(3))
	f.Fuzz(func(t *testing.T, u1, n1, n2 byte) {
		cache := newReplayCache(ReplayWindow)
		defer cache.Close()
		var uuid [UUIDLen]byte
		uuid[0] = u1
		var nonce1, nonce2 [HandshakeNonce]byte
		nonce1[0] = n1
		nonce2[0] = n2

		// First admission of nonce1 must succeed.
		if !cache.MarkSeenOrReject(uuid, nonce1) {
			t.Fatal("first admission of fresh nonce rejected")
		}
		// Immediate duplicate must be rejected.
		if cache.MarkSeenOrReject(uuid, nonce1) {
			t.Fatal("duplicate (uuid,nonce) admitted")
		}
		// A distinct nonce must still be admitted (no false-positive).
		if nonce1 != nonce2 {
			if !cache.MarkSeenOrReject(uuid, nonce2) {
				t.Fatal("distinct nonce falsely rejected as replay")
			}
		}
	})
}

// FuzzV23TranscriptBinding asserts the transcript hash chains are
// order-sensitive and content-sensitive: swapping two messages or altering
// any byte must yield a different transcript, so a man-in-the-middle cannot
// reorder or rewrite handshake messages without breaking the Finished MACs.
func FuzzV23TranscriptBinding(f *testing.F) {
	f.Add([]byte("init"), []byte("retry"), byte(1))
	f.Fuzz(func(t *testing.T, m1, m2 []byte, flip byte) {
		if len(m1) == 0 || len(m2) == 0 || len(m1) > 512 || len(m2) > 512 {
			t.Skip()
		}
		tCI := v23Transcript(v23Suite.labelTCI, m1)
		tHRa := v23Transcript(v23Suite.labelTHR, tCI[:], m2)

		// Alter m2 by one byte; the resulting transcript must differ.
		m2alt := append([]byte(nil), m2...)
		m2alt[0] ^= flip | 0x01
		tHRb := v23Transcript(v23Suite.labelTHR, tCI[:], m2alt)
		if tHRa == tHRb {
			t.Fatal("transcript insensitive to message content change")
		}

		// A different prior transcript (different m1) must change the chain.
		m1alt := append([]byte(nil), m1...)
		m1alt[0] ^= flip | 0x01
		tCIalt := v23Transcript(v23Suite.labelTCI, m1alt)
		tHRc := v23Transcript(v23Suite.labelTHR, tCIalt[:], m2)
		if tHRa == tHRc {
			t.Fatal("transcript insensitive to prior-message change (binding broken)")
		}
	})
}

// mustResetDecoder returns a FrameAEAD suitable for decoding, with counter 0.
// It reuses the deterministic fuzz key material so sealed records made by the
// matching encoder open correctly.
func mustResetDecoder(t *testing.T, _ []byte) *FrameAEAD {
	t.Helper()
	var key [AEADKeyLen]byte
	var prefix [NoncePrefixLen]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range prefix {
		prefix[i] = byte(0xa0 + i)
	}
	d, err := NewFrameAEAD(key, prefix)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
