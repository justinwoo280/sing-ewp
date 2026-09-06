package ewp

// Opening-phase exact refragmentation (v2.2/v2.3 shared).
//
// The bucket-ladder padding policy (padding_policy.go) pads each frame
// *relative* to its payload: the smallest fitting bucket plus jitter. That
// leaves a residual signal we measured: payloads one or two buckets apart
// are discriminable at ~77%, and payloads several buckets apart (1 KiB vs
// 4 KiB) at ~100%, because padding can only ever make small things bigger —
// it never makes a large write smaller.
//
// This file adopts the AnyTLS insight: during the OPENING of a stream (the
// phase an observer fingerprints hardest, since it carries the inner
// handshake), shape the byte stream to *exact* scheme-driven record sizes by
// both splitting oversized writes and padding undersized ones. A 4 KiB
// first write no longer produces a recognisable ~4 KiB frame: it is chopped
// into scheme-sized records indistinguishable from any other connection's
// opening.
//
// Two deliberate deviations from AnyTLS:
//
//   - AnyTLS ships ONE fixed default scheme and rotates it via server push
//     (cmdUpdatePaddingScheme) because a fixed scheme eventually becomes a
//     fingerprint itself. EWP padding is a unilateral sender-side decision
//     (the receiver just skips pad bytes), so we can draw a FRESH randomised
//     scheme per connection from a TLS-1.3-handshake-shaped distribution.
//     Fingerprint rotation is free: no negotiation, no fixed shape to
//     blacklist.
//
//   - AnyTLS emits pure chaff records to complete a scheme after the payload
//     runs out (until its "c" check-mark). We adopt the same force/"c"
//     split: the two records that every TLS handshake exhibits
//     (ClientHello-ish, ServerHello-ish) are forced — completed with
//     FramePaddingOnly chaff when the payload runs out — so frame count and
//     total opening bytes do not leak the write size for writes up to ~2.1
//     KB. Certificate-flight and later positions are "c": emission stops
//     when the payload does, bounding chaff at ~2.2 KB per connection.
//     (Timing-driven cover traffic, when wanted, remains the StreamShaper's
//     job.)

// v22RecordOverhead is the wire bytes a v2.2 opaque record adds around its
// payload: 4-byte cleartext outer length + 15-byte encrypted inner header
// (counter 8 + type 1 + metalen 2 + payloadlen 4) + 16-byte AEAD tag.
const v22RecordOverhead = v22OuterLengthSize + v22InnerHeaderSize + 16

// openingScheme is a per-connection sequence of target WIRE sizes (all
// overhead included) for the first TCP-data records of a stream. Positions
// are consumed in order; once exhausted the stream falls back to the steady
// bucket-ladder policy.
//
// Each position is marked force or "c" (AnyTLS check-mark semantics):
//
//   - force: the record is emitted at its exact target size even when the
//     application payload has run out — the shortfall is made up with a
//     FramePaddingOnly chaff record. The first two positions (the
//     ClientHello / ServerHello silhouette every TLS handshake exhibits)
//     are forced, so EVERY connection's opening shows the same two-record
//     shape and small writes are indistinguishable in frame count up to the
//     forced capacity (~2.1 KB). Without this, frame count leaks the write
//     size: a 1 KB write consumes 2 records while a 4 KB write consumes 3+,
//     leaving total wire bytes 100% discriminable.
//   - "c": emission stops as soon as the payload is sent; no chaff is
//     generated. Certificate-flight and later positions use this, bounding
//     per-connection chaff overhead at ~2.2 KB worst case.
type openingScheme struct {
	sizes []int
	force []bool
	pos   int
}

// newOpeningScheme draws a fresh scheme shaped like a TLS 1.3 handshake
// record silhouette:
//
//	record 0      inner ClientHello-ish          400–700    (force)
//	record 1      ServerHello + EncryptedExt    1200–1500   (force)
//	records 2..k  Certificate flight (2–4 recs) 2048–8192   (c)
//	record k+1    CertificateVerify-ish          800–1500   (c)
//	record k+2    Finished / early-data-ish      800–1500   (c)
//
// Every size is drawn independently per connection, so the population of
// connections shows a family of silhouettes rather than one blacklistable
// shape.
func newOpeningScheme() *openingScheme {
	sizes := []int{
		400 + secureRandIntn(301),
		1200 + secureRandIntn(301),
	}
	force := []bool{true, true}
	for i, n := 0, 2+secureRandIntn(3); i < n; i++ {
		sizes = append(sizes, 2048+secureRandIntn(6145))
		force = append(force, false)
	}
	sizes = append(sizes,
		800+secureRandIntn(701),
		800+secureRandIntn(701),
	)
	force = append(force, false, false)
	return &openingScheme{sizes: sizes, force: force}
}

// active reports whether any scheme positions remain.
func (o *openingScheme) active() bool {
	return o != nil && o.pos < len(o.sizes)
}

// next returns the next target wire size and whether it is forced, and
// consumes the position. Callers must check active() first.
func (o *openingScheme) next() (target int, force bool) {
	v := o.sizes[o.pos]
	if o.pos < len(o.force) {
		force = o.force[o.pos]
	}
	o.pos++
	return v, force
}

// forceCurrent reports whether the CURRENT (not yet consumed) position is
// forced — i.e. whether emission must continue even with no payload left.
func (o *openingScheme) forceCurrent() bool {
	return o != nil && o.pos < len(o.force) && o.force[o.pos]
}

// remaining reports how many scheme positions are left (for tests).
func (o *openingScheme) remaining() int {
	if o == nil {
		return 0
	}
	return len(o.sizes) - o.pos
}
