package ewp

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// EWP/v3 uses one strict length-delimited field encoding for every handshake
// structure. A field is tag (uint16, big endian), length (uint32, big endian),
// and value. Tags are strictly increasing. The high tag bit marks a critical
// field; unknown non-critical fields may be ignored by a newer implementation.
const (
	v3FieldHeaderLen = 2 + 4
	v3CriticalTag    = uint16(0x8000)
	MaxV3MessageSize = 64 << 10
	MaxV3FieldCount  = 64
)

var (
	ErrV3Malformed       = errors.New("ewp/v3: malformed encoding")
	ErrV3NonCanonical    = errors.New("ewp/v3: non-canonical encoding")
	ErrV3DuplicateField  = errors.New("ewp/v3: duplicate field")
	ErrV3UnknownField    = errors.New("ewp/v3: unknown critical field")
	ErrV3FieldTooLarge   = errors.New("ewp/v3: field exceeds bound")
	ErrV3MessageTooLarge = errors.New("ewp/v3: message exceeds bound")
)

type v3Field struct {
	tag   uint16
	value []byte
}

type v3DecodedField struct {
	tag   uint16
	value []byte
}

type v3FieldSet struct {
	entries [MaxV3FieldCount]v3DecodedField
	count   int
}

func (s *v3FieldSet) get(tag uint16) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	for i := 0; i < s.count; i++ {
		if s.entries[i].tag == tag {
			return s.entries[i].value, true
		}
	}
	return nil, false
}

func v3Bytes(tag uint16, value []byte) v3Field {
	return v3Field{tag: tag, value: value}
}

func v3U8(tag uint16, value byte) v3Field {
	return v3Field{tag: tag, value: []byte{value}}
}

func v3U16(tag uint16, value uint16) v3Field {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], value)
	return v3Field{tag: tag, value: b[:]}
}

func v3U32(tag uint16, value uint32) v3Field {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	return v3Field{tag: tag, value: b[:]}
}

func v3U64(tag uint16, value uint64) v3Field {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], value)
	return v3Field{tag: tag, value: b[:]}
}

func encodeV3Fields(fields ...v3Field) ([]byte, error) {
	if len(fields) > MaxV3FieldCount {
		return nil, ErrV3Malformed
	}
	total := 0
	var previous uint16
	for i, field := range fields {
		if field.tag == 0 || (i > 0 && field.tag <= previous) {
			return nil, ErrV3NonCanonical
		}
		if len(field.value) > MaxV3MessageSize {
			return nil, ErrV3FieldTooLarge
		}
		if len(field.value) > int(^uint32(0)) {
			return nil, ErrV3FieldTooLarge
		}
		total += v3FieldHeaderLen + len(field.value)
		if total > MaxV3MessageSize {
			return nil, ErrV3MessageTooLarge
		}
		previous = field.tag
	}
	out := make([]byte, 0, total)
	for _, field := range fields {
		var header [v3FieldHeaderLen]byte
		binary.BigEndian.PutUint16(header[0:2], field.tag)
		binary.BigEndian.PutUint32(header[2:6], uint32(len(field.value)))
		out = append(out, header[:]...)
		out = append(out, field.value...)
	}
	return out, nil
}

// decodeV3Fields validates ordering and bounds into a fixed field table. The
// returned values borrow data; parsers copy only slices that escape their
// result. Unknown non-critical fields are retained in the table for duplicate
// detection but are ignored by semantic parsers.
func decodeV3Fields(data []byte, known map[uint16]struct{}) (v3FieldSet, error) {
	if len(data) > MaxV3MessageSize {
		return v3FieldSet{}, ErrV3MessageTooLarge
	}
	var fields v3FieldSet
	var previous uint16
	count := 0
	for len(data) > 0 {
		if len(data) < v3FieldHeaderLen {
			return v3FieldSet{}, ErrV3Malformed
		}
		count++
		if count > MaxV3FieldCount {
			return v3FieldSet{}, ErrV3Malformed
		}
		tag := binary.BigEndian.Uint16(data[:2])
		length := binary.BigEndian.Uint32(data[2:6])
		if tag == 0 || (count > 1 && tag <= previous) {
			return v3FieldSet{}, ErrV3NonCanonical
		}
		data = data[v3FieldHeaderLen:]
		if uint64(length) > uint64(len(data)) {
			return v3FieldSet{}, ErrV3Malformed
		}
		value := data[:int(length)]
		data = data[int(length):]
		for i := 0; i < fields.count; i++ {
			if fields.entries[i].tag == tag {
				return v3FieldSet{}, ErrV3DuplicateField
			}
		}
		if known != nil {
			if _, ok := known[tag]; !ok {
				if tag&v3CriticalTag != 0 {
					return v3FieldSet{}, fmt.Errorf("%w: 0x%04x", ErrV3UnknownField, tag)
				}
			}
		}
		if len(value) > MaxV3MessageSize {
			return v3FieldSet{}, ErrV3FieldTooLarge
		}
		fields.entries[fields.count] = v3DecodedField{tag: tag, value: value}
		fields.count++
		previous = tag
	}
	return fields, nil
}

// v3FieldRegion returns the byte range occupied by tag in an already
// canonical field sequence. It is used to preserve exact nested wire bytes
// while still exposing parsed values to callers.
func v3FieldRegion(data []byte, wanted uint16) (start, end int, err error) {
	original := data
	var previous uint16
	count := 0
	for len(data) > 0 {
		if len(data) < v3FieldHeaderLen {
			return 0, 0, ErrV3Malformed
		}
		count++
		tag := binary.BigEndian.Uint16(data[:2])
		length := binary.BigEndian.Uint32(data[2:6])
		if tag == 0 || (count > 1 && tag <= previous) {
			return 0, 0, ErrV3NonCanonical
		}
		fieldStart := len(original) - len(data)
		if uint64(length) > uint64(len(data)-v3FieldHeaderLen) {
			return 0, 0, ErrV3Malformed
		}
		fieldEnd := fieldStart + v3FieldHeaderLen + int(length)
		if tag == wanted {
			return fieldStart, fieldEnd, nil
		}
		data = data[v3FieldHeaderLen+int(length):]
		previous = tag
	}
	return 0, 0, fmt.Errorf("%w: missing field 0x%04x", ErrV3Malformed, wanted)
}

func v3WithoutField(data []byte, wanted uint16) ([]byte, error) {
	start, end, err := v3FieldRegion(data, wanted)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(data)-(end-start))
	result = append(result, data[:start]...)
	result = append(result, data[end:]...)
	return result, nil
}

func v3Required(fields *v3FieldSet, tag uint16) ([]byte, error) {
	value, ok := fields.get(tag)
	if !ok {
		return nil, fmt.Errorf("%w: missing field 0x%04x", ErrV3Malformed, tag)
	}
	return value, nil
}

func v3Exact(fields *v3FieldSet, tag uint16, length int) ([]byte, error) {
	value, err := v3Required(fields, tag)
	if err != nil {
		return nil, err
	}
	if len(value) != length {
		return nil, fmt.Errorf("%w: field 0x%04x length %d, want %d", ErrV3Malformed, tag, len(value), length)
	}
	return value, nil
}

func v3ReadU8(fields *v3FieldSet, tag uint16) (byte, error) {
	value, err := v3Exact(fields, tag, 1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func v3ReadU16(fields *v3FieldSet, tag uint16) (uint16, error) {
	value, err := v3Exact(fields, tag, 2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}

func v3ReadU32(fields *v3FieldSet, tag uint16) (uint32, error) {
	value, err := v3Exact(fields, tag, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}

func v3ReadU64(fields *v3FieldSet, tag uint16) (uint64, error) {
	value, err := v3Exact(fields, tag, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(value), nil
}

func v3Domain(label string, parts ...[]byte) []byte {
	// Domain inputs are themselves length-delimited to prevent concatenation
	// ambiguity in labels, transcript hashes, cookies, and KDF info.
	out := make([]byte, 0, len(label)+4*(len(parts)+1))
	appendPart := func(part []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		out = append(out, length[:]...)
		out = append(out, part...)
	}
	appendPart([]byte(label))
	for _, part := range parts {
		appendPart(part)
	}
	return out
}

func v3Hash(label string, parts ...[]byte) [32]byte {
	return sha256.Sum256(v3Domain(label, parts...))
}
