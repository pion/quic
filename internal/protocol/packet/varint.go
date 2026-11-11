// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package packet

import (
	"errors"
	"io"
)

// MaxVarint is the maximum value of a QUIC variable-length integer (2^62-1).
const MaxVarint uint64 = (1 << 62) - 1

// ErrVarintOverflow indicates a value outside the QUIC varint range.
var ErrVarintOverflow = errors.New("QUIC varint exceeds 62 bits")

// VarintLen returns the minimum encoding length in bytes (1, 2, 4, or 8).
// Values above MaxVarint return zero and ErrVarintOverflow.
// https://datatracker.ietf.org/doc/html/rfc9000#section-16
func VarintLen(value uint64) (int, error) {
	switch {
	case value < 1<<6:
		return 1, nil
	case value < 1<<14:
		return 2, nil
	case value < 1<<30:
		return 4, nil
	case value <= MaxVarint:
		return 8, nil
	default:
		return 0, ErrVarintOverflow
	}
}

// AppendVarint appends a variable-length integer in network byte order,
// using the minimum encoding length. On overflow, dst is unchanged.
// https://datatracker.ietf.org/doc/html/rfc9000#section-16
func AppendVarint(dst []byte, value uint64) ([]byte, error) {
	length, err := VarintLen(value)
	if err != nil {
		return dst, err
	}
	start := len(dst)
	for i := length - 1; i >= 0; i-- {
		dst = append(dst, byte((value>>uint(8*i))&0xff))
	}
	// The two most significant bits encode the base-2 logarithm of the length in bytes.
	switch length {
	case 2:
		dst[start] |= 0x40
	case 4:
		dst[start] |= 0x80
	case 8:
		dst[start] |= 0xc0
	}

	return dst, nil
}

// ParseVarint returns the value and bytes consumed. Values need not use the
// minimum number of bytes necessary to encode the value.
// Truncated input returns zero bytes consumed and io.ErrUnexpectedEOF.
func ParseVarint(raw []byte) (uint64, int, error) {
	if len(raw) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	length := 1 << (raw[0] >> 6)
	if len(raw) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}
	value := uint64(raw[0] & 0x3f)
	for _, b := range raw[1:length] {
		value = value<<8 | uint64(b)
	}

	return value, length, nil
}
