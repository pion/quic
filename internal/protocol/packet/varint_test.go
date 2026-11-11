// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package packet

import (
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVarint(t *testing.T) {
	for _, test := range []struct {
		wire  string
		value uint64
	}{
		{"00", 0},
		{"3f", 63},
		{"4040", 64},
		{"7fff", (1 << 14) - 1},
		{"80004000", 1 << 14},
		{"bfffffff", (1 << 30) - 1},
		{"c000000040000000", 1 << 30},
		{"ffffffffffffffff", MaxVarint},
		// RFC 9000, Appendix A.1 examples.
		{"25", 37},
		{"7bbd", 15293},
		{"9d7f3e7d", 494878333},
		{"c2197c5eff14e88c", 151288809941952652},
	} {
		t.Run(test.wire, func(t *testing.T) {
			wire, err := hex.DecodeString(test.wire)
			require.NoError(t, err)
			length, err := VarintLen(test.value)
			require.NoError(t, err)
			assert.Equal(t, len(wire), length)

			encoded, err := AppendVarint([]byte{0xab}, test.value)
			require.NoError(t, err)
			assert.Equal(t, append([]byte{0xab}, wire...), encoded)

			value, consumed, err := ParseVarint(append(wire, 0xab))
			require.NoError(t, err)
			assert.Equal(t, test.value, value)
			assert.Equal(t, length, consumed)
		})
	}
}

func TestParseVarintNonMinimal(t *testing.T) {
	for _, wire := range [][]byte{
		{0x40, 0x25},
		{0x80, 0, 0, 0x25},
		{0xc0, 0, 0, 0, 0, 0, 0, 0x25},
	} {
		value, consumed, err := ParseVarint(wire)
		require.NoError(t, err)
		assert.Equal(t, uint64(37), value)
		assert.Equal(t, len(wire), consumed)
	}
}

func TestParseVarintTruncated(t *testing.T) {
	for _, wire := range [][]byte{
		{0}, {0x40, 0}, {0x80, 0, 0, 0}, {0xc0, 0, 0, 0, 0, 0, 0, 0},
	} {
		for length := range len(wire) {
			value, consumed, err := ParseVarint(wire[:length])
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			assert.Zero(t, value)
			assert.Zero(t, consumed)
		}
	}
}

func TestVarintOverflow(t *testing.T) {
	for _, value := range []uint64{MaxVarint + 1, ^uint64(0)} {
		length, err := VarintLen(value)
		require.ErrorIs(t, err, ErrVarintOverflow)
		assert.Zero(t, length)

		dst := []byte{0xab, 0xcd}
		encoded, err := AppendVarint(dst, value)
		require.ErrorIs(t, err, ErrVarintOverflow)
		assert.Equal(t, []byte{0xab, 0xcd}, encoded)
		assert.Equal(t, []byte{0xab, 0xcd}, dst)
	}
}
