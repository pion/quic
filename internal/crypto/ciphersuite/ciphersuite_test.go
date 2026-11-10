// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"testing"

	"github.com/pion/dtls/v4/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestCapabilitySizing(t *testing.T) {
	aead, err := NewAEADCapabilities(protocol.Version1_3, 64, 0, 16, 16)
	require.NoError(t, err)
	protectedLen, err := aead.ProtectedLen(37)
	require.NoError(t, err)
	require.Equal(t, 53, protectedLen)
	upper, err := aead.PlaintextLenUpperBound(protectedLen)
	require.NoError(t, err)
	require.Equal(t, 37, upper)
	require.NoError(t, aead.ValidatePlaintextLen(protectedLen, 37))
	require.ErrorIs(t, aead.ValidatePlaintextLen(protectedLen, 36), ErrInvalidCapabilities)
}

func TestCapabilitiesRequireRecordNumberMask(t *testing.T) {
	_, err := NewAEADCapabilities(protocol.Version1_3, 64, 0, 16, 0)
	require.ErrorIs(t, err, ErrInvalidCapabilities)
}
