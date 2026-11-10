// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"github.com/pion/dtls/v4/internal/crypto/elliptic"
)

// NewActive creates a DTLS 1.3 state with initialized common fields.
func NewActive(isClient bool) *State13 {
	return Activate13(&State13{Common: &Common{IsClient: isClient}})
}

// CommonState returns the state's common fields, allocating them if unset.
// A nil state yields a detached, empty Common.
func CommonState(state *State13) *Common {
	if state == nil {
		return &Common{}
	}
	if state.Common == nil {
		state.Common = &Common{}
	}

	return state.Common
}

// Activate13 returns state with its lazily allocated fields initialized.
func Activate13(state *State13) *State13 {
	if state == nil {
		state = &State13{}
	}
	CommonState(state)
	if state.TrafficKeys == nil {
		state.TrafficKeys = &TrafficKeyState{}
	}
	if state.LocalKeypairs == nil {
		state.LocalKeypairs = make(map[elliptic.Curve]*elliptic.Keypair)
	}

	return state
}

func HandshakeRecvSequence(state *State13) int {
	if state == nil {
		return 0
	}

	return state.HandshakeRecvSequence
}

func NextHandshakeSendSequence(state *State13) uint16 {
	if state == nil {
		return 0
	}
	state.sequenceMu.Lock()
	defer state.sequenceMu.Unlock()
	seq := state.HandshakeSendSequence
	state.HandshakeSendSequence++

	return uint16(seq) //nolint:gosec // G115
}
