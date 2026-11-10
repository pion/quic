// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"github.com/pion/dtls/v4/internal/crypto/elliptic"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/protocol"
)

// Active is the connection state that shares common connection fields.
type Active interface {
	CommonFields() *Common
}

// NewActive creates a DTLS 1.3 active state with initialized common fields.
func NewActive(isClient bool) Active {
	return Activate13(&State13{Common: &Common{IsClient: isClient, LocalVersion: protocol.Version1_3}})
}

// CommonState returns the common state shared by an active state.
func CommonState(active Active) *Common {
	if active == nil {
		return &Common{}
	}
	if common := active.CommonFields(); common != nil {
		return common
	}

	common := &Common{}
	if state, ok := active.(*State13); ok {
		state.Common = common
	}

	return common
}

// Activate13 returns a DTLS 1.3 active state with its lazily allocated fields
// initialized.
func Activate13(active Active) *State13 {
	common := CommonState(active)
	state, ok := active.(*State13)
	if !ok {
		state = &State13{}
	}
	state.Common = common
	if state.TrafficKeys == nil {
		state.TrafficKeys = &TrafficKeyState{}
	}
	if state.LocalKeypairs == nil {
		state.LocalKeypairs = make(map[elliptic.Curve]*elliptic.Keypair)
	}

	return state
}

func As13(active Active) (*State13, error) {
	state, ok := active.(*State13)
	if !ok {
		return nil, dtlserrors.ErrInvalidProtocolVersionState
	}

	return state, nil
}

func HandshakeRecvSequence(active Active) int {
	if state, ok := active.(*State13); ok {
		return state.HandshakeRecvSequence
	}

	return 0
}

func NextHandshakeSendSequence(active Active) uint16 {
	state, ok := active.(*State13)
	if !ok {
		return 0
	}
	state.sequenceMu.Lock()
	defer state.sequenceMu.Unlock()
	seq := state.HandshakeSendSequence
	state.HandshakeSendSequence++

	return uint16(seq) //nolint:gosec // G115
}
