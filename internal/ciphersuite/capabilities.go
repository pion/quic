// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	cryptosuite "github.com/pion/dtls/v4/internal/crypto/ciphersuite"
	"github.com/pion/dtls/v4/internal/protocol"
)

// maxInnerPlaintextLen is 2^14 bytes of content plus the inner content type.
// https://www.rfc-editor.org/rfc/rfc8446#section-5.4
const maxInnerPlaintextLen = 1<<14 + 1

func mustAEADCapabilities(explicitNonceLen, tagLen, maskSampleLen int) cryptosuite.Capabilities {
	capabilities, err := cryptosuite.NewAEADCapabilities(
		protocol.Version1_3,
		maxInnerPlaintextLen,
		explicitNonceLen,
		tagLen,
		maskSampleLen,
	)
	if err != nil {
		return cryptosuite.Capabilities{}
	}

	return capabilities
}
