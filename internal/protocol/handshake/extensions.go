// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"

	"github.com/pion/dtls/v4/internal/handshakewire"
)

func serverHelloExtensionContext(random Random) handshakewire.Context {
	randomBytes := random.MarshalFixed()
	if bytes.Equal(randomBytes[:], HelloRetryRequestRandom()) {
		return handshakewire.ContextHelloRetryRequest
	}

	return handshakewire.ContextServerHello
}
