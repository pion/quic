// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import "crypto/tls"

// ID is a registered TLS cipher-suite identifier.
type ID uint16

// Supported DTLS 1.3 cipher-suite identifiers.
// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
const (
	TLS_AES_128_GCM_SHA256       ID = 0x1301 // nolint: revive,staticcheck
	TLS_AES_256_GCM_SHA384       ID = 0x1302 // nolint: revive,staticcheck
	TLS_CHACHA20_POLY1305_SHA256 ID = 0x1303 // nolint: revive,staticcheck
)

func (i ID) String() string {
	return tls.CipherSuiteName(uint16(i))
}
