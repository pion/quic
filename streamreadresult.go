// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package quic

// StreamReadResult holds information relating to the result returned from readInto.
type StreamReadResult struct {
	Amount   int
	Finished bool
}
