// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package quic

// StreamWriteParameters holds information relating to the data to be written.
type StreamWriteParameters struct {
	Data     []byte
	Finished bool
}
