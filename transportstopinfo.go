// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package quic

// TransportStopInfo holds information relating to the error code for
// stopping a TransportBase.
type TransportStopInfo struct {
	ErrorCode uint16
	Reason    string
}
