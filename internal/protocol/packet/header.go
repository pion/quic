// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package packet defines unprotected QUIC v1 headers.
// https://datatracker.ietf.org/doc/html/rfc9000#section-17
package packet

// Version is the 32-bit QUIC wire version.
type Version uint32

const (
	VersionNegotiation Version = 0
	Version1           Version = 1
)

// QUIC v1 first-byte fields and header-protection masks.
// https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
const (
	HeaderFormBit          byte = 0x80
	FixedBit               byte = 0x40
	LongPacketTypeMask     byte = 0x30
	LongPacketTypeShift    byte = 4
	LongReservedMask       byte = 0x0c
	ShortSpinBit           byte = 0x20
	ShortReservedMask      byte = 0x18
	ShortKeyPhaseBit       byte = 0x04
	PacketNumberLengthMask byte = 0x03
	LongProtectionMask     byte = 0x0f
	ShortProtectionMask    byte = 0x1f
)

// LongPacketType is the unshifted QUIC v1 long-header type field.
type LongPacketType uint8

const (
	PacketTypeInitial   LongPacketType = 0
	PacketTypeZeroRTT   LongPacketType = 1
	PacketTypeHandshake LongPacketType = 2
	PacketTypeRetry     LongPacketType = 3
)

// QUIC v1 wire limits and fixed field sizes, in bytes unless otherwise stated.
const (
	MaxConnectionIDLength = 20
	MinPacketNumberLength = 1
	MaxPacketNumberLength = 4
	MaxPacketNumber       = (1 << 62) - 1
	VersionLength         = 4
	RetryIntegrityTagSize = 16
)

// LongHeader contains the common long-header fields.
// https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
type LongHeader struct {
	Version                 Version
	DestinationConnectionID []byte
	SourceConnectionID      []byte
}

// ProtectedLongHeader describes an Initial, 0-RTT, or Handshake header.
// Token is Initial-only; Length counts packet-number bytes plus ciphertext.
type ProtectedLongHeader struct {
	LongHeader
	Type               LongPacketType
	Token              []byte
	Length             uint64
	PacketNumber       uint64
	PacketNumberLength uint8
}

// ShortHeader describes a 1-RTT header, with a full packet number and wire width.
// https://datatracker.ietf.org/doc/html/rfc9000#section-17.3
type ShortHeader struct {
	DestinationConnectionID []byte
	PacketNumber            uint64
	PacketNumberLength      uint8
	SpinBit                 bool
	KeyPhase                bool
}

// RetryPacket carries a token and integrity tag; UnusedBits is the low four bits.
// https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.5
type RetryPacket struct {
	LongHeader
	UnusedBits   uint8
	Token        []byte
	IntegrityTag [RetryIntegrityTagSize]byte
}

// VersionNegotiationPacket has version zero; UnusedBits is the low seven bits.
// https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.1
type VersionNegotiationPacket struct {
	LongHeader
	UnusedBits        uint8
	SupportedVersions []Version
}
