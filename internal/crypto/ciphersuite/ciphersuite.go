// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite defines cipher-suite descriptors, immutable record
// metadata, protection capabilities, and DTLS 1.3 record-protection contracts.
package ciphersuite

import (
	"errors"
	"hash"
	"math"

	"github.com/pion/dtls/v4/internal/protocol"
)

var (
	// ErrInvalidCapabilities reports a malformed cipher suite capabilities.
	ErrInvalidCapabilities = errors.New("invalid cipher suite capabilities")
	// ErrAuthenticationFailed reports that a protected record could not be
	// authenticated.
	ErrAuthenticationFailed = errors.New("record authentication failed")
)

// Suite describes a cipher suite without connection-specific key material.
// DTLS 1.3 cipher suites only select the AEAD and the HKDF hash.
// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
type Suite interface {
	String() string
	ID() ID
	HashFunc() func() hash.Hash
	Capabilities() Capabilities
}

// UsageLimits describes advisory per-key recommendations for DTLS.
// Zero means unspecified.
type UsageLimits struct {
	MaxSealedRecords          uint64
	MaxAuthenticationFailures uint64
}

// UsageLimitProvider is optional metadata for cipher suites that report
// recommended key-usage limits in connection statistics.
type UsageLimitProvider interface {
	UsageLimits() UsageLimits
}

// Capabilities is AEAD protection metadata for one protocol version.
type Capabilities struct {
	version          protocol.Version
	valid            bool
	maxPlaintextLen  int
	maxProtectedLen  int
	explicitNonceLen int
	tagLen           int
	maskSampleLen    int
}

// NewAEADCapabilities constructs capabilities for an AEAD suite.
func NewAEADCapabilities(version protocol.Version, maxPlaintextLen, explicitNonceLen, tagLen, maskSampleLen int) (Capabilities, error) {
	maxProtectedLen, valid := validAEADLengths(maxPlaintextLen, explicitNonceLen, tagLen)
	if !valid || !validAEADMask(version, maskSampleLen, maxProtectedLen) {
		return Capabilities{}, ErrInvalidCapabilities
	}

	return Capabilities{version: version, valid: true, maxPlaintextLen: maxPlaintextLen, maxProtectedLen: maxProtectedLen, explicitNonceLen: explicitNonceLen, tagLen: tagLen, maskSampleLen: maskSampleLen}, nil
}

func validAEADLengths(maxPlaintextLen, explicitNonceLen, tagLen int) (int, bool) {
	if !validPositiveUint16(maxPlaintextLen) || !validNonNegativeUint16(explicitNonceLen) ||
		!validPositiveUint16(tagLen) {
		return 0, false
	}

	maxProtectedLen := maxPlaintextLen + explicitNonceLen + tagLen

	return maxProtectedLen, maxProtectedLen <= math.MaxUint16
}

func validPositiveUint16(value int) bool {
	return value > 0 && value <= math.MaxUint16
}

func validNonNegativeUint16(value int) bool {
	return value >= 0 && value <= math.MaxUint16
}

// DTLS 1.3 record-number encryption samples the ciphertext.
// https://www.rfc-editor.org/rfc/rfc9147#section-4.2.3
func validAEADMask(version protocol.Version, maskSampleLen, maxProtectedLen int) bool {
	return version == protocol.Version1_3 && maskSampleLen > 0 && maskSampleLen <= maxProtectedLen
}

// Version returns the protocol version supported by the suite.
func (c Capabilities) Version() protocol.Version {
	return c.version
}

// SupportsVersion reports whether these capabilities describe version.
func (c Capabilities) SupportsVersion(version protocol.Version) bool {
	return c.valid && c.version == version
}

// MaskLen returns the required ciphertext sample length for record-number
// masking.
func (c Capabilities) MaskLen() int {
	return c.maskSampleLen
}

// ProtectedLen returns the exact protected payload length for plaintextLen.
func (c Capabilities) ProtectedLen(plaintextLen int) (int, error) {
	if !c.valid || plaintextLen < 0 || plaintextLen > c.maxPlaintextLen {
		return 0, ErrInvalidCapabilities
	}

	return plaintextLen + c.explicitNonceLen + c.tagLen, nil
}

// PlaintextLenUpperBound validates protectedLen and returns a checked allocation
// bound.
func (c Capabilities) PlaintextLenUpperBound(protectedLen int) (int, error) {
	if !c.valid || protectedLen < 0 || protectedLen > c.maxProtectedLen {
		return 0, ErrInvalidCapabilities
	}
	plaintextLen := protectedLen - c.explicitNonceLen - c.tagLen
	if plaintextLen < 0 || plaintextLen > c.maxPlaintextLen {
		return 0, ErrInvalidCapabilities
	}

	return plaintextLen, nil
}

// ValidatePlaintextLen checks the actual plaintext length returned by a
// successful Open against the protected length.
func (c Capabilities) ValidatePlaintextLen(protectedLen, plaintextLen int) error {
	expected, err := c.PlaintextLenUpperBound(protectedLen)
	if err != nil || plaintextLen != expected {
		return ErrInvalidCapabilities
	}

	return nil
}

// TrafficSecret is borrowed while deriving generation-bound traffic protection.
type TrafficSecret interface {
	// Bytes returns the borrowed secret. Implementations must not modify or retain it.
	Bytes() []byte
}

// Record is the read-only protection view of one record.
type Record interface {
	// Number returns the version-appropriate nonce number.
	RecordNumber() uint64
	// Data returns owned authentication bytes and validates the supplied record length.
	AuthenticationData(recordLen int) ([]byte, error)
}

// Protection seals and opens records. Implementations treat inputs as read-only
// and return caller-owned bytes.
type Protection interface {
	Seal(record Record, plaintext []byte) ([]byte, error)
	// Open authenticates and decrypts protected. It returns
	// ErrAuthenticationFailed for peer-controlled authentication failures.
	// for operational / provider failures it should pick other errors.
	Open(record Record, protected []byte) ([]byte, error)
}

// TrafficProtection adds record-number masking for generation-bound traffic.
type TrafficProtection interface {
	Protection
	// Mask treats sample as read-only and returns caller-owned bytes.
	Mask(sample []byte) ([]byte, error)
}

// TrafficSuite derives directional, generation-bound traffic protection.
type TrafficSuite interface {
	Suite
	NewTrafficProtection(TrafficSecret) (TrafficProtection, error)
}
