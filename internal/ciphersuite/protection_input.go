// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"bytes"
	"encoding/binary"
	"math"

	cryptosuite "github.com/pion/dtls/v4/internal/crypto/ciphersuite"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/protocol"
	"github.com/pion/dtls/v4/internal/recordwire"
)

type trafficSecret struct{ secret []byte }

func NewTrafficSecret(secret []byte) (cryptosuite.TrafficSecret, error) {
	if len(secret) == 0 {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}

	return trafficSecret{secret: secret}, nil
}

func (s trafficSecret) Bytes() []byte { return s.secret }

type protectionRecord struct {
	recordNumber       uint64
	authenticationData []byte
	protectedLen       int
}

func (r protectionRecord) RecordNumber() uint64 { return r.recordNumber }

func (r protectionRecord) AuthenticationData(recordLen int) ([]byte, error) {
	if recordLen < 0 || recordLen > math.MaxUint16 {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}
	if recordLen != r.protectedLen {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}

	return bytes.Clone(r.authenticationData), nil
}

// NewUnifiedRecord snapshots the clear, exact unified header used as AAD.
func NewUnifiedRecord(epoch, sequenceNumber uint64, header []byte, protectedLen int) (cryptosuite.Record, error) {
	if len(header) < 2 || !protocol.IsDTLS13Ciphertext(protocol.ContentType(header[0])) || protectedLen < 0 || protectedLen > math.MaxUint16 {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}

	return newValidatedUnifiedRecord(epoch, sequenceNumber, header, protectedLen)
}

func newValidatedUnifiedRecord(epoch, sequenceNumber uint64, header []byte, protectedLen int) (cryptosuite.Record, error) {
	sequenceEnd := len(header)
	if header[0]&recordwire.LengthBit != 0 {
		if len(header) < 4 || int(binary.BigEndian.Uint16(header[len(header)-2:])) != protectedLen {
			return nil, dtlserrors.ErrInvalidProtectionInput
		}
		sequenceEnd -= 2
	}
	sequenceLen := 1
	if header[0]&recordwire.SequenceBit != 0 {
		sequenceLen = 2
	}
	cidLength := sequenceEnd - sequenceLen - 1
	if cidLength < 0 || cidLength > math.MaxUint8 || (header[0]&recordwire.CIDBit != 0) != (cidLength != 0) || uint8(epoch&3) != header[0]&recordwire.EpochMask {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}
	if !unifiedSequenceMatches(header, sequenceEnd, sequenceLen, sequenceNumber) {
		return nil, dtlserrors.ErrInvalidProtectionInput
	}

	return protectionRecord{recordNumber: sequenceNumber, authenticationData: bytes.Clone(header), protectedLen: protectedLen}, nil
}

func unifiedSequenceMatches(header []byte, sequenceEnd, sequenceLen int, sequenceNumber uint64) bool {
	for i := range sequenceLen {
		if header[sequenceEnd-1-i] != byte((sequenceNumber>>uint(8*i))&0xff) {
			return false
		}
	}

	return true
}
