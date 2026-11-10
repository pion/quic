// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/protocol"
	"github.com/pion/dtls/v4/internal/recordwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUDPDecode(t *testing.T) {
	for _, test := range []struct {
		Name      string
		Data      []byte
		Want      [][]byte
		WantError error
	}{
		{Name: "Alert, single packet", Data: []byte{0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01}, Want: [][]byte{{0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01}}},
		{
			Name: "Alert, multi packet",
			Data: []byte{0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01, 0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01},
			Want: [][]byte{{0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01}, {0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01}},
		},
		{
			Name:      "Invalid packet length",
			Data:      []byte{0x15, 0xfe},
			WantError: ErrInvalidPacketLength,
		},
		{Name: "Packet declared invalid length", Data: []byte{0x15, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0xFF, 0x01}, WantError: ErrInvalidPacketLength},
	} {
		dtlsPkts, err := UnpackDatagram(test.Data, UnpackDatagramConfig{})
		assert.ErrorIs(t, err, test.WantError)
		assert.Equal(t, test.Want, dtlsPkts, "UDP decode: %s", test.Name)
	}
}

func TestUnpackDatagramRejectsInvalidCIDLength(t *testing.T) {
	for _, cidLength := range []int{-1, maxConnectionIDLength + 1} {
		records, err := UnpackDatagram(nil, UnpackDatagramConfig{CIDLength: cidLength})
		require.ErrorIs(t, err, ErrInvalidPacketLength)
		require.Nil(t, records)
	}
}

func FuzzUnpackDatagram_No_Panics(f *testing.F) {
	Datasingle := []byte{
		0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01,
	}
	Datamulti := []byte{0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x01, 0x14, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x01}
	f.Add(Datasingle, uint8(0))
	f.Add(Datamulti, uint8(0))
	f.Add(append([]byte{recordwire.UnifiedFixedBits, 0x01}, make([]byte, minDTLSCiphertextRecordLen)...), uint8(0))

	f.Fuzz(func(_ *testing.T, data []byte, cidLength uint8) {
		_, _ = UnpackDatagram(data, UnpackDatagramConfig{CIDLength: int(cidLength)})
	})
}

func ciphertext13Payload(seed byte) []byte {
	out := make([]byte, minDTLSCiphertextRecordLen)
	for i := range out {
		out[i] = seed + byte(i)
	}

	return out
}

func TestUnpackDatagramCiphertext13(t *testing.T) {
	encryptedRecord := ciphertext13Payload(0xaa)
	ciphertextWithLengthRaw, err := MarshalCiphertext(CiphertextConfig{SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, encryptedRecord)
	require.NoError(t, err)

	ciphertextWithoutLengthRaw := append([]byte{0x20, 0x02}, ciphertext13Payload(0xcc)...)

	datagram := append(append([]byte{}, ciphertextWithLengthRaw...), ciphertextWithoutLengthRaw...)
	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{})
	require.NoError(t, err)
	require.Equal(t, [][]byte{ciphertextWithLengthRaw, ciphertextWithoutLengthRaw}, records)
}

func TestUnpackDatagramRejectsShortFinalCiphertextRecordWithoutLength(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		raw := append([]byte{0x20, 0x01}, make([]byte, recordLen)...)

		_, err := UnpackDatagram(raw, UnpackDatagramConfig{})
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d", recordLen)
	}
}

func TestUnpackDatagramRejectsShortCiphertextRecordWithLength(t *testing.T) {
	for recordLen := range minDTLSCiphertextRecordLen {
		raw := []byte{
			0x2c, 0x00, 0x01,
			byte(recordLen >> 8), byte(recordLen),
		}
		raw = append(raw, make([]byte, recordLen)...)

		_, err := UnpackDatagram(raw, UnpackDatagramConfig{})
		require.ErrorIs(t, err, ErrInvalidPacketLength, "record length %d", recordLen)
	}
}

func TestUnpackDatagramPlaintextRecordPolicy(t *testing.T) {
	alertRecord := fixedRecordForScannerTest(t, protocol.ContentTypeAlert, 0, 0xa1)
	handshakeRecord := fixedRecordForScannerTest(t, protocol.ContentTypeHandshake, 0, 0xb2)
	ackRecord := fixedRecordForScannerTest(t, protocol.ContentTypeACK, 0, 0xc3)
	unified := unifiedRecordForScannerTest(t, nil, 1)
	datagram := append(append(append(append([]byte{}, alertRecord...), handshakeRecord...), ackRecord...), unified...)

	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{})
	require.NoError(t, err)
	require.Equal(t, [][]byte{alertRecord, handshakeRecord, ackRecord, unified}, records)

	for _, test := range []struct {
		name        string
		contentType protocol.ContentType
		epoch       uint16
	}{
		{name: "application data", contentType: protocol.ContentTypeApplicationData, epoch: 0},
		{name: "nonzero plaintext epoch", contentType: protocol.ContentTypeAlert, epoch: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			disallowed := fixedRecordForScannerTest(t, test.contentType, test.epoch, 0xdd)
			records, err := UnpackDatagram(disallowed, UnpackDatagramConfig{})
			require.Error(t, err)
			require.Empty(t, records)
		})
	}
}

func TestUnpackDatagramRejectsRequiredCIDWithoutLength(t *testing.T) {
	records, err := UnpackDatagram(nil, UnpackDatagramConfig{
		CIDRequired: true,
	})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
	require.Nil(t, records)
}

func TestUnpackDatagramRequiresCIDPerDatagram(t *testing.T) {
	cid := []byte{0xca, 0xfe, 0xba, 0xbe}
	fixed := fixedRecordForScannerTest(t, protocol.ContentTypeHandshake, 0, 0xa1)
	cidless := unifiedRecordForScannerTest(t, nil, 1)
	withCID := unifiedRecordForScannerTest(t, cid, 2)
	config := UnpackDatagramConfig{
		CIDLength:   len(cid),
		CIDRequired: true,
	}

	datagram := append(append(append([]byte{}, fixed...), cidless...), withCID...)
	records, err := UnpackDatagram(datagram, config)
	require.NoError(t, err)
	require.Equal(t, [][]byte{fixed, cidless, withCID}, records)

	datagramWithoutCID := append(append([]byte{}, fixed...), cidless...)
	records, err = UnpackDatagram(datagramWithoutCID, config)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
	require.Nil(t, records)

	// DTLSPlaintext has no CID field. A peer may retransmit an epoch-zero
	// handshake record after the local endpoint has committed the negotiated
	// CID, so a plaintext-only datagram remains eligible.
	records, err = UnpackDatagram(fixed, config)
	require.NoError(t, err)
	require.Equal(t, [][]byte{fixed}, records)
}

func TestUnpackDatagramAllowsCIDLessUnifiedWithConfiguredCIDLength(t *testing.T) {
	raw, err := MarshalCiphertext(CiphertextConfig{SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xaa))
	require.NoError(t, err)

	records, err := UnpackDatagram(raw, UnpackDatagramConfig{CIDLength: 4})
	require.NoError(t, err)
	require.Equal(t, [][]byte{raw}, records)
}

func TestUnpackDatagramRejectsUnifiedCIDWithoutConfiguredLength(t *testing.T) {
	raw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: []byte{1, 2, 3, 4}, SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xaa))
	require.NoError(t, err)

	_, err = UnpackDatagram(raw, UnpackDatagramConfig{})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
}

func TestUnpackDatagramRejectsTruncatedUnifiedCID(t *testing.T) {
	_, err := UnpackDatagram([]byte{0x30, 0x01, 0x02}, UnpackDatagramConfig{CIDLength: 4})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
}

func TestUnpackDatagramDoesNotApplyCIDAssociationPolicy(t *testing.T) {
	firstRaw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: []byte{1, 2, 3, 4}, SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xaa))
	require.NoError(t, err)

	secondRaw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: []byte{4, 3, 2, 1}, SequenceNumber: 2, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xba))
	require.NoError(t, err)

	records, err := UnpackDatagram(
		append(append([]byte{}, firstRaw...), secondRaw...),
		UnpackDatagramConfig{CIDLength: 4},
	)
	require.NoError(t, err)
	require.Equal(t, [][]byte{firstRaw, secondRaw}, records)
}

func TestUnpackDatagramAllRecordForms(t *testing.T) {
	fixedRaw, err := MarshalRecord(RecordConfig{ContentType: protocol.ContentTypeAlert, Version: protocol.Version1_2}, []byte{1, 0})
	require.NoError(t, err)

	cid := []byte{0xca, 0xfe}

	unifiedRaw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: cid, SequenceNumber: 3, TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(0xc3))
	require.NoError(t, err)

	datagram := append(append([]byte{}, fixedRaw...), unifiedRaw...)
	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{CIDLength: len(cid)})
	require.NoError(t, err)
	require.Equal(t, [][]byte{fixedRaw, unifiedRaw}, records)

	records, err = UnpackDatagram(datagram, UnpackDatagramConfig{})
	require.ErrorIs(t, err, ErrInvalidPacketLength)
	require.Equal(t, [][]byte{fixedRaw}, records)

	records, err = UnpackDatagram(
		datagram[:len(datagram)-1],
		UnpackDatagramConfig{CIDLength: len(cid)},
	)
	require.ErrorIs(t, err, ErrInvalidPacketLength)
	require.Equal(t, [][]byte{fixedRaw}, records)
}

func TestUnpackDatagramOmittedUnifiedLengthConsumesRemainder(t *testing.T) {
	omitted := append([]byte{recordwire.UnifiedFixedBits, 0x01}, ciphertext13Payload(0xaa)...)

	following, err := MarshalRecord(RecordConfig{ContentType: protocol.ContentTypeApplicationData, Version: protocol.Version1_2}, []byte{0xbb})
	require.NoError(t, err)

	datagram := append(append([]byte{}, omitted...), following...)
	records, err := UnpackDatagram(datagram, UnpackDatagramConfig{})
	require.NoError(t, err)
	require.Equal(t, [][]byte{datagram}, records)
}

func fixedRecordForScannerTest(t *testing.T, contentType protocol.ContentType, epoch uint16, payload byte) []byte {
	t.Helper()
	raw, err := MarshalRecord(RecordConfig{ContentType: contentType, Version: protocol.Version1_2, Epoch: epoch}, []byte{payload})
	require.NoError(t, err)

	return raw
}

func unifiedRecordForScannerTest(t *testing.T, cid []byte, sequenceNumber uint8) []byte {
	t.Helper()
	raw, err := MarshalCiphertext(CiphertextConfig{ConnectionID: cid, SequenceNumber: uint16(sequenceNumber), TwoByteSequence: true, LengthPresent: true}, ciphertext13Payload(sequenceNumber))
	require.NoError(t, err)

	return raw
}
