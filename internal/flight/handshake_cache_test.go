// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight_test

import (
	"testing"

	cryptosuite "github.com/pion/dtls/v4/internal/crypto/ciphersuite"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/protocol"
	"github.com/pion/dtls/v4/internal/protocol/alert"
	"github.com/pion/dtls/v4/internal/protocol/extension"
	"github.com/pion/dtls/v4/internal/protocol/handshake"
	handshake13 "github.com/pion/dtls/v4/internal/protocol/handshake/dtls13"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cacheItem(typ handshake.Type, client bool, epoch uint64, sequence uint16, data byte) dtlsflight.HandshakeCacheItem {
	return dtlsflight.HandshakeCacheItem{Typ: typ, IsClient: client, Epoch: epoch, MessageSequence: sequence, Data: []byte{data}}
}

func cacheRule(typ handshake.Type, client bool, epoch uint64) dtlsflight.HandshakeCachePullRule {
	return dtlsflight.HandshakeCachePullRule{Typ: typ, Epoch: epoch, IsClient: client}
}

func TestHandshakeCacheSinglePush(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []dtlsflight.HandshakeCachePullRule
		Input    []dtlsflight.HandshakeCacheItem
		Expected []byte
	}{
		{Name: "Single Push", Input: []dtlsflight.HandshakeCacheItem{cacheItem(0, true, 0, 0, 0)}, Rule: []dtlsflight.HandshakeCachePullRule{cacheRule(0, true, 0)}, Expected: []byte{0x00}},
		{Name: "Multi Push", Input: []dtlsflight.HandshakeCacheItem{cacheItem(0, true, 0, 0, 0), cacheItem(1, true, 0, 1, 1), cacheItem(2, true, 0, 2, 2)}, Rule: []dtlsflight.HandshakeCachePullRule{cacheRule(0, true, 0), cacheRule(1, true, 0), cacheRule(2, true, 0)}, Expected: []byte{0x00, 0x01, 0x02}},
		{
			Name:  "Multi Push, Rules set order",
			Input: []dtlsflight.HandshakeCacheItem{cacheItem(2, true, 0, 2, 2), cacheItem(0, true, 0, 0, 0), cacheItem(1, true, 0, 1, 1)},
			Rule: []dtlsflight.HandshakeCachePullRule{
				cacheRule(0, true, 0), cacheRule(1, true, 0), cacheRule(2, true, 0),
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},

		{Name: "Multi Push, Dupe Seqnum", Input: []dtlsflight.HandshakeCacheItem{cacheItem(0, true, 0, 0, 0), cacheItem(1, true, 0, 1, 1), cacheItem(1, true, 0, 1, 1)}, Rule: []dtlsflight.HandshakeCachePullRule{cacheRule(0, true, 0), cacheRule(1, true, 0)}, Expected: []byte{0x00, 0x01}},
		{
			Name:  "Multi Push, Dupe Seqnum Client/Server",
			Input: []dtlsflight.HandshakeCacheItem{cacheItem(0, true, 0, 0, 0), cacheItem(1, true, 0, 1, 1), cacheItem(1, false, 0, 1, 2)},
			Rule: []dtlsflight.HandshakeCachePullRule{
				cacheRule(0, true, 0), cacheRule(1, true, 0), cacheRule(1, false, 0),
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name:  "Multi Push, Dupe Seqnum with Unique HandshakeType",
			Input: []dtlsflight.HandshakeCacheItem{cacheItem(1, true, 0, 0, 0), cacheItem(2, true, 0, 1, 1), cacheItem(3, false, 0, 0, 2)},
			Rule: []dtlsflight.HandshakeCachePullRule{
				cacheRule(1, true, 0), cacheRule(2, true, 0), cacheRule(3, false, 0),
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name:  "Multi Push, Wrong epoch",
			Input: []dtlsflight.HandshakeCacheItem{cacheItem(1, true, 0, 0, 0), cacheItem(2, true, 1, 1, 1), cacheItem(2, true, 0, 2, 0x11), cacheItem(3, false, 0, 0, 2), cacheItem(3, false, 1, 0, 0x12), cacheItem(3, false, 2, 0, 0x12)},
			Rule: []dtlsflight.HandshakeCachePullRule{
				cacheRule(1, true, 0), cacheRule(2, true, 1), cacheRule(3, false, 0),
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name:     "Full Width Epoch",
			Input:    []dtlsflight.HandshakeCacheItem{cacheItem(1, true, 3, 0, 0), cacheItem(1, true, 1<<32+3, 1, 1)},
			Rule:     []dtlsflight.HandshakeCachePullRule{cacheRule(1, true, 1<<32+3)},
			Expected: []byte{1},
		},
	} {
		h := dtlsflight.NewCache()
		for _, i := range test.Input {
			h.Push(i.Data, i.Epoch, i.MessageSequence, i.Typ, i.IsClient)
		}
		verifyData := h.PullAndMerge(test.Rule...)
		assert.Equal(t, test.Expected, verifyData)
	}
}

func TestHandshakeCachePullExact(t *testing.T) {
	cache := dtlsflight.NewCache()
	cache.Push([]byte{1}, 2, 3, handshake.TypeFinished, true)
	cache.Push([]byte{2}, 2, 3, handshake.TypeNewSessionTicket, false)

	item, ok := cache.PullExact(3, false)
	require.True(t, ok)
	assert.Equal(t, handshake.TypeNewSessionTicket, item.Typ)
	assert.Equal(t, []byte{2}, item.Data)

	_, ok = cache.PullExact(4, false)
	assert.False(t, ok)
	cache.Push([]byte{3}, 3, 4, handshake.TypeNewSessionTicket, false)
	cache.DiscardBefore(3, 4, false)
	_, ok = cache.PullExact(3, true)
	assert.False(t, ok)
	_, ok = cache.PullExact(3, false)
	assert.False(t, ok)
	item, ok = cache.PullExact(4, false)
	require.True(t, ok)
	assert.Equal(t, []byte{3}, item.Data)
}

func TestHandshakeCachePushCopiesData(t *testing.T) {
	data := []byte{1, 2, 3}
	cache := dtlsflight.NewCache()
	cache.Push(data, 0, 0, handshake.TypeFinished, true)
	data[0] = 9

	item, ok := cache.PullExact(0, true)
	require.True(t, ok)
	assert.Equal(t, []byte{1, 2, 3}, item.Data)
}

func TestHandshakeCacheFullPullMapItemsReturnsAcceptedRawItems(t *testing.T) {
	cipherSuiteID := uint16(cryptosuite.TLS_AES_128_GCM_SHA256)
	rawClientHello := marshalHandshakeCacheTestMessage(t, 0, &handshake.MessageClientHello{Version: protocol.Version1_2, CipherSuiteIDs: []uint16{uint16(cryptosuite.TLS_AES_128_GCM_SHA256)}, CompressionMethods: dtlsflight.DefaultCompressionMethods()})
	rawServerHello := marshalHandshakeCacheTestMessage(t, 1, &handshake.MessageServerHello{Version: protocol.Version1_2, CipherSuiteID: &cipherSuiteID, CompressionMethod: dtlsflight.DefaultCompressionMethods()[0]})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, 0, 1, handshake.TypeServerHello, false)
	cache.Push(rawClientHello, 0, 0, handshake.TypeClientHello, true)

	pull := cache.FullPullMapItems(0,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: 0, IsClient: false, Optional: false},
	)

	require.NoError(t, pull.Err)
	require.True(t, pull.Ready)
	assert.Equal(t, 2, pull.NextSequence)
	require.IsType(t, &handshake.MessageClientHello{}, pull.Messages[handshake.TypeClientHello])
	require.IsType(t, &handshake.MessageServerHello{}, pull.Messages[handshake.TypeServerHello])
	require.Len(t, pull.Items, 2)
	assert.Equal(t, rawClientHello, pull.Items[0].Raw.Data)
	assert.Equal(t, rawServerHello, pull.Items[1].Raw.Data)
	require.NotNil(t, pull.Items[0].Parsed)
	require.NotNil(t, pull.Items[1].Parsed)
	assert.Same(t, pull.Messages[handshake.TypeClientHello], pull.Items[0].Parsed.Message)
	assert.Same(t, pull.Messages[handshake.TypeServerHello], pull.Items[1].Parsed.Message)

	secondPull := cache.FullPullMapItems(0,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false},
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: 0, IsClient: false, Optional: false},
	)
	require.NoError(t, secondPull.Err)
	require.True(t, secondPull.Ready)
	assert.Same(t, pull.Items[0].Parsed, secondPull.Items[0].Parsed)
	assert.Same(t, pull.Items[1].Parsed, secondPull.Items[1].Parsed)
}

func TestHandshakeCachePullResultDistinguishesIncompleteAndMalformed(t *testing.T) {
	rule := dtlsflight.HandshakeCachePullRule{
		Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false,
	}

	t.Run("missing", func(t *testing.T) {
		pull := dtlsflight.NewCache().FullPullMapItems(7, rule)
		assert.False(t, pull.Ready)
		assert.NoError(t, pull.Err)
		assert.Equal(t, 7, pull.NextSequence)
	})

	t.Run("sequence gap", func(t *testing.T) {
		raw := marshalHandshakeCacheTestMessage(t, 1, &handshake.MessageClientHello{Version: protocol.Version1_2, CompressionMethods: dtlsflight.DefaultCompressionMethods()})
		cache := dtlsflight.NewCache()
		cache.Push(raw, 0, 1, handshake.TypeClientHello, true)

		pull := cache.FullPullMapItems(0, rule)
		assert.False(t, pull.Ready)
		assert.NoError(t, pull.Err)
		assert.Equal(t, 0, pull.NextSequence)
	})

	t.Run("malformed complete message", func(t *testing.T) {
		cache := dtlsflight.NewCache()
		cache.Push([]byte{byte(handshake.TypeClientHello)}, 0, 0, handshake.TypeClientHello, true)

		pull := cache.FullPullMapItems(0, rule)
		assert.True(t, pull.Ready)
		assert.ErrorIs(t, pull.Err, dtlserrors.ErrBufferTooSmall)
		var got *alert.Alert
		require.ErrorAs(t, pull.Err, &got)
		assert.Equal(t, alert.DecodeError, got.Description)
	})
}

func TestHandshakeCachePullValidatesMetadataAndHeader(t *testing.T) {
	valid := marshalHandshakeCacheTestMessage(t, 0, &handshake.MessageClientHello{Version: protocol.Version1_2, CompressionMethods: dtlsflight.DefaultCompressionMethods()})
	rule := dtlsflight.HandshakeCachePullRule{
		Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false,
	}

	tests := map[string]struct {
		data []byte
		typ  handshake.Type
		seq  uint16
	}{
		"header sequence": {data: marshalHandshakeCacheTestMessage(t, 1, &handshake.MessageClientHello{Version: protocol.Version1_2, CompressionMethods: dtlsflight.DefaultCompressionMethods()}), typ: handshake.TypeClientHello},
		"header type":     {data: marshalHandshakeCacheTestMessage(t, 0, &handshake.MessageServerHello{Version: protocol.Version1_2, CipherSuiteID: new(uint16), CompressionMethod: dtlsflight.DefaultCompressionMethods()[0]}), typ: handshake.TypeClientHello},
		"fragment offset": {
			data: func() []byte {
				data := append([]byte(nil), valid...)
				data[8] = 1

				return data
			}(),
			typ: handshake.TypeClientHello,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cache := dtlsflight.NewCache()
			cache.Push(test.data, 0, test.seq, test.typ, true)

			pull := cache.FullPullMapItems(0, rule)
			require.True(t, pull.Ready)
			assert.ErrorIs(t, pull.Err, dtlserrors.ErrInvalidHandshakeTranscriptMessage)
			var got *alert.Alert
			require.ErrorAs(t, pull.Err, &got)
			assert.Equal(t, alert.DecodeError, got.Description)
		})
	}
}

func TestHandshakeCachePullPreservesExtensionAlert(t *testing.T) {
	raw := marshalHandshakeCacheTestMessage(t, 0, &handshake.MessageClientHello{Version: protocol.Version1_2, CompressionMethods: dtlsflight.DefaultCompressionMethods(), Extensions: []extension.Value{extension.Raw{Type: 0xfefe}, extension.Raw{Type: 0xfefe}}})
	cache := dtlsflight.NewCache()
	cache.Push(raw, 0, 0, handshake.TypeClientHello, true)

	pull := cache.FullPullMapItems(0, dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false})
	require.True(t, pull.Ready)
	assert.ErrorIs(t, pull.Err, dtlserrors.ErrDuplicateExtension)
	var got *alert.Alert
	require.ErrorAs(t, pull.Err, &got)
	assert.Equal(t, alert.IllegalParameter, got.Description)
}

func TestHandshakeCachePullRejectsUnexpectedMessageAtRequiredSequence(t *testing.T) {
	cache := dtlsflight.NewCache()
	cache.Push([]byte{byte(handshake.TypeServerHello)}, 0, 0, handshake.TypeServerHello, true)

	pull := cache.FullPullMapItems(0, dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false})
	require.True(t, pull.Ready)
	assert.ErrorIs(t, pull.Err, dtlserrors.ErrUnexpectedHandshakeMessage)
	var got *alert.Alert
	require.ErrorAs(t, pull.Err, &got)
	assert.Equal(t, alert.UnexpectedMessage, got.Description)
}

func TestHandshakeCachePullOptionalRules(t *testing.T) {
	optionalRule := dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeNewSessionTicket, Epoch: 0, IsClient: false, Optional: true}
	serverHelloRule := dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: 0, IsClient: false, Optional: true}

	t.Run("skip to later rule", func(t *testing.T) {
		cipherSuiteID := uint16(cryptosuite.TLS_AES_128_GCM_SHA256)
		raw := marshalHandshakeCacheTestMessage(t, 0, &handshake.MessageServerHello{Version: protocol.Version1_2, CipherSuiteID: &cipherSuiteID, CompressionMethod: dtlsflight.DefaultCompressionMethods()[0]})
		cache := dtlsflight.NewCache()
		cache.Push(raw, 0, 0, handshake.TypeServerHello, false)

		pull := cache.FullPullMapItems(0, optionalRule, serverHelloRule)
		require.NoError(t, pull.Err)
		require.True(t, pull.Ready)
		require.IsType(t, &handshake.MessageServerHello{}, pull.Messages[handshake.TypeServerHello])
	})

	t.Run("unexpected message", func(t *testing.T) {
		raw := marshalHandshakeCacheTestMessage(t, 0, &handshake13.MessageCertificate{})
		cache := dtlsflight.NewCache()
		cache.Push(raw, 0, 0, handshake.TypeCertificate, false)

		pull := cache.FullPullMapItems(0, optionalRule, serverHelloRule)
		require.True(t, pull.Ready)
		assert.ErrorIs(t, pull.Err, dtlserrors.ErrUnexpectedHandshakeMessage)
		var got *alert.Alert
		require.ErrorAs(t, pull.Err, &got)
		assert.Equal(t, alert.UnexpectedMessage, got.Description)
	})
}

func TestHandshakeCachePullRejectsSequenceOverflow(t *testing.T) {
	rule := dtlsflight.HandshakeCachePullRule{
		Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false,
	}
	pull := dtlsflight.NewCache().FullPullMapItems(-1, rule)
	require.True(t, pull.Ready)
	assert.ErrorIs(t, pull.Err, dtlserrors.ErrHandshakeSequenceOverflow)
	var got *alert.Alert
	require.ErrorAs(t, pull.Err, &got)
	assert.Equal(t, alert.DecodeError, got.Description)
}

func marshalHandshakeCacheTestMessage(t *testing.T, seq uint16, message handshake.Message) []byte {
	t.Helper()

	raw, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: seq},
		Message: message,
	}).Marshal()
	require.NoError(t, err)

	return raw
}
