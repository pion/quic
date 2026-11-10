// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"encoding/gob"
	"testing"
	"time"

	cryptosuite "github.com/pion/dtls/v4/internal/crypto/ciphersuite"
	"github.com/pion/dtls/v4/internal/crypto/selfsign"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/internal/protocol"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/stretchr/testify/require"
)

func TestStateRoundTripPreservesNegotiatedExtensions(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	client, server := handshakePair(t, []ClientOption{
		WithInsecureSkipVerify(true),
		WithConnectionID(func() []byte { return []byte("client") }, CIDPathMigrationRRC),
		WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
		WithSRTPMasterKeyIdentifier([]byte{1}),
	}, []ServerOption{
		WithCertificates(cert),
		WithConnectionID(func() []byte { return []byte("server") }, CIDPathMigrationRRC),
		WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
		WithSRTPMasterKeyIdentifier([]byte{2}),
	})
	require.NoError(t, client.configErr)
	require.NoError(t, server.configErr)
	require.NoError(t, client.handshakeError)
	require.NoError(t, server.handshakeError)
	t.Cleanup(func() { _ = client.conn.Close(); _ = server.conn.Close() })
	peerMKI := bytes.Clone(dtlsstate.CommonState(server.conn.state).RemoteSRTPMasterKeyIdentifier)
	require.Equal(t, []byte{1}, peerMKI)

	state, err := server.conn.ExportState()
	require.NoError(t, err)
	data, err := state.MarshalBinary()
	require.NoError(t, err)
	var restored State
	require.NoError(t, restored.UnmarshalBinary(data))
	require.Equal(t, peerMKI, restored.peerSRTPMKI)
	require.True(t, restored.rrcNegotiated)
	require.Equal(t, SRTP_AES128_CM_HMAC_SHA1_80, restored.srtpProtectionProfile)
}

func TestUnmarshalBinaryRejectsDTLS12State(t *testing.T) {
	for _, version := range []protocol.Version{0, protocol.Version1_2} {
		var buf bytes.Buffer
		require.NoError(t, gob.NewEncoder(&buf).Encode(serializedState{Version: version, CipherSuiteID: 0xc02b}))
		var state State
		require.ErrorIs(t, state.UnmarshalBinary(buf.Bytes()), dtlserrors.ErrInvalidProtocolVersionState)
	}
}

func TestResume(t *testing.T) {
	for _, test := range []struct {
		name    string
		version protocol.Version
		suite   cryptosuite.ID
	}{
		{"DTLS13/AES128", protocol.Version1_3, cryptosuite.TLS_AES_128_GCM_SHA256},
		{"DTLS13/AES256", protocol.Version1_3, cryptosuite.TLS_AES_256_GCM_SHA384},
		{"DTLS13/ChaCha20", protocol.Version1_3, cryptosuite.TLS_CHACHA20_POLY1305_SHA256},
	} {
		for mode, binary := range map[string]bool{"State": false, "Binary": true} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				cert, err := selfsign.GenerateSelfSigned()
				require.NoError(t, err)
				client, server := handshakePair(t, []ClientOption{
					WithInsecureSkipVerify(true), WithCipherSuites(test.suite),
					WithConnectionID(func() []byte { return []byte("client") }, CIDPathMigrationReject),
					WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
					WithSRTPMasterKeyIdentifier([]byte{1}),
				}, []ServerOption{
					WithCertificates(cert), WithCipherSuites(test.suite),
					WithConnectionID(func() []byte { return []byte("server") }, CIDPathMigrationReject),
					WithSRTPProtectionProfiles(SRTP_AES128_CM_HMAC_SHA1_80),
					WithSRTPMasterKeyIdentifier([]byte{2}),
				})
				require.NoError(t, client.configErr)
				require.NoError(t, server.configErr)
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				exchangeResumeData(t, client.conn, server.conn)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if test.version == protocol.Version1_3 {
					// Exercise independent read/write epochs and retain an older key.
					require.NoError(t, client.conn.UpdateKeys(ctx, KeyUpdateOptions{}))
					exchangeResumeData(t, client.conn, server.conn)
				}
				inspection, ok := client.conn.ConnectionState()
				require.True(t, ok)
				_, err = Resume(&inspection, nil, nil)
				require.ErrorIs(t, err, dtlserrors.ErrInvalidExportedState)
				data, err := inspection.MarshalBinary()
				require.NoError(t, err)
				require.NoError(t, inspection.UnmarshalBinary(data))
				_, err = Resume(&inspection, nil, nil)
				require.ErrorIs(t, err, dtlserrors.ErrInvalidExportedState)
				exchangeResumeData(t, client.conn, server.conn)
				clientState, err := client.conn.ExportState()
				require.NoError(t, err)
				serverState, err := server.conn.ExportState()
				require.NoError(t, err)
				for _, state := range []*State{&clientState, &serverState} {
					data, marshalErr := state.MarshalBinary()
					require.NoError(t, marshalErr)
					if binary {
						*state = State{}
						require.NoError(t, state.UnmarshalBinary(data))
					}
				}
				require.NoError(t, client.conn.Close())
				require.NoError(t, server.conn.Close())
				_, err = client.conn.Write([]byte("after export"))
				require.ErrorIs(t, err, ErrConnClosed)
				require.Equal(t, clientState.sequenceNumber, dtlsstate.CommonState(client.conn.state).NextLocalSequenceNumber(clientState.localEpoch))
				_, err = client.conn.ExportState()
				require.ErrorIs(t, err, dtlserrors.ErrInvalidExportedState)
				exported, err := clientState.ExportKeyingMaterial("resume-test", nil, 32)
				require.NoError(t, err)
				ca, cb := packetPipe()
				t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
				resumedClient, err := Resume(&clientState, ca, ca.RemoteAddr())
				require.NoError(t, err)
				t.Cleanup(func() { _ = resumedClient.Close() })
				_, err = Resume(&clientState, ca, ca.RemoteAddr())
				require.ErrorIs(t, err, dtlserrors.ErrInvalidExportedState)
				_, err = clientState.MarshalBinary()
				require.ErrorIs(t, err, dtlserrors.ErrInvalidExportedState)
				resumedServer, err := Resume(&serverState, cb, cb.RemoteAddr())
				require.NoError(t, err)
				t.Cleanup(func() { _ = resumedServer.Close() })
				// Each endpoint must restore without waiting for a new handshake.
				require.NoError(t, resumedClient.HandshakeContext(ctx))
				require.NoError(t, resumedServer.HandshakeContext(ctx))
				restored, ok := resumedClient.ConnectionState()
				require.True(t, ok)
				require.Equal(t, test.version, restored.NegotiatedVersion())
				actual, err := restored.ExportKeyingMaterial("resume-test", nil, 32)
				require.NoError(t, err)
				require.Equal(t, exported, actual)
				if test.version == protocol.Version1_3 {
					state, is13 := resumedServer.state.(*dtlsstate.State13)
					require.True(t, is13)
					for epoch, cutoff := range state.ReplayCutoff {
						_, accepted := resumedServer.replayMarker(epoch, cutoff, ^uint64(0))
						require.False(t, accepted, "previously received records must remain rejected")
					}
				}
				exchangeResumeData(t, resumedClient, resumedServer)
				if test.version == protocol.Version1_3 {
					require.NoError(t, resumedServer.UpdateKeys(ctx, KeyUpdateOptions{}))
					require.NoError(t, resumedClient.UpdateKeys(ctx, KeyUpdateOptions{}))
					exchangeResumeData(t, resumedClient, resumedServer)
				}
			})
		}
	}
}

func exchangeResumeData(t *testing.T, client, server *Conn) {
	t.Helper()
	for _, pair := range [][2]*Conn{{client, server}, {server, client}} {
		require.NoError(t, pair[0].SetWriteDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, pair[1].SetReadDeadline(time.Now().Add(5*time.Second)))
		written := make(chan error, 1)
		go func() { _, err := pair[0].Write([]byte("resumed data")); written <- err }()
		buffer := make([]byte, 100)
		n, err := pair[1].Read(buffer)
		require.NoError(t, err)
		require.Equal(t, "resumed data", string(buffer[:n]))
		require.NoError(t, <-written)
	}
}
