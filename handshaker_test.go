// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	cryptosuite "github.com/pion/dtls/v4/internal/crypto/ciphersuite"
	"github.com/pion/dtls/v4/internal/crypto/selfsign"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test that writes to the key log are in the correct format and only applies
// when a key log writer is given.
func TestWriteKeyLog(t *testing.T) {
	var buf bytes.Buffer
	cfg := dtlsconfig.HandshakeConfig{
		KeyLogWriter: &buf,
	}
	cfg.WriteKeyLog("LABEL", []byte{0xAA, 0xBB, 0xCC}, []byte{0xDD, 0xEE, 0xFF})

	// Secrets follow the format <Label> <space> <ClientRandom> <space> <Secret>
	// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
	want := "LABEL aabbcc ddeeff\n"
	assert.Equal(t, want, buf.String())

	// no key log writer = no writes
	cfg = dtlsconfig.HandshakeConfig{}
	cfg.WriteKeyLog("LABEL", []byte{0xAA, 0xBB, 0xCC}, []byte{0xDD, 0xEE, 0xFF})
}

const keyLogEarlyData = "early"

func TestKeyLog(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	for _, testCase := range []struct {
		name      string
		suites    []cryptosuite.ID
		scenarios []string
	}{
		{"DTLS13", []cryptosuite.ID{cryptosuite.TLS_AES_128_GCM_SHA256, cryptosuite.TLS_AES_256_GCM_SHA384, cryptosuite.TLS_CHACHA20_POLY1305_SHA256}, []string{"full", "retry", "resumed", keyLogEarlyData}},
	} {
		for _, suite := range testCase.suites {
			for _, scenario := range testCase.scenarios {
				t.Run(fmt.Sprintf("%s/%s/%s", testCase.name, suite, scenario), func(t *testing.T) {
					testKeyLogHandshake(t, certificate, suite, scenario)
				})
			}
		}
	}
}

func testKeyLogHandshake(t *testing.T, certificate tls.Certificate, suite cryptosuite.ID, scenario string) {
	t.Helper()
	var clientLog, serverLog bytes.Buffer
	clientOptions := []ClientOption{WithInsecureSkipVerify(true), WithCipherSuites(suite), WithKeyLogWriter(&clientLog)}
	serverOptions := []ServerOption{WithCertificates(certificate), WithCipherSuites(suite), WithKeyLogWriter(&serverLog), WithInsecureSkipVerifyHello(scenario != "retry")}
	if scenario == "resumed" || scenario == keyLogEarlyData {
		secretLen := 32
		if suite == cryptosuite.TLS_AES_256_GCM_SHA384 {
			secretLen = 48
		}
		ticket := Session{IsClient: true, ID: []byte("ticket"), Secret: bytes.Repeat([]byte{0x42}, secretLen), Ticket: &SessionTicket{CipherSuite: suite, CreatedAt: time.Now().Add(-time.Second), Lifetime: 60, MaxEarlyDataSize: 32, PeerCertificates: certificate.Certificate}}
		limit := uint32(0)
		if scenario == keyLogEarlyData {
			limit = 32
		}
		clientOptions = append(clientOptions, WithSessionStore(&earlyDataTestStore{session: ticket}, WithMaxEarlyDataSize(limit)))
		ticket.IsClient = false
		serverOptions = append(serverOptions, WithSessionStore(&earlyDataTestStore{session: ticket}, WithMaxEarlyDataSize(limit)))
	}
	client, err := DetachedClient(&net.UDPAddr{Port: 5555}, clientOptions...)
	require.NoError(t, err)
	server, err := DetachedServer(&net.UDPAddr{Port: 4444}, serverOptions...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, server.Start(ctx))
	require.NoError(t, client.Start(ctx))
	if scenario == keyLogEarlyData {
		_, err = client.WriteEarlyData([]byte(keyLogEarlyData))
		require.NoError(t, err)
	}
	pumpEarlyDataPair(t, client, server)
	require.True(t, client.established.Load())
	require.True(t, server.established.Load())
	assertKeyLog(t, client.conn.state, clientLog.String(), serverLog.String(), scenario)
}

func assertKeyLog(t *testing.T, clientState *dtlsstate.State13, clientLog, serverLog, scenario string) {
	t.Helper()
	require.NotNil(t, clientState)
	random := clientState.LocalRandom.MarshalFixed()
	hashSize := clientState.CipherSuite.HashFunc()().Size()
	if scenario == "resumed" || scenario == keyLogEarlyData {
		require.NotEmpty(t, clientState.PSK)
	}
	secrets := clientState.KeySchedule
	expected := map[string][]byte{
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET": secrets.HandshakeTraffic.Client,
		"SERVER_HANDSHAKE_TRAFFIC_SECRET": secrets.HandshakeTraffic.Server,
		"CLIENT_TRAFFIC_SECRET_0":         secrets.ClientApplicationTrafficSecret0,
		"SERVER_TRAFFIC_SECRET_0":         secrets.ServerApplicationTrafficSecret0,
		"EXPORTER_SECRET":                 secrets.ExporterMasterSecret,
	}
	early := scenario == keyLogEarlyData
	clientLines := strings.Split(strings.TrimSpace(clientLog), "\n")
	serverLines := strings.Split(strings.TrimSpace(serverLog), "\n")
	require.ElementsMatch(t, clientLines, serverLines)
	count := len(expected)
	if early {
		count++
	}
	require.Len(t, clientLines, count)
	for label, secret := range expected {
		require.NotEmpty(t, secret)
		require.Contains(t, clientLines, fmt.Sprintf("%s %x %x", label, random, secret))
	}
	if early {
		require.True(t, strings.HasPrefix(clientLines[0], fmt.Sprintf("CLIENT_EARLY_TRAFFIC_SECRET %x ", random)))
		require.Len(t, strings.Fields(clientLines[0])[2], hashSize*2)
	}
}
