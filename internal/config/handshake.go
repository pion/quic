// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package config contains internal handshake configuration.
package config

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	cryptosuite "github.com/pion/dtls/v4/internal/crypto/ciphersuite"
	"github.com/pion/dtls/v4/internal/crypto/elliptic"
	"github.com/pion/dtls/v4/internal/crypto/signaturehash"
	"github.com/pion/dtls/v4/internal/ech"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlscrypto "github.com/pion/dtls/v4/internal/handshakecrypto"
	"github.com/pion/dtls/v4/internal/protocol/extension"
	"github.com/pion/dtls/v4/internal/protocol/handshake"
	internalstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/logging"
)

type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

type (
	CipherSuite           = cryptosuite.Suite
	SRTPProtectionProfile = extension.SRTPProtectionProfile
)

type ClientHelloInfo struct {
	ServerName        string
	CipherSuites      []cryptosuite.ID
	RandomBytes       [handshake.RandomBytesLength]byte
	Hello             *handshake.MessageClientHello
	HelloRetryRequest bool
	Context           func() context.Context
	Conn              net.Conn
}

type CertificateRequestInfo struct {
	AcceptableCAs    [][]byte
	SignatureSchemes []signaturehash.Algorithm
}

func (cri *CertificateRequestInfo) SupportsCertificate(certificate *tls.Certificate) error {
	if len(cri.SignatureSchemes) > 0 {
		if _, err := signaturehash.SelectSignatureScheme(cri.SignatureSchemes, certificate.PrivateKey); err != nil {
			return err
		}
	}

	return SupportsCertificate(cri.AcceptableCAs, certificate)
}

func SupportsCertificate(acceptableCAs [][]byte, c *tls.Certificate) error {
	if len(acceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf
		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range acceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}

	return dtlserrors.ErrNotAcceptableCertificateChain
}

type HandshakeConfig struct {
	// ECHConfigList enables initial-offer construction internally.
	ECHConfigList      []byte
	ECHKeys            []ech.Key
	GetECHKeys         func(*ClientHelloInfo) ([]ech.Key, error)
	ECHRejectionVerify func(internalstate.Active) error
	PSKIdentityLimit   int
	// SelectPSK returns the selected offer index, key, and hash, or a nil key if none match.
	SelectPSK                     func(identities [][]byte) (index int, key []byte, hash crypto.Hash, err error)
	GetPSKs                       func() ([]internalstate.PSK, error)
	LocalCipherSuites             []CipherSuite
	LocalSignatureSchemes         []signaturehash.Algorithm
	LocalCertSignatureSchemes     []signaturehash.Algorithm
	LocalSRTPProtectionProfiles   []SRTPProtectionProfile
	LocalSRTPMasterKeyIdentifier  []byte
	ServerName                    string
	SupportedProtocols            []string
	ClientAuth                    ClientAuthType
	LocalCertificates             []tls.Certificate
	InsecureSkipVerify            bool
	VerifyPeerCertificate         func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	VerifyConnection              func(internalstate.Active) error
	MaxEarlyDataSize              uint32
	EnableEarlyData               bool
	ClaimEarlyData                func(ticket []byte, expiresAt time.Time) (bool, error)
	SetSessionTicket              func(key, id, secret, identity []byte, ticket internalstate.SessionTicket) error
	GetSessionTicket              func(key []byte, serverName string) (*internalstate.PSK, error)
	RootCAs                       *x509.CertPool
	ClientCAs                     *x509.CertPool
	InitialRetransmitInterval     time.Duration
	DisableRetransmitBackoff      bool
	EllipticCurves                []elliptic.Curve
	InsecureSkipHelloVerify       bool
	ReceiveCIDLength              int
	ConnectionIDGenerator         func() []byte
	EnableRRC                     bool
	HelloRandomBytesGenerator     func() [handshake.RandomBytesLength]byte
	Log                           logging.LeveledLogger
	KeyLogWriter                  io.Writer
	LocalGetCertificate           func(*ClientHelloInfo) (*tls.Certificate, error)
	LocalGetClientCertificate     func(*CertificateRequestInfo) (*tls.Certificate, error)
	InitialEpoch                  uint64
	ClientHelloMessageHook        func(handshake.MessageClientHello) handshake.Message
	ServerHelloMessageHook        func(handshake.MessageServerHello) handshake.Message
	CertificateRequestMessageHook func(handshake.Message) handshake.Message
	ResumeState                   internalstate.Active
	TimerFactory                  func(time.Duration) Timer

	nameToCertificate map[string]*tls.Certificate
	mu                sync.Mutex
}

// GenerateConnectionID returns a CID matching the configured receive length.
func (c *HandshakeConfig) GenerateConnectionID() ([]byte, error) {
	cid := c.ConnectionIDGenerator()
	if len(cid) != c.ReceiveCIDLength {
		return nil, fmt.Errorf("%w: generator returned %d bytes, want %d", dtlserrors.ErrInvalidConnectionIDLength, len(cid), c.ReceiveCIDLength)
	}

	return cid, nil
}

// Timer is the timer surface used by the handshake state machines.
type Timer interface {
	C() <-chan time.Time
	Stop()
}

type systemTimer struct {
	timer *time.Timer
}

func (t *systemTimer) C() <-chan time.Time {
	return t.timer.C
}

func (t *systemTimer) Stop() {
	t.timer.Stop()
}

// NewTimer returns a handshake timer.
func (c *HandshakeConfig) NewTimer(d time.Duration) Timer {
	if c.TimerFactory != nil {
		return c.TimerFactory(d)
	}

	return &systemTimer{timer: time.NewTimer(d)}
}

func (c *HandshakeConfig) WriteKeyLog(label string, clientRandom, secret []byte) {
	if c.KeyLogWriter == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := fmt.Fprintf(c.KeyLogWriter, "%s %x %x\n", label, clientRandom, secret)
	if err != nil {
		c.Log.Debugf("failed to write key log file: %s", err)
	}
}

func (c *HandshakeConfig) setNameToCertificateLocked() {
	nameToCertificate := make(map[string]*tls.Certificate)
	for i := range c.LocalCertificates {
		cert := &c.LocalCertificates[i]
		x509Cert := cert.Leaf
		if x509Cert == nil {
			var parseErr error
			x509Cert, parseErr = x509.ParseCertificate(cert.Certificate[0])
			if parseErr != nil {
				continue
			}
		}
		if len(x509Cert.Subject.CommonName) > 0 {
			nameToCertificate[strings.ToLower(x509Cert.Subject.CommonName)] = cert
		}
		for _, san := range x509Cert.DNSNames {
			nameToCertificate[strings.ToLower(san)] = cert
		}
	}
	c.nameToCertificate = nameToCertificate
}

func (c *HandshakeConfig) GetCertificate(clientHelloInfo *ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.shouldGetCertificateFromCallbackLocked(clientHelloInfo) {
		cert, err := c.LocalGetCertificate(clientHelloInfo)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if c.nameToCertificate == nil {
		c.setNameToCertificateLocked()
	}

	if len(c.LocalCertificates) == 0 {
		return nil, dtlserrors.ErrNoCertificates
	}

	if len(c.LocalCertificates) == 1 {
		return &c.LocalCertificates[0], nil
	}

	if len(clientHelloInfo.ServerName) == 0 {
		return &c.LocalCertificates[0], nil
	}

	if cert := c.getCertificateForNameLocked(clientHelloInfo.ServerName); cert != nil {
		return cert, nil
	}

	return &c.LocalCertificates[0], nil
}

func (c *HandshakeConfig) shouldGetCertificateFromCallbackLocked(clientHelloInfo *ClientHelloInfo) bool {
	if c.LocalGetCertificate == nil {
		return false
	}

	return len(c.LocalCertificates) == 0 || len(clientHelloInfo.ServerName) > 0
}

func (c *HandshakeConfig) getCertificateForNameLocked(serverName string) *tls.Certificate {
	name := strings.TrimRight(strings.ToLower(serverName), ".")

	if cert, ok := c.nameToCertificate[name]; ok {
		return cert
	}

	// A certificate wildcard replaces only the left-most DNS label.
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		candidate := "*" + name[dot:]
		if cert, ok := c.nameToCertificate[candidate]; ok {
			return cert
		}
	}

	return nil
}

func (c *HandshakeConfig) GetClientCertificate(cri *CertificateRequestInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.LocalGetClientCertificate != nil {
		return c.LocalGetClientCertificate(cri)
	}

	for i := range c.LocalCertificates {
		chain := c.LocalCertificates[i]
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}

		return &chain, nil
	}

	return new(tls.Certificate), nil
}

// SendServerName omits IP literals from SNI while retaining them for verification.
func (c *HandshakeConfig) SendServerName() bool {
	return len(c.ServerName) > 0 && net.ParseIP(c.ServerName) == nil
}

func (c *HandshakeConfig) UsableServerCertificate(raw [][]byte) bool {
	if len(raw) == 0 {
		return false
	}
	chains, err := c.verifySessionCertificate(raw)
	if err != nil {
		return false
	}

	return c.VerifyPeerCertificate == nil || c.VerifyPeerCertificate(raw, chains) == nil
}

func (c *HandshakeConfig) verifySessionCertificate(raw [][]byte) ([][]*x509.Certificate, error) {
	if c.InsecureSkipVerify {
		return nil, nil
	} //nolint:nilnil // Verification was explicitly disabled.
	algs := c.LocalCertSignatureSchemes
	if len(algs) == 0 {
		algs = c.LocalSignatureSchemes
	}

	return dtlscrypto.VerifyServerCert(raw, c.RootCAs, c.ServerName, algs)
}
