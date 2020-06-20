// Package wrapper is a wrapper around lucas-clemente/quic-go to match
// the net.Conn based interface used troughout pion/webrtc.
package wrapper

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"

	quic "github.com/lucas-clemente/quic-go"
)

// Config represents the configuration of a Quic session
type Config struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	SkipVerify  bool
}

func getDefaultQuicConfig() *quic.Config {
	return &quic.Config{
		MaxIncomingStreams:                    1000,
		MaxIncomingUniStreams:                 -1,              // disable unidirectional streams
		MaxReceiveStreamFlowControlWindow:     3 * (1 << 20),   // 3 MB
		MaxReceiveConnectionFlowControlWindow: 4.5 * (1 << 20), // 4.5 MB
		KeepAlive:                             true,
	}
}

// Client establishes a QUIC session over an existing conn
func Client(conn net.Conn, config *Config) (*Session, error) {
	tlscfg := getTLSConfig(config)
	rAddr := conn.RemoteAddr()
	if rAddr == nil {
		return nil, fmt.Errorf("quic: creating client without remote address")
	}
	s, err := quic.Dial(newFakePacketConn(conn), rAddr, rAddr.String(), tlscfg, getDefaultQuicConfig())
	if err != nil {
		return nil, err
	}
	return &Session{s: s}, nil
}

// Dial dials the address over quic
func Dial(addr string, config *Config) (*Session, error) {
	tlscfg := getTLSConfig(config)
	s, err := quic.DialAddr(addr, tlscfg, getDefaultQuicConfig())
	if err != nil {
		return nil, err
	}
	return &Session{s: s}, nil
}

// Server creates a listener for listens for incoming QUIC sessions
func Server(conn net.Conn, config *Config) (*Listener, error) {
	tlscfg := getTLSConfig(config)
	l, err := quic.Listen(newFakePacketConn(conn), tlscfg, getDefaultQuicConfig())
	if err != nil {
		return nil, err
	}
	return &Listener{l: l}, nil
}

// Listen listens on the address over quic
func Listen(addr string, config *Config) (*Listener, error) {
	tlscfg := getTLSConfig(config)
	l, err := quic.ListenAddr(addr, tlscfg, getDefaultQuicConfig())
	if err != nil {
		return nil, err
	}
	return &Listener{l: l}, nil
}

func getTLSConfig(config *Config) *tls.Config {
	/* #nosec G402 */
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: config.SkipVerify,
		ClientAuth:         tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{config.Certificate.Raw},
			PrivateKey:  config.PrivateKey,
		}},
		NextProtos: []string{"pion-quic"},
	}
}

// A Session is a QUIC connection between two peers.
type Session struct {
	s quic.Session
}

// OpenStream opens a new stream
func (s *Session) OpenStream() (*Stream, error) {
	str, err := s.s.OpenStream()
	if err != nil {
		return nil, err
	}
	return &Stream{s: str}, nil
}

// AcceptStream accepts an incoming stream
func (s *Session) AcceptStream() (*Stream, error) {
	str, err := s.s.AcceptStream(context.TODO())
	if err != nil {
		return nil, err
	}
	return &Stream{s: str}, nil
}

// GetRemoteCertificates returns the certificate chain presented by remote peer.
func (s *Session) GetRemoteCertificates() []*x509.Certificate {
	return s.s.ConnectionState().PeerCertificates
}

// Close the connection
func (s *Session) Close() error {
	return s.CloseWithError(0, io.EOF)
}

// CloseWithError closes the connection with an error.
// The error must not be nil.
func (s *Session) CloseWithError(code uint16, err error) error {
	var e = "nil"
	if err != nil {
		e = err.Error()
	}
	return s.s.CloseWithError(quic.ErrorCode(code), e)
}
