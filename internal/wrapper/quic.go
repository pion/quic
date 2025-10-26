// Package wrapper is a wrapper around lucas-clemente/quic-go to match
// the net.Conn based interface used troughout pion/webrtc.
package wrapper

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// Config represents the configuration of a Quic session.
type Config struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	SkipVerify  bool
}

func getDefaultQuicConfig() *quic.Config {
	return &quic.Config{
		MaxIncomingStreams:         1000,
		MaxIncomingUniStreams:      1000,
		MaxStreamReceiveWindow:     3 << 20,
		MaxConnectionReceiveWindow: 9 << 19,
		KeepAlivePeriod:            30 * time.Second,
	}
}

var errClientWithoutRemoteAddress = errors.New("quic: creating client without remote address")

// Client establishes a QUIC session over an existing conn.
func Client(ctx context.Context, conn net.Conn, config *Config) (*Conn, error) {
	rAddr := conn.RemoteAddr()
	if rAddr == nil {
		return nil, errClientWithoutRemoteAddress
	}

	c, err := quic.Dial(ctx, newFakePacketConn(conn), rAddr, getTLSConfig(config), getDefaultQuicConfig())
	if err != nil {
		return nil, err
	}

	return &Conn{c: c}, nil
}

// Dial dials the address over quic.
func Dial(ctx context.Context, addr string, config *Config) (*Conn, error) {
	c, err := quic.DialAddr(ctx, addr, getTLSConfig(config), getDefaultQuicConfig())
	if err != nil {
		return nil, err
	}

	return &Conn{c: c}, nil
}

// Server creates a listener for listens for incoming QUIC sessions.
func Server(conn net.Conn, config *Config) (*Listener, error) {
	l, err := quic.Listen(newFakePacketConn(conn), getTLSConfig(config), getDefaultQuicConfig())
	if err != nil {
		return nil, err
	}

	return &Listener{l: l}, nil
}

// Listen listens on the address over quic.
func Listen(addr string, config *Config) (*Listener, error) {
	l, err := quic.ListenAddr(addr, getTLSConfig(config), getDefaultQuicConfig())
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

// A Conn is a QUIC connection between two peers.
type Conn struct {
	c *quic.Conn
}

// OpenStream opens a new stream.
func (c *Conn) OpenStream() (*Stream, error) {
	str, err := c.c.OpenStream()
	if err != nil {
		return nil, err
	}

	return &Stream{s: str}, nil
}

// OpenUniStream opens and returns a new WritableStream.
func (c *Conn) OpenUniStream() (*WritableStream, error) {
	str, err := c.c.OpenUniStream()
	if err != nil {
		return nil, err
	}

	return &WritableStream{s: str}, nil
}

// AcceptStream accepts an incoming stream.
func (c *Conn) AcceptStream() (*Stream, error) {
	str, err := c.c.AcceptStream(context.TODO())
	if err != nil {
		if strings.HasPrefix(err.Error(), "Application error 0x0") {
			//nolint:nilnil // todo fix.
			return nil, nil // Errorcode == 0 implies session is closed without error
		}

		return nil, err
	}

	return &Stream{s: str}, nil
}

// AcceptUniStream accepts an incoming unidirectional stream and returns a ReadableStream.
func (c *Conn) AcceptUniStream() (*ReadableStream, error) {
	str, err := c.c.AcceptUniStream(context.TODO())
	if err != nil {
		if strings.HasPrefix(err.Error(), "Application error 0x0") {
			//nolint:nilnil // todo fix.
			return nil, nil // Errorcode == 0 implies session is closed without error
		}

		return nil, err
	}

	return &ReadableStream{s: str}, nil
}

// GetRemoteCertificates returns the certificate chain presented by remote peer.
func (c *Conn) GetRemoteCertificates() []*x509.Certificate {
	return c.c.ConnectionState().TLS.PeerCertificates
}

// Close the connection.
func (c *Conn) Close() error {
	return c.c.CloseWithError(0, io.EOF.Error())
}

// CloseWithError closes the connection with an error.
// The error must not be nil.
func (c *Conn) CloseWithError(code uint16, err error) error {
	e := "nil"
	if err != nil {
		e = err.Error()
	}

	return c.c.CloseWithError(quic.ApplicationErrorCode(code), e)
}
