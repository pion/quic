// Package quic implements the QUIC API for Client-to-Server Connections
// https://w3c.github.io/webrtc-quic/
package quic

import (
	"fmt"
	"io"

	"github.com/pion/logging"
	"github.com/pion/quic/internal/wrapper"
)

// Transport is a quic transport focused on client/server use cases.
type Transport struct {
	TransportBase
}

// NewTransport creates a new Transport
func NewTransport(url string, config *Config) (*Transport, error) {
	if config.LoggerFactory == nil {
		config.LoggerFactory = logging.NewDefaultLoggerFactory()
	}

	cfg := config.clone()
	cfg.SkipVerify = true // Using self signed certificates for now

	s, err := wrapper.Dial(url, cfg)
	if err != nil {
		return nil, err
	}

	t := &Transport{}
	t.TransportBase.log = config.LoggerFactory.NewLogger("quic")
	return t, t.TransportBase.startBase(s)
}

// single accept listen for testing
func newServer(url string, config *Config) (*Transport, io.Closer, error) {
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	cfg := config.clone()
	cfg.SkipVerify = true // Using self signed certificates for now

	l, err := wrapper.Listen(url, cfg)
	if err != nil {
		return nil, nil, err
	}

	s, err := l.Accept()
	if err != nil {
		if cerr := l.Close(); cerr != nil {
			err = fmt.Errorf("failed to close listener (%s) after accept failed: %w", cerr, err)
		}
		return nil, nil, err
	}

	t := &Transport{}
	t.TransportBase.log = loggerFactory.NewLogger("quic")
	return t, l, t.TransportBase.startBase(s)
}
