// Package quic implements the QUIC API for Client-to-Server Connections
// https://w3c.github.io/webrtc-quic/
package quic

import (
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

func newServer(url string, config *Config) (*Transport, error) {
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	cfg := config.clone()
	cfg.SkipVerify = true // Using self signed certificates for now

	l, err := wrapper.Listen(url, cfg)
	if err != nil {
		return nil, err
	}

	s, err := l.Accept()
	if err != nil {
		return nil, err
	}

	t := &Transport{}
	t.TransportBase.log = loggerFactory.NewLogger("quic")
	return t, t.TransportBase.startBase(s)
}
