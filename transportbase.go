// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package quic

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/quic/internal/wrapper"
)

// TransportBase is the base for Transport. Most of the
// functionality of a Transport is in the base class to allow for
// other subclasses (such as a p2p variant) to share the same interface.
type TransportBase struct {
	lock                       sync.RWMutex
	onBidirectionalStreamHdlr  func(*BidirectionalStream)
	onUnidirectionalStreamHdlr func(*ReadableStream)
	session                    *wrapper.Conn
	log                        logging.LeveledLogger
}

// Config is used to hold the configuration of StartBase.
type Config struct {
	Client        bool
	Certificate   *x509.Certificate
	PrivateKey    crypto.PrivateKey
	LoggerFactory logging.LoggerFactory
}

// StartBase is used to start the TransportBase. Most implementations
// should instead use the methods on quic.Transport or
// webrtc.QUICTransport to setup a Quic connection.
func (b *TransportBase) StartBase(conn net.Conn, config *Config) error {
	lf := config.LoggerFactory
	if lf == nil {
		lf = logging.NewDefaultLoggerFactory()
	}
	b.log = lf.NewLogger("quic-wrapper")

	cfg := config.clone()
	cfg.SkipVerify = true // Using self signed certificates; WebRTC will check the fingerprint

	var con *wrapper.Conn
	var err error
	if config.Client {
		// Assumes the peer offered to be passive and we accepted.
		con, err = wrapper.Client(context.Background(), conn, cfg)
	} else {
		// Assumes we offer to be passive and this is accepted.
		var l *wrapper.Listener
		l, err = wrapper.Server(conn, cfg)
		if err != nil {
			return err
		}
		con, err = l.Accept()
	}

	if err != nil {
		return err
	}

	return b.startBase(con)
}

func (b *TransportBase) startBase(s *wrapper.Conn) error {
	b.session = s

	go b.acceptStreams()
	go b.acceptUniStreams()

	return nil
}

func (c *Config) clone() *wrapper.Config {
	return &wrapper.Config{
		Certificate: c.Certificate,
		PrivateKey:  c.PrivateKey,
	}
}

// CreateBidirectionalStream creates an QuicBidirectionalStream object.
func (b *TransportBase) CreateBidirectionalStream() (*BidirectionalStream, error) {
	s, err := b.session.OpenStream()
	if err != nil {
		return nil, err
	}

	return &BidirectionalStream{
		s: s,
	}, nil
}

// CreateUnidirectionalStream creates an QuicWritableStream object.
func (b *TransportBase) CreateUnidirectionalStream() (*WritableStream, error) {
	s, err := b.session.OpenUniStream()
	if err != nil {
		return nil, err
	}

	return &WritableStream{
		s: s,
	}, nil
}

// OnBidirectionalStream allows setting an event handler for that is fired
// when data is received from a BidirectionalStream for the first time.
func (b *TransportBase) OnBidirectionalStream(f func(*BidirectionalStream)) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.onBidirectionalStreamHdlr = f
}

// OnUnidirectionalStream allows setting an event handler for that is fired
// when data is received from a UnidirectionalStream for the first time.
func (b *TransportBase) OnUnidirectionalStream(f func(*ReadableStream)) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.onUnidirectionalStreamHdlr = f
}

func (b *TransportBase) onBidirectionalStream(s *BidirectionalStream) {
	b.lock.Lock()
	f := b.onBidirectionalStreamHdlr
	b.lock.Unlock()
	if f != nil {
		go f(s)
	}
}

func (b *TransportBase) onUnidirectionalStream(s *ReadableStream) {
	b.lock.Lock()
	f := b.onUnidirectionalStreamHdlr
	b.lock.Unlock()
	if f != nil {
		go f(s)
	}
}

// GetRemoteCertificates returns the certificate chain in use by the remote side.
func (b *TransportBase) GetRemoteCertificates() []*x509.Certificate {
	return b.session.GetRemoteCertificates()
}

func (b *TransportBase) acceptStreams() {
	for {
		stream, err := b.session.AcceptStream()
		if err != nil {
			b.log.Errorf("Failed to accept stream: %v", err)
			stopErr := b.Stop(TransportStopInfo{
				Reason: err.Error(),
			})
			if stopErr != nil {
				b.log.Errorf("Failed to stop transport: %v", stopErr)
			}

			return
		}
		if stream != nil {
			stream := &BidirectionalStream{s: stream}
			b.onBidirectionalStream(stream)
		} else {
			return
		}
	}
}

func (b *TransportBase) acceptUniStreams() {
	for {
		stream, err := b.session.AcceptUniStream()
		if err != nil {
			b.log.Errorf("Failed to accept stream: %v", err)
			stopErr := b.Stop(TransportStopInfo{
				Reason: err.Error(),
			})
			if stopErr != nil {
				b.log.Errorf("Failed to stop transport: %v", stopErr)
			}

			return
		}
		if stream != nil {
			stream := &ReadableStream{s: stream}
			b.onUnidirectionalStream(stream)
		} else {
			return
		}
	}
}

// Stop stops and closes the TransportBase.
func (b *TransportBase) Stop(stopInfo TransportStopInfo) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.session == nil {
		return nil
	}

	if stopInfo.ErrorCode > 0 || len(stopInfo.Reason) > 0 {
		return b.session.CloseWithError(stopInfo.ErrorCode, errors.New(stopInfo.Reason)) //nolint:err113
	}

	return b.session.Close()
}
