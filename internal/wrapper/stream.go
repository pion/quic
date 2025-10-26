// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package wrapper

import (
	"errors"
	"io"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Stream represents a wrapped quic-go Stream.
type Stream struct {
	s *quic.Stream
}

// Read implements the Conn Read method.
func (s *Stream) Read(p []byte) (int, error) {
	return s.s.Read(p)
}

// ReadQuic reads a frame and determines if it is the final frame.
func (s *Stream) ReadQuic(p []byte) (int, bool, error) {
	n, err := s.s.Read(p)
	fin := false

	if errors.Is(err, io.EOF) {
		fin = true
	} else if err != nil {
		var ne net.Error
		if errors.As(err, &ne) {
			fin = !ne.Timeout()
		} else {
			fin = true
		}
	}

	return n, fin, err
}

// Write implements the Conn Write method.
func (s *Stream) Write(p []byte, fin bool) (int, error) {
	return s.s.Write(p)
}

// WriteQuic writes a frame and closes the stream if fin is true.
func (s *Stream) WriteQuic(p []byte, fin bool) (int, error) {
	n, err := s.s.Write(p)
	if err != nil {
		return n, err
	}
	if fin {
		return n, s.s.Close()
	}

	return n, nil
}

// StreamID returns the ID of the QuicStream.
func (s *Stream) StreamID() int64 {
	return int64(s.s.StreamID())
}

// Close implements the Conn Close method. It is used to close
// the connection. Any calls to Read and Write will be unblocked and return an error.
func (s *Stream) Close() error {
	return s.s.Close()
}

// SetDeadline sets read and write deadlines associated with the stream.
// A zero value for t means Read and Write will not timeout.
func (s *Stream) SetDeadline(t time.Time) error {
	return s.s.SetDeadline(t)
}

// Detach returns the underlying quic-go Stream.
func (s *Stream) Detach() *quic.Stream {
	return s.s
}
