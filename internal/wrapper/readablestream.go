package wrapper

import (
	"errors"
	"io"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

// ReadableStream represents a wrapped quic-go ReceiveStream
type ReadableStream struct {
	s quic.ReceiveStream
}

// Read implements the Conn Read method.
func (s *ReadableStream) Read(p []byte) (int, error) {
	return s.s.Read(p)
}

// ReadQuic reads a frame and determines if it is the final frame
func (s *ReadableStream) ReadQuic(p []byte) (int, bool, error) {
	n, err := s.s.Read(p)
	fin := false
	if err != nil {
		if errors.Is(err, io.EOF) {
			fin = true
		} else {
			if ne, ok := err.(net.Error); ok {
				fin = !ne.Timeout()
			} else {
				// which error isn't fin=true but timeout?
				fin = true
			}
		}
	}
	return n, fin, err
}

// StreamID returns the ID of the QuicStream
func (s *ReadableStream) StreamID() uint64 {
	return uint64(s.s.StreamID())
}

// SetReadDeadline sets the deadline for future Read calls. A zero value for t means Read will not time out.
func (s *ReadableStream) SetReadDeadline(t time.Time) error {
	return s.s.SetReadDeadline(t)
}

// Detach returns the underlying quic-go ReveiveStream
func (s *ReadableStream) Detach() quic.ReceiveStream {
	return s.s
}
