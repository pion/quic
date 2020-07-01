package wrapper

import (
	"errors"
	"fmt"
	"io"
	"net"

	quic "github.com/lucas-clemente/quic-go"
)

// Stream represents a wrapped quic-go stream
type Stream struct {
	s quic.Stream
}

// Read implements the Conn Read method.
func (s *Stream) Read(p []byte) (int, error) {
	return s.s.Read(p)
}

// ReadQuic reads a frame and determines if it is the final frame
func (s *Stream) ReadQuic(p []byte) (int, bool, error) {
	n, err := s.s.Read(p)
	fin := false
	if err != nil {
		if errors.Is(err, io.EOF) {
			fin = true
		} else {
			if ne, ok := err.(net.Error); ok && !ne.Timeout() {
				fin = true
			} else {
				// TODO determine if closed
				fmt.Println("[quic debug] read error: %T %+v", err, err)
				// seriously, which error isn't fin=true but timeout?
			}
		}
	}
	return n, fin, err
}

// Write implements the Conn Write method.
func (s *Stream) Write(p []byte, fin bool) (int, error) {
	return s.s.Write(p)
}

// WriteQuic writes a frame and closes the stream if fin is true
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

// StreamID returns the ID of the QuicStream
func (s *Stream) StreamID() uint64 {
	return uint64(s.s.StreamID())
}

// Close implements the Conn Close method. It is used to close
// the connection. Any calls to Read and Write will be unblocked and return an error.
func (s *Stream) Close() error {
	return s.s.Close()
}

// Detach returns the underlying quic-go Stream
func (s *Stream) Detach() quic.Stream {
	return s.s
}
