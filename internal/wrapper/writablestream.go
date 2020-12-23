package wrapper

import (
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

// WritableStream represents a wrapped quic-go SendStream
type WritableStream struct {
	s quic.SendStream
}

// Write implements the Conn Write method.
func (s *WritableStream) Write(p []byte, fin bool) (int, error) {
	return s.s.Write(p)
}

// WriteQuic writes a frame and closes the stream if fin is true
func (s *WritableStream) WriteQuic(p []byte, fin bool) (int, error) {
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
func (s *WritableStream) StreamID() uint64 {
	return uint64(s.s.StreamID())
}

// Close implements the Conn Close method. It is used to close
// the connection. Any calls to Write will be unblocked and return an error.
func (s *WritableStream) Close() error {
	return s.s.Close()
}

// SetWriteDeadline sets the deadline for future Write calls. A zero value for t means Write will not time out.
func (s *WritableStream) SetWriteDeadline(t time.Time) error {
	return s.s.SetWriteDeadline(t)
}

// Detach returns the underlying quic-go SendStream
func (s *WritableStream) Detach() quic.SendStream {
	return s.s
}
