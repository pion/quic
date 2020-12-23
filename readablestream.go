package quic

import (
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/pion/quic/internal/wrapper"
)

// ReadableStream represents a unidirectional quic ReceiveStream
type ReadableStream struct {
	s *wrapper.ReadableStream
}

// ReadInto reads from the ReadableStream into the buffer.
func (s *ReadableStream) ReadInto(data []byte) (StreamReadResult, error) {
	n, fin, err := s.s.ReadQuic(data)
	return StreamReadResult{
		Amount:   n,
		Finished: fin,
	}, err
}

// StreamID returns the ID of the ReadableStream
func (s *ReadableStream) StreamID() uint64 {
	return s.s.StreamID()
}

// SetReadDeadline sets the deadline for future Read calls. A zero value for t means Read will not time out.
func (s *ReadableStream) SetReadDeadline(t time.Time) error {
	return s.s.SetReadDeadline(t)
}

// Detach detaches and returns the underlying quic-go ReceiveStream
func (s *ReadableStream) Detach() quic.ReceiveStream {
	return s.s.Detach()
}
