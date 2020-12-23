package quic

import (
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/pion/quic/internal/wrapper"
)

// WritableStream represents a quic SendStream
type WritableStream struct {
	s *wrapper.WritableStream
}

// Write writes data to the stream.
func (s *WritableStream) Write(data StreamWriteParameters) error {
	_, err := s.s.WriteQuic(data.Data, data.Finished)
	return err
}

// StreamID returns the ID of the WritableStream
func (s *WritableStream) StreamID() uint64 {
	return s.s.StreamID()
}

// SetWriteDeadline sets the deadline for future Write calls. A zero value for t means Write will not time out.
func (s *WritableStream) SetWriteDeadline(t time.Time) error {
	return s.s.SetWriteDeadline(t)
}

// Detach detaches the underlying quic-go SendStream
func (s *WritableStream) Detach() quic.SendStream {
	return s.s.Detach()
}
