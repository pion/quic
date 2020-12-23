package quic

import (
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/pion/quic/internal/wrapper"
)

// BidirectionalStream represents a bidirectional Quic stream.
type BidirectionalStream struct {
	s *wrapper.Stream
}

// Write writes data to the stream.
func (s *BidirectionalStream) Write(data StreamWriteParameters) error {
	_, err := s.s.WriteQuic(data.Data, data.Finished)
	return err
}

// ReadInto reads from the stream into the buffer.
func (s *BidirectionalStream) ReadInto(data []byte) (StreamReadResult, error) {
	n, fin, err := s.s.ReadQuic(data)
	return StreamReadResult{
		Amount:   n,
		Finished: fin,
	}, err
}

// StreamID returns the ID of the QuicStream
func (s *BidirectionalStream) StreamID() uint64 {
	return s.s.StreamID()
}

// SetDeadline sets read and write deadlines associated with the stream. A zero value for t means Read and Write will not timeout.
func (s *BidirectionalStream) SetDeadline(t time.Time) error {
	return s.s.SetDeadline(t)
}

// Detach detaches the underlying quic-go stream
func (s *BidirectionalStream) Detach() quic.Stream {
	return s.s.Detach()
}
