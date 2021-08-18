package http3

import (
	"context"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go"
)

// A RequestStream is a QUIC stream for processing HTTP/3 requests.
// Instances may also implement DatagramContextProvider and/or WebTransportProvider.
type RequestStream interface {
	quic.Stream

	// TODO: integrate QPACK encoding and decoding with dynamic tables

	// WebTransport returns a WebTransport interface, if supported.
	// TODO: should this method live here?
	WebTransport() (WebTransport, error)
}

type requestStream struct {
	quic.Stream
	conn *connection
	r    io.Reader // Allows buffering reads from the stream
}

var _ quic.Stream = &requestStream{}

func newRequestStream(conn *connection, str quic.Stream, r io.Reader) *requestStream {
	if r == nil {
		r = str
	}
	return &requestStream{
		Stream: str,
		conn:   conn,
		r:      r,
	}
}

func (s *requestStream) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s *requestStream) Close() error {
	s.conn.cleanup(s.Stream.StreamID())
	return s.Stream.Close()
}

func (s *requestStream) CancelRead(code quic.StreamErrorCode) {
	s.conn.cleanup(s.Stream.StreamID())
	s.Stream.CancelRead(code)
}

func (s *requestStream) CancelWrite(code quic.StreamErrorCode) {
	s.conn.cleanup(s.Stream.StreamID())
	s.Stream.CancelWrite(code)
}

func (s *requestStream) AcceptDatagramContext(ctx context.Context) (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *requestStream) RegisterDatagramContext() (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *requestStream) DatagramNoContext() (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *requestStream) WebTransport() (WebTransport, error) {
	return s.conn.WebTransport(s.Stream)
}
