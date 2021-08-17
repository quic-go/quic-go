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
	WebTransport() (WebTransport, error)
}

type requestStream struct {
	quic.Stream
	conn Conn
	r    io.Reader // Allows buffering reads from the stream
}

func newRequestStream(conn Conn, str quic.Stream, r io.Reader) *requestStream {
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
	return nil, errors.New("TODO: not supported yet")
}
