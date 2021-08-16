package http3

import (
	"context"
	"errors"

	"github.com/lucas-clemente/quic-go"
)

// A RequestStream is a QUIC stream for processing HTTP/3 requests.
// Instances may also implement DatagramContextProvider and/or WebTransportProvider.
type RequestStream interface {
	quic.Stream

	// TODO: integrate QPACK encoding and decoding with dynamic tables

	// WriteHeaderFrame([]qpack.HeaderField) error
	// WriteDataFrame([]byte) error

	// WebTransport returns a WebTransport interface, if supported.
	WebTransport() (WebTransport, error)
}

type requestStream struct {
	quic.Stream
	conn Conn
}

func newRequestStream(conn Conn, str quic.Stream) (RequestStream, error) {
	s := &requestStream{
		Stream: str,
		conn:   conn,
	}

	return s, nil
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
