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

	// WebTransport returns a WebTransport interface, if supported.
	// TODO: should this method live here?
	WebTransport() (WebTransport, error)
}

type requestStream struct {
	quic.Stream
	conn *connection
	pfx  []byte // Allows buffering reads from the stream
}

var _ quic.Stream = &requestStream{}

func newRequestStream(conn *connection, str quic.Stream, pfx []byte) *requestStream {
	return &requestStream{
		Stream: str,
		conn:   conn,
		pfx:    pfx,
	}
}

// Read first copies bytes from pfx, then reads from Stream.
func (s *requestStream) Read(p []byte) (int, error) {
	n := len(s.pfx)
	if n == 0 {
		return s.Stream.Read(p)
	}
	if n <= len(p) {
		copy(p, s.pfx)
		s.pfx = nil
		return n, nil
	}
	copy(p, s.pfx[:len(p)])
	s.pfx = s.pfx[len(p):]
	return len(p), nil
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
	return newWebTransportSession(s.conn, s), nil
}
