package http3

import (
	"context"
	"io"

	"github.com/lucas-clemente/quic-go"
)

// A WebTransport SessionID is the same as the request stream ID.
type SessionID = quic.StreamID

// WebTransport is an interface to accept or open streams and read and write datagrams.
type WebTransport interface {
	StreamHandler
	DatagramHandler
	io.Closer
}

// A StreamHandler can accept or open new QUIC streams.
type StreamHandler interface {
	// AcceptStream accepts the next incoming bidirectional stream.
	AcceptStream(context.Context) (quic.Stream, error)

	// AcceptUniStream accepts the next incoming unidirectional stream.
	AcceptUniStream(context.Context) (quic.ReceiveStream, error)

	// OpenStream opens a new stream.
	OpenStream() (quic.Stream, error)

	// OpenStreamSync opens a new stream, blocking until it is possible to open the stream.
	OpenStreamSync(context.Context) (quic.Stream, error)

	// OpenUniStream opens a new unidirectional stream.
	OpenUniStream() (quic.SendStream, error)

	// OpenUniStreamSync opens a new unidirectional stream.
	OpenUniStreamSync(context.Context) (quic.SendStream, error)
}

type wtSession struct {
	conn *connection
	str  quic.Stream
}

func newWebTransportSession(conn *connection, str quic.Stream) WebTransport {
	return &wtSession{
		conn: conn,
		str:  str,
	}
}

func (s *wtSession) SessionID() SessionID {
	return s.str.StreamID()
}

func (s *wtSession) Close() error {
	s.conn.cleanup(s.SessionID())
	s.str.CancelRead(quic.StreamErrorCode(errorNoError))
	s.str.CancelWrite(quic.StreamErrorCode(errorNoError))
	return nil
}

func (s *wtSession) AcceptStream(ctx context.Context) (quic.Stream, error) {
	return s.conn.acceptStream(ctx, s.SessionID())
}

func (s *wtSession) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	return s.conn.acceptUniStream(ctx, s.SessionID())
}

func (s *wtSession) OpenStream() (quic.Stream, error) {
	return s.conn.openStream(s.SessionID())
}

func (s *wtSession) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	return s.conn.openStreamSync(ctx, s.SessionID())
}

func (s *wtSession) OpenUniStream() (quic.SendStream, error) {
	return s.conn.openUniStream(s.SessionID())
}

func (s *wtSession) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	return s.conn.openUniStreamSync(ctx, s.SessionID())
}

func (s *wtSession) ReadDatagram(ctx context.Context) ([]byte, error) {
	return s.conn.readDatagram(ctx, s.SessionID())
}

func (s *wtSession) WriteDatagram(msg []byte) error {
	return s.conn.writeDatagram(s.SessionID(), msg)
}
