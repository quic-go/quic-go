package http3

import (
	"context"
	"io"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

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

func (s *wtSession) SessionID() quic.StreamID {
	return s.str.StreamID()
}

func (s *wtSession) Close() error {
	s.conn.cleanup(s.SessionID())
	s.str.CancelRead(quic.StreamErrorCode(errorNoError))
	s.str.CancelWrite(quic.StreamErrorCode(errorNoError))
	return nil
}

func (s *wtSession) AcceptStream(ctx context.Context) (quic.Stream, error) {
	select {
	case str := <-s.conn.incomingStreamsChan(s.SessionID()):
		return str, nil
	case <-s.conn.session.Context().Done():
		return nil, s.conn.session.Context().Err()
	}
}

func (s *wtSession) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	select {
	case str := <-s.conn.incomingUniStreamsChan(s.SessionID()):
		return str, nil
	case <-s.conn.session.Context().Done():
		return nil, s.conn.session.Context().Err()
	}
}

func (s *wtSession) OpenStream() (quic.Stream, error) {
	str, err := s.conn.session.OpenStream()
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(FrameTypeWebTransportStream))
	quicvarint.Write(w, uint64(s.SessionID()))
	return str, nil
}

func (s *wtSession) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	str, err := s.conn.session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(FrameTypeWebTransportStream))
	quicvarint.Write(w, uint64(s.SessionID()))
	return str, nil
}

func (s *wtSession) OpenUniStream() (quic.SendStream, error) {
	str, err := s.conn.session.OpenUniStream()
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(StreamTypeWebTransportStream))
	quicvarint.Write(w, uint64(s.SessionID()))
	return str, nil
}

func (s *wtSession) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	str, err := s.conn.session.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	w := quicvarint.NewWriter(str)
	quicvarint.Write(w, uint64(StreamTypeWebTransportStream))
	quicvarint.Write(w, uint64(s.SessionID()))
	return str, nil
}

func (s *wtSession) ReadDatagram(ctx context.Context) ([]byte, error) {
	return s.conn.readDatagram(ctx, s.SessionID())
}

func (s *wtSession) WriteDatagram(msg []byte) error {
	return s.conn.writeDatagram(s.SessionID(), msg)
}
