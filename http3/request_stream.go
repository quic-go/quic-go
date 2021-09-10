package http3

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"
)

type requestStream struct {
	quic.Stream
	conn *connection

	fr               *FrameReader
	dataReaderClosed bool

	w                quicvarint.Writer
	dataWriterClosed bool
}

var (
	_ RequestStream         = &requestStream{}
	_ WebTransporter        = &requestStream{}
	_ datagramRequestStream = &requestStream{}
)

// newRequestStream creates a new RequestStream. If a frame has already been
// partially consumed from str, t specifies the frame type and n the number of
// bytes remaining in the frame payload.
func newRequestStream(conn *connection, str quic.Stream, t FrameType, n int64) RequestStream {
	s := &requestStream{
		Stream: str,
		conn:   conn,
		fr:     &FrameReader{R: str, Type: t, N: n},
		w:      quicvarint.NewWriter(str),
	}
	return s
}

// CancelRead cleans up any buffered incoming streams and datagrams.
func (s *requestStream) CancelRead(code quic.StreamErrorCode) {
	s.conn.cleanup(s.Stream.StreamID())
	s.Stream.CancelRead(code)
}

// CancelWrite cleans up any buffered incoming streams and datagrams.
func (s *requestStream) CancelWrite(code quic.StreamErrorCode) {
	s.conn.cleanup(s.Stream.StreamID())
	s.Stream.CancelWrite(code)
}

// Close cleans up any buffered incoming streams and datagrams.
// TODO(ydnar): should this close the stream if a WebTransport interface was created?
// TODO(ydnar): should a WebTransport session persist after an http.Handler returns?
func (s *requestStream) Close() error {
	s.conn.cleanup(s.Stream.StreamID())
	return s.Stream.Close()
}

// LocalAddr returns the local address.
func (s *requestStream) LocalAddr() net.Addr {
	return s.conn.session.LocalAddr()
}

// RemoteAddr returns the address of the peer.
func (s *requestStream) RemoteAddr() net.Addr {
	return s.conn.session.RemoteAddr()
}

// ReadHeaders reads the next HEADERS frame, used for HTTP request and
// response headers and trailers. An interim response (status 100-199)
// must be followed by one or more additional HEADERS frames.
// If ReadHeaders encounters a DATA frame or an otherwise unhandled frame,
// it will return a FrameTypeError.
func (s *requestStream) ReadHeaders() ([]qpack.HeaderField, error) {
	err := s.nextHeadersFrame()
	if err != nil {
		return nil, err
	}

	max := s.conn.maxHeaderBytes()
	if s.fr.N > int64(max) {
		return nil, &FrameLengthError{Type: s.fr.Type, Len: uint64(s.fr.N), Max: max}
	}

	p := make([]byte, s.fr.N)
	_, err = io.ReadFull(s.fr, p)
	if err != nil {
		return nil, err
	}

	dec := qpack.NewDecoder(nil)
	fields, err := dec.DecodeFull(p)
	if err != nil {
		s.conn.session.CloseWithError(quic.ApplicationErrorCode(errorGeneralProtocolError), err.Error())
		return nil, err
	}

	return fields, nil
}

// WriteHeaders writes a single QPACK-encoded HEADERS frame to s.
// It returns an error if the estimated size of the frame exceeds the peer’s
// MAX_FIELD_SECTION_SIZE. Headers are not modified or validated.
// It is the responsibility of the caller to ensure the fields are valid.
// It should not be called concurrently with Write or ReadFrom.
// It MAY also write a greasing frame, which the peer should ignore.
// See https://quicwg.org/base-drafts/draft-ietf-quic-http.html#name-reserved-frame-types
// and https://datatracker.ietf.org/doc/html/draft-nottingham-http-grease-00.
func (s *requestStream) WriteHeaders(fields []qpack.HeaderField) error {
	n := uint64(time.Now().Nanosecond() >> 10) // Rougly microseconds
	if n&0x1 == 0 {
		writeGreaseFrame(s.w, n)
	}
	return writeHeadersFrame(s.w, fields, s.conn.peerMaxHeaderBytes())
}

func (s *requestStream) DataReader() io.ReadCloser {
	return (*dataReader)(s)
}

func (s *requestStream) DataWriter() io.WriteCloser {
	return (*dataWriter)(s)
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
	if !s.conn.Settings().WebTransportEnabled() {
		return nil, errors.New("WebTransport not enabled")
	}
	peerSettings, err := s.conn.PeerSettingsSync(context.Background())
	if err != nil {
		return nil, err
	}
	if !peerSettings.WebTransportEnabled() {
		return nil, errors.New("WebTransport not supported by peer")
	}
	return (*webTransportSession)(s), nil
}

// nextHeadersFrame reads incoming HTTP/3 frames until it finds
// the next HEADERS frame. If it encounters a DATA frame prior to
// reading a HEADERS frame, it will return a frameTypeError.
func (s *requestStream) nextHeadersFrame() error {
	if s.fr.Type == FrameTypeHeaders && s.fr.N > 0 {
		return nil
	}
	return s.nextFrame(FrameTypeHeaders)
}

// nextDataFrame reads incoming HTTP/3 frames until it finds
// the next DATA frame. If it encounters a HEADERS frame prior to
// reading a DATA frame, it will return a frameTypeError.
func (s *requestStream) nextDataFrame() error {
	if s.fr.Type == FrameTypeData && s.fr.N > 0 {
		return nil
	}
	return s.nextFrame(FrameTypeData)
}

func (s *requestStream) nextFrame(want FrameType) error {
	for {
		// Next discards any unread frame payload bytes.
		err := s.fr.Next()
		if err != nil {
			return err
		}
		switch s.fr.Type { //nolint:exhaustive
		case FrameTypeData:
			// Stop processing on DATA or HEADERS frames.
			if s.dataReaderClosed {
				continue
			}
			if want != FrameTypeData {
				return &FrameTypeError{Want: want, Type: s.fr.Type}
			}
			return nil

		case FrameTypeHeaders:
			// Stop processing on HEADERS frames.
			if want != FrameTypeHeaders {
				return &FrameTypeError{Want: want, Type: s.fr.Type}
			}
			return nil

		case FrameTypeCancelPush:
			// TODO: handle HTTP/3 pushes

		case FrameTypePushPromise:
			// TODO: handle HTTP/3 pushes
			if s.conn.session.Perspective() == quic.PerspectiveServer {
				// Not allowed on a request stream.
				// Close the connection with H3_FRAME_UNEXPECTED.
				err = &FrameTypeError{Want: want, Type: s.fr.Type}
				s.conn.session.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), err.Error())
				return err
			}

		case FrameTypeSettings, FrameTypeGoAway, FrameTypeMaxPushID:
			// Not allowed on a request stream.
			// Close the connection with H3_FRAME_UNEXPECTED.
			err = &FrameTypeError{Want: want, Type: s.fr.Type}
			s.conn.session.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), err.Error())
			return err

		default:
			// Skip unknown frame types.
		}
	}
}

// readData will read from at most a single DATA frame.
func (s *requestStream) readData(p []byte) (n int, err error) {
	if s.dataReaderClosed {
		return 0, io.EOF
	}
	for s.fr.N <= 0 {
		err = s.nextDataFrame()
		if err != nil {
			// Return EOF if we encounter trailers
			if err, ok := err.(*FrameTypeError); ok && err.Type == FrameTypeHeaders {
				s.closeDataReader()
				return n, io.EOF
			}
			return n, err
		}
	}
	if s.fr.N < int64(len(p)) {
		p = p[:s.fr.N]
	}
	return s.fr.Read(p)
}

const bodyCopyBufferSize = 8 * 1024

// writeData writes bytes to DATA frames to the underlying quic.Stream.
func (s *requestStream) writeData(p []byte) (n int, err error) {
	if s.dataWriterClosed {
		return 0, io.ErrClosedPipe
	}
	for len(p) > 0 {
		pp := p
		if len(p) > bodyCopyBufferSize {
			pp = p[:bodyCopyBufferSize]
		}
		x, err := s.writeDataFrame(pp)
		p = p[x:]
		n += x
		if err != nil {
			return n, err
		}
	}
	return n, err
}

// writeDataFrom reads from r until an error or io.EOF and writes DATA frames to
// the underlying quic.Stream. This is the underlying implementation of
// BodyReader().(io.ReaderFrom).
func (s *requestStream) writeDataFrom(r io.Reader) (n int64, err error) {
	if s.dataWriterClosed {
		return 0, io.ErrClosedPipe
	}
	buf := make([]byte, bodyCopyBufferSize)
	for {
		l, rerr := r.Read(buf)
		if l == 0 {
			if rerr == nil {
				continue
			} else if rerr == io.EOF {
				return n, nil
			}
			return n, rerr
		}
		x, err := s.writeDataFrame(buf[:l])
		n += int64(x)
		if err != nil {
			return n, err
		}
		if rerr == io.EOF {
			return n, nil
		}
	}
}

func (s *requestStream) writeDataFrame(p []byte) (n int, err error) {
	quicvarint.Write(s.w, uint64(FrameTypeData))
	quicvarint.Write(s.w, uint64(len(p)))
	return s.w.Write(p)
}

func (s *requestStream) closeDataReader() error {
	s.dataReaderClosed = true
	return nil
}

func (s *requestStream) closeDataWriter() error {
	s.dataWriterClosed = true
	return nil
}

// dataReader is an alias for requestStream, so (*requestStream).BodyReader can
// return a limited interface version of itself.
type dataReader requestStream

var _ io.ReadCloser = &dataReader{}

func (r *dataReader) Read(p []byte) (n int, err error) {
	return (*requestStream)(r).readData(p)
}

func (r *dataReader) Close() error {
	return (*requestStream)(r).closeDataReader()
}

// dataWriter is an alias for requestStream, so (*requestStream).BodyWriter can
// return a limited interface version of itself.
type dataWriter requestStream

var (
	_ io.WriteCloser = &dataWriter{}
	_ io.ReaderFrom  = &dataWriter{}
)

func (w *dataWriter) Write(p []byte) (n int, err error) {
	return (*requestStream)(w).writeData(p)
}

func (w *dataWriter) ReadFrom(r io.Reader) (n int64, err error) {
	return (*requestStream)(w).writeDataFrom(r)
}

func (w *dataWriter) Close() error {
	return (*requestStream)(w).closeDataWriter()
}

// webTransportSession is an alias for requestStream.
type webTransportSession requestStream

var _ WebTransport = &webTransportSession{}

func (s *webTransportSession) SessionID() SessionID {
	return s.StreamID()
}

func (s *webTransportSession) Close() error {
	s.CancelRead(quic.StreamErrorCode(errorNoError))
	s.CancelWrite(quic.StreamErrorCode(errorNoError))
	return nil
}

func (s *webTransportSession) AcceptStream(ctx context.Context) (quic.Stream, error) {
	return s.conn.acceptStream(ctx, s.SessionID())
}

func (s *webTransportSession) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	return s.conn.acceptUniStream(ctx, s.SessionID())
}

func (s *webTransportSession) OpenStream() (quic.Stream, error) {
	return s.conn.openStream(s.SessionID())
}

func (s *webTransportSession) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	return s.conn.openStreamSync(ctx, s.SessionID())
}

func (s *webTransportSession) OpenUniStream() (quic.SendStream, error) {
	return s.conn.openUniStream(s.SessionID())
}

func (s *webTransportSession) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	return s.conn.openUniStreamSync(ctx, s.SessionID())
}

func (s *webTransportSession) ReadDatagram(ctx context.Context) ([]byte, error) {
	return s.conn.readDatagram(ctx, s.SessionID())
}

func (s *webTransportSession) WriteDatagram(msg []byte) error {
	return s.conn.writeDatagram(s.SessionID(), msg)
}
