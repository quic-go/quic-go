package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"
)

// A RequestStream wraps a QUIC stream for processing HTTP/3 requests. It
// processes HEADERS and DATA frames, making these available to the caller via
// ReadHeaders and DataReader. It may also process other frame types or skip any
// unknown frame types. A caller can also bypass the framing methods and
// directly read from or write to the underlying quic.Stream.
type RequestStream interface {
	quic.Stream

	// TODO: integrate QPACK encoding and decoding with dynamic tables.

	// ReadHeaders reads the next HEADERS frame, used for HTTP request and
	// response headers and trailers. An interim response (status 100-199)
	// must be followed by one or more additional HEADERS frames. If
	// ReadHeaders encounters a DATA frame or an otherwise unhandled frame,
	// it will return a FrameTypeError.
	ReadHeaders() ([]qpack.HeaderField, error)

	// WriteHeaders writes a single HEADERS frame, used for HTTP request and
	// response headers and trailers. It returns any errors that may occur,
	// including QPACK encoding or writes to the underlying quic.Stream.
	// WriteHeaders shoud not be called simultaneously with Write, ReadFrom,
	// or writes to the underlying quic.Stream.
	WriteHeaders([]qpack.HeaderField) error

	// DataReader returns an io.ReadCloser that reads DATA frames from the
	// underlying quic.Stream, used for reading an HTTP request or response
	// body. If Read encounters a HEADERS frame it will return a
	// FrameTypeError. If the write side of the stream closes, it will
	// return io.EOF. Closing DataReader will prevent further writes, but
	// will not close the stream.
	DataReader() io.ReadCloser

	// DataWriter returns an io.WriteCloser that writes DATA frames to the
	// underlying quic.Stream, used for writing an HTTP request or response
	// body. Write should not be called simultaneously with WriteHeaders.
	// Closing DataWriter will prevent further writes, but will not close
	// the stream.
	DataWriter() io.WriteCloser

	// WebTransport returns a WebTransport interface, if supported.
	WebTransport() (WebTransport, error)
}

type requestStream struct {
	quic.Stream
	conn *connection

	fr               *FrameReader
	dataReaderClosed bool

	w                quicvarint.Writer
	dataWriterClosed bool
}

var (
	_ RequestStream = &requestStream{}
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
func (s *requestStream) WriteHeaders(fields []qpack.HeaderField) error {
	var l uint64
	for i := range fields {
		// https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html#name-dynamic-table-size
		l += uint64(len(fields[i].Name) + len(fields[i].Value) + 32)
	}
	max := s.conn.peerMaxHeaderBytes()
	if l > max {
		return fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", l, max)
	}

	buf := &bytes.Buffer{}
	encoder := qpack.NewEncoder(buf)
	for i := range fields {
		encoder.WriteField(fields[i])
	}

	quicvarint.Write(s.w, uint64(FrameTypeHeaders))
	quicvarint.Write(s.w, uint64(buf.Len()))
	_, err := s.w.Write(buf.Bytes())
	return err
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
	return newWebTransportSession(s.conn, s.Stream)
}

func (s *requestStream) CancelRead(code quic.StreamErrorCode) {
	s.conn.cleanup(s.Stream.StreamID())
	s.Stream.CancelRead(code)
}

func (s *requestStream) CancelWrite(code quic.StreamErrorCode) {
	s.conn.cleanup(s.Stream.StreamID())
	s.Stream.CancelWrite(code)
}

func (s *requestStream) Close() error {
	// FIXME: should this close the stream if a WebTransport interface was created?
	// Should a WebTransport session persist after an http.Handler returns?
	s.conn.cleanup(s.Stream.StreamID())
	return s.Stream.Close()
}

// nextHeadersFrame reads incoming HTTP/3 frames until it finds
// the next HEADERS frame. If it encouters a DATA frame prior to
// reading a HEADERS frame, it will return a frameTypeError.
func (s *requestStream) nextHeadersFrame() error {
	if s.fr.Type == FrameTypeHeaders && s.fr.N > 0 {
		return nil
	}
	err := s.readFrames()
	if err != nil {
		return err
	}
	if s.fr.Type != FrameTypeHeaders && !s.dataReaderClosed {
		return &FrameTypeError{Want: FrameTypeHeaders, Type: s.fr.Type}
	}
	return nil
}

// nextDataFrame reads incoming HTTP/3 frames until it finds
// the next DATA frame. If it encouters a HEADERS frame prior to
// reading a DATA frame, it will return a frameTypeError.
func (s *requestStream) nextDataFrame() error {
	if s.fr.Type == FrameTypeData && s.fr.N > 0 {
		return nil
	}
	err := s.readFrames()
	if err != nil {
		return err
	}
	if s.fr.Type != FrameTypeData {
		return &FrameTypeError{Want: FrameTypeData, Type: s.fr.Type}
	}
	return nil
}

func (s *requestStream) readFrames() error {
	for {
		// Next discards any unread frame payload bytes.
		err := s.fr.Next()
		if err != nil {
			return err
		}
		switch s.fr.Type {
		case FrameTypeData, FrameTypeHeaders:
			// Stop processing on DATA or HEADERS frames.
			return nil

		case FrameTypeSettings, FrameTypeGoAway, FrameTypeMaxPushID:
			// Receipt of these frame types is a connection error: H3_FRAME_UNEXPECTED.
			// TODO(ydnar): should RequestStream close the connection, rather than the caller?
			return nil

		case FrameTypeCancelPush, FrameTypePushPromise:
			// TODO: handle HTTP/3 pushes
		}
	}
}

func (s *requestStream) readData(p []byte) (n int, err error) {
	if s.dataReaderClosed {
		return 0, io.EOF
	}
	for len(p) > 0 {
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
		pp := p
		if s.fr.N < int64(len(p)) {
			pp = p[:s.fr.N]
		}
		x, err := s.fr.Read(pp)
		n += x
		p = p[x:]
		if err != nil {
			return n, err
		}
	}
	return n, nil
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
	n, err = s.w.Write(p)
	return
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

var _ io.WriteCloser = &dataWriter{}
var _ io.ReaderFrom = &dataWriter{}

func (w *dataWriter) Write(p []byte) (n int, err error) {
	return (*requestStream)(w).writeData(p)
}

func (w *dataWriter) ReadFrom(r io.Reader) (n int64, err error) {
	return (*requestStream)(w).writeDataFrom(r)
}

func (w *dataWriter) Close() error {
	return (*requestStream)(w).closeDataWriter()
}
