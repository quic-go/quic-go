package http3

import (
	"context"
	"errors"
	"fmt"
	"github.com/Noooste/fhttp"
	"io"
	"net/http/httptrace"

	"github.com/Noooste/uquic-go"
	"github.com/Noooste/uquic-go/internal/protocol"

	"github.com/quic-go/qpack"
)

type datagramStream interface {
	quic.Stream
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

// A Stream is an HTTP/3 request stream.
// When writing to and reading from the stream, data is framed in HTTP/3 DATA frames.
type Stream struct {
	datagramStream
	conn *connection

	buf []byte // used as a temporary buffer when writing the HTTP/3 frame headers

	bytesRemainingInFrame uint64

	parseTrailer  func(io.Reader, uint64) error
	parsedTrailer bool
}

func newStream(str datagramStream, conn *connection, parseTrailer func(io.Reader, uint64) error) *Stream {
	return &Stream{
		datagramStream: str,
		conn:           conn,
		buf:            make([]byte, 16),
		parseTrailer:   parseTrailer,
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	fp := &frameParser{
		r:    s.datagramStream,
		conn: s.conn,
	}
	if s.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := fp.ParseNext()
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *dataFrame:
				if s.parsedTrailer {
					return 0, errors.New("DATA frame received after trailers")
				}
				s.bytesRemainingInFrame = f.Length
				break parseLoop
			case *headersFrame:
				if s.conn.perspective == protocol.PerspectiveServer {
					continue
				}
				if s.parsedTrailer {
					return 0, errors.New("additional HEADERS frame received after trailers")
				}
				s.parsedTrailer = true
				return 0, s.parseTrailer(s.datagramStream, f.Length)
			default:
				s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if s.bytesRemainingInFrame < uint64(len(b)) {
		n, err = s.datagramStream.Read(b[:s.bytesRemainingInFrame])
	} else {
		n, err = s.datagramStream.Read(b)
	}
	s.bytesRemainingInFrame -= uint64(n)
	return n, err
}

func (s *Stream) hasMoreData() bool {
	return s.bytesRemainingInFrame > 0
}

func (s *Stream) Write(b []byte) (int, error) {
	s.buf = s.buf[:0]
	s.buf = (&dataFrame{Length: uint64(len(b))}).Append(s.buf)
	if _, err := s.datagramStream.Write(s.buf); err != nil {
		return 0, err
	}
	return s.datagramStream.Write(b)
}

func (s *Stream) writeUnframed(b []byte) (int, error) {
	return s.datagramStream.Write(b)
}

func (s *Stream) StreamID() protocol.StreamID {
	return s.datagramStream.StreamID()
}

// A RequestStream is a low-level abstraction representing an HTTP/3 request stream.
// It decouples sending of the HTTP request from reading the HTTP response, allowing
// the application to optimistically use the stream (and, for example, send datagrams)
// before receiving the response.
type RequestStream struct {
	*Stream

	responseBody io.ReadCloser // set by ReadResponse

	decoder            *qpack.Decoder
	requestWriter      *requestWriter
	maxHeaderBytes     uint64
	reqDone            chan<- struct{}
	disableCompression bool
	response           *http.Response
	trace              *httptrace.ClientTrace

	sentRequest   bool
	requestedGzip bool
	isConnect     bool
	firstByte     bool
}

func newRequestStream(
	str *Stream,
	requestWriter *requestWriter,
	reqDone chan<- struct{},
	decoder *qpack.Decoder,
	disableCompression bool,
	maxHeaderBytes uint64,
	rsp *http.Response,
	trace *httptrace.ClientTrace,
) *RequestStream {
	return &RequestStream{
		Stream:             str,
		requestWriter:      requestWriter,
		reqDone:            reqDone,
		decoder:            decoder,
		disableCompression: disableCompression,
		maxHeaderBytes:     maxHeaderBytes,
		response:           rsp,
		trace:              trace,
	}
}

func (s *RequestStream) Read(b []byte) (int, error) {
	if s.responseBody == nil {
		return 0, errors.New("http3: invalid use of RequestStream.Read: need to call ReadResponse first")
	}
	return s.responseBody.Read(b)
}

// SendRequestHeader sends the HTTP request.
// It is invalid to call it more than once.
// It is invalid to call it after Write has been called.
func (s *RequestStream) SendRequestHeader(req *http.Request) error {
	if s.sentRequest {
		return errors.New("http3: invalid duplicate use of SendRequestHeader")
	}
	if !s.disableCompression && req.Method != http.MethodHead &&
		req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		s.requestedGzip = true
	}
	s.isConnect = req.Method == http.MethodConnect
	s.sentRequest = true
	return s.requestWriter.WriteRequestHeader(s.datagramStream, req, s.requestedGzip)
}

// ReadResponse reads the HTTP response from the stream.
// It is invalid to call it more than once.
// It doesn't set Response.Request and Response.TLS.
// It is invalid to call it after Read has been called.
func (s *RequestStream) ReadResponse() (*http.Response, error) {
	qstr := s.datagramStream
	fp := &frameParser{
		conn: s.conn,
		r: &tracingReader{
			Reader: qstr,
			first:  &s.firstByte,
			trace:  s.trace,
		},
	}
	frame, err := fp.ParseNext()
	if err != nil {
		s.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: parsing frame failed: %w", err)
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "expected first frame to be a HEADERS frame")
		return nil, errors.New("http3: expected first frame to be a HEADERS frame")
	}
	if hf.Length > s.maxHeaderBytes {
		s.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: HEADERS frame too large: %d bytes (max: %d)", hf.Length, s.maxHeaderBytes)
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(qstr, headerBlock); err != nil {
		s.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		s.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		return nil, fmt.Errorf("http3: failed to read response headers: %w", err)
	}
	hfs, err := s.decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeGeneralProtocolError), "")
		return nil, fmt.Errorf("http3: failed to decode response headers: %w", err)
	}
	res := s.response
	if err := updateResponseFromHeaders(res, hfs); err != nil {
		s.CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
		s.CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
		return nil, fmt.Errorf("http3: invalid response: %w", err)
	}

	// Check that the server doesn't send more data in DATA frames than indicated by the Content-Length header (if set).
	// See section 4.1.2 of RFC 9114.
	respBody := newResponseBody(s.Stream, res.ContentLength, s.reqDone)

	// Rules for when to set Content-Length are defined in https://tools.ietf.org/html/rfc7230#section-3.3.2.
	isInformational := res.StatusCode >= 100 && res.StatusCode < 200
	isNoContent := res.StatusCode == http.StatusNoContent
	isSuccessfulConnect := s.isConnect && res.StatusCode >= 200 && res.StatusCode < 300
	if (isInformational || isNoContent || isSuccessfulConnect) && res.ContentLength == -1 {
		res.ContentLength = 0
	}
	if s.requestedGzip && res.Header.Get("Content-Encoding") == "gzip" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		s.responseBody = newGzipReader(respBody)
		res.Uncompressed = true
	} else {
		s.responseBody = respBody
	}
	res.Body = s.responseBody
	return res, nil
}

func (s *Stream) SendDatagram(b []byte) error {
	// TODO: reject if datagrams are not negotiated (yet)
	return s.datagramStream.SendDatagram(b)
}

func (s *Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	// TODO: reject if datagrams are not negotiated (yet)
	return s.datagramStream.ReceiveDatagram(ctx)
}

type tracingReader struct {
	io.Reader
	first *bool
	trace *httptrace.ClientTrace
}

func (r *tracingReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if n > 0 && r.first != nil && !*r.first {
		traceGotFirstResponseByte(r.trace)
		*r.first = true
	}
	return n, err
}
