package http3

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go"

	"github.com/quic-go/qpack"
)

// A Stream is an HTTP/3 request stream.
// When writing to and reading from the stream, data is framed in HTTP/3 DATA frames.
type Stream = quic.Stream

// A RequestStream is an HTTP/3 request stream.
// When writing to and reading from the stream, data is framed in HTTP/3 DATA frames.
type RequestStream interface {
	quic.Stream

	// SendRequestHeader sends the HTTP request.
	// It is invalid to call it more than once.
	// It is invalid to call it after Write has been called.
	SendRequestHeader(req *http.Request) error

	// ReadResponse reads the HTTP response from the stream.
	// It is invalid to call it more than once.
	// It doesn't set Response.Request and Response.TLS.
	// It is invalid to call it after Read has been called.
	ReadResponse() (*http.Response, error)
}

type stream struct {
	quic.Stream
	closeConnection func(ErrCode)

	buf []byte // used as a temporary buffer when writing the HTTP/3 frame headers

	bytesRemainingInFrame uint64
}

var _ Stream = &stream{}

func newStream(str quic.Stream, closeConnection func(ErrCode)) *stream {
	return &stream{
		Stream:          str,
		closeConnection: closeConnection,
		buf:             make([]byte, 0, 16),
	}
}

func (s *stream) Read(b []byte) (int, error) {
	if s.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := parseNextFrame(s.Stream, nil)
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *headersFrame:
				// skip HEADERS frames
				continue
			case *dataFrame:
				s.bytesRemainingInFrame = f.Length
				break parseLoop
			default:
				s.closeConnection(ErrCodeFrameUnexpected)
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if s.bytesRemainingInFrame < uint64(len(b)) {
		n, err = s.Stream.Read(b[:s.bytesRemainingInFrame])
	} else {
		n, err = s.Stream.Read(b)
	}
	s.bytesRemainingInFrame -= uint64(n)
	return n, err
}

func (s *stream) hasMoreData() bool {
	return s.bytesRemainingInFrame > 0
}

func (s *stream) Write(b []byte) (int, error) {
	s.buf = s.buf[:0]
	s.buf = (&dataFrame{Length: uint64(len(b))}).Append(s.buf)
	if _, err := s.Stream.Write(s.buf); err != nil {
		return 0, err
	}
	return s.Stream.Write(b)
}

// The stream conforms to the quic.Stream interface, but instead of writing to and reading directly
// from the QUIC stream, it writes to and reads from the HTTP stream.
type requestStream struct {
	*stream

	conn quic.Connection

	responseBody io.ReadCloser // set by ReadResponse

	decoder            *qpack.Decoder
	requestWriter      *requestWriter
	closeConnection    func(ErrCode)
	maxHeaderBytes     uint64
	reqDone            chan<- struct{}
	disableCompression bool

	sentRequest   bool
	requestedGzip bool
	isConnect     bool
}

var _ RequestStream = &requestStream{}

func newRequestStream(
	str *stream,
	conn quic.Connection,
	requestWriter *requestWriter,
	reqDone chan<- struct{},
	decoder *qpack.Decoder,
	disableCompression bool,
	maxHeaderBytes uint64,
	closeConnection func(ErrCode),
) *requestStream {
	return &requestStream{
		stream:             str,
		conn:               conn,
		requestWriter:      requestWriter,
		reqDone:            reqDone,
		decoder:            decoder,
		disableCompression: disableCompression,
		closeConnection:    closeConnection,
		maxHeaderBytes:     maxHeaderBytes,
	}
}

func (s *requestStream) Read(b []byte) (int, error) {
	if s.responseBody == nil {
		return 0, errors.New("http3: invalid use of RequestStream.Read: need to call ReadResponse first")
	}
	return s.responseBody.Read(b)
}

func (s *requestStream) SendRequestHeader(req *http.Request) error {
	if s.sentRequest {
		return errors.New("http3: invalid duplicate use of SendRequestHeader")
	}
	if !s.disableCompression && req.Method != http.MethodHead &&
		req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		s.requestedGzip = true
	}
	s.isConnect = req.Method == http.MethodConnect
	s.sentRequest = true
	return s.requestWriter.WriteRequestHeader(s.Stream, req, s.requestedGzip)
}

func (s *requestStream) ReadResponse() (*http.Response, error) {
	frame, err := parseNextFrame(s.Stream, nil)
	if err != nil {
		s.Stream.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.Stream.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: parsing frame failed: %w", err)
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		s.closeConnection(ErrCodeFrameUnexpected)
		return nil, errors.New("http3: expected first frame to be a HEADERS frame")
	}
	if hf.Length > s.maxHeaderBytes {
		s.Stream.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.Stream.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: HEADERS frame too large: %d bytes (max: %d)", hf.Length, s.maxHeaderBytes)
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(s.Stream, headerBlock); err != nil {
		s.Stream.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		s.Stream.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		return nil, fmt.Errorf("http3: failed to read response headers: %w", err)
	}
	hfs, err := s.decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		s.closeConnection(ErrCodeGeneralProtocolError)
		return nil, fmt.Errorf("http3: failed to decode response headers: %w", err)
	}

	res, err := responseFromHeaders(hfs)
	if err != nil {
		s.Stream.CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
		s.Stream.CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
		return nil, fmt.Errorf("http3: invalid response: %w", err)
	}

	// Check that the server doesn't send more data in DATA frames than indicated by the Content-Length header (if set).
	// See section 4.1.2 of RFC 9114.
	var httpStr Stream
	if _, ok := res.Header["Content-Length"]; ok && res.ContentLength >= 0 {
		httpStr = newLengthLimitedStream(s.stream, res.ContentLength)
	} else {
		httpStr = s.stream
	}
	respBody := newResponseBody(httpStr, s.reqDone)

	// Rules for when to set Content-Length are defined in https://tools.ietf.org/html/rfc7230#section-3.3.2.
	_, hasTransferEncoding := res.Header["Transfer-Encoding"]
	isInformational := res.StatusCode >= 100 && res.StatusCode < 200
	isNoContent := res.StatusCode == http.StatusNoContent
	isSuccessfulConnect := s.isConnect && res.StatusCode >= 200 && res.StatusCode < 300
	if !hasTransferEncoding && !isInformational && !isNoContent && !isSuccessfulConnect {
		res.ContentLength = -1
		if clens, ok := res.Header["Content-Length"]; ok && len(clens) == 1 {
			if clen64, err := strconv.ParseInt(clens[0], 10, 64); err == nil {
				res.ContentLength = clen64
			}
		}
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

var errTooMuchData = errors.New("peer sent too much data")

type lengthLimitedStream struct {
	*stream

	contentLength int64
	read          int64
	resetStream   bool
}

var _ Stream = &lengthLimitedStream{}

func newLengthLimitedStream(str *stream, contentLength int64) *lengthLimitedStream {
	return &lengthLimitedStream{
		stream:        str,
		contentLength: contentLength,
	}
}

func (s *lengthLimitedStream) checkContentLengthViolation() error {
	if s.read > s.contentLength || s.read == s.contentLength && s.hasMoreData() {
		if !s.resetStream {
			s.CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
			s.CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
			s.resetStream = true
		}
		return errTooMuchData
	}
	return nil
}

func (s *lengthLimitedStream) Read(b []byte) (int, error) {
	if err := s.checkContentLengthViolation(); err != nil {
		return 0, err
	}
	n, err := s.stream.Read(b[:min(int64(len(b)), s.contentLength-s.read)])
	s.read += int64(n)
	if err := s.checkContentLengthViolation(); err != nil {
		return n, err
	}
	return n, err
}
