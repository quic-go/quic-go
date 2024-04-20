package http3

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/quic-go/qpack"
)

const (
	// MethodGet0RTT allows a GET request to be sent using 0-RTT.
	// Note that 0-RTT doesn't provide replay protection and should only be used for idempotent requests.
	MethodGet0RTT = "GET_0RTT"
	// MethodHead0RTT allows a HEAD request to be sent using 0-RTT.
	// Note that 0-RTT doesn't provide replay protection and should only be used for idempotent requests.
	MethodHead0RTT = "HEAD_0RTT"
)

const (
	defaultUserAgent              = "quic-go HTTP/3"
	defaultMaxResponseHeaderBytes = 10 * 1 << 20 // 10 MB
)

var defaultQuicConfig = &quic.Config{
	MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
	KeepAlivePeriod:    10 * time.Second,
}

// SingleDestinationRoundTripper is an HTTP/3 client doing requests to a single remote server.
type SingleDestinationRoundTripper struct {
	Connection quic.Connection

	// Enable support for HTTP/3 datagrams (RFC 9297).
	// If a QUICConfig is set, datagram support also needs to be enabled on the QUIC layer by setting EnableDatagrams.
	EnableDatagrams bool

	// Additional HTTP/3 settings.
	// It is invalid to specify any settings defined by RFC 9114 (HTTP/3) and RFC 9297 (HTTP Datagrams).
	AdditionalSettings map[uint64]uint64
	StreamHijacker     func(FrameType, quic.ConnectionTracingID, quic.Stream, error) (hijacked bool, err error)
	UniStreamHijacker  func(StreamType, quic.ConnectionTracingID, quic.ReceiveStream, error) (hijacked bool)

	// MaxResponseHeaderBytes specifies a limit on how many response bytes are
	// allowed in the server's response header.
	// Zero means to use a default limit.
	MaxResponseHeaderBytes int64

	// DisableCompression, if true, prevents the Transport from requesting compression with an
	// "Accept-Encoding: gzip" request header when the Request contains no existing Accept-Encoding value.
	// If the Transport requests gzip on its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body.
	// However, if the user explicitly requested gzip it is not automatically uncompressed.
	DisableCompression bool

	Logger *slog.Logger

	initOnce      sync.Once
	hconn         *connection
	requestWriter *requestWriter
	decoder       *qpack.Decoder
}

func (c *SingleDestinationRoundTripper) Start() Connection {
	c.initOnce.Do(func() { c.init() })
	return c.hconn
}

func (c *SingleDestinationRoundTripper) init() {
	c.requestWriter = newRequestWriter()
	c.decoder = qpack.NewDecoder(func(hf qpack.HeaderField) {})
	c.hconn = newConnection(c.Connection, c.EnableDatagrams, c.UniStreamHijacker, protocol.PerspectiveClient, c.Logger)
	// send the SETTINGs frame, using 0-RTT data, if possible
	go func() {
		if err := c.setupConn(c.Connection); err != nil {
			if c.Logger != nil {
				c.Logger.Debug("setting up connection failed", "error", err)
			}
			c.Connection.CloseWithError(quic.ApplicationErrorCode(ErrCodeInternalError), "")
		}
	}()
	if c.StreamHijacker != nil {
		go c.handleBidirectionalStreams()
	}
	go c.hconn.HandleUnidirectionalStreams()
}

func (c *SingleDestinationRoundTripper) setupConn(conn quic.Connection) error {
	// open the control stream
	str, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	// send the SETTINGS frame
	b = (&settingsFrame{Datagram: c.EnableDatagrams, Other: c.AdditionalSettings}).Append(b)
	_, err = str.Write(b)
	return err
}

func (c *SingleDestinationRoundTripper) handleBidirectionalStreams() {
	for {
		str, err := c.hconn.AcceptStream(context.Background())
		if err != nil {
			if c.Logger != nil {
				c.Logger.Debug("accepting bidirectional stream failed", "error", err)
			}
			return
		}
		go func(str quic.Stream) {
			_, err := parseNextFrame(str, func(ft FrameType, e error) (processed bool, err error) {
				id := c.hconn.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
				return c.StreamHijacker(ft, id, str, e)
			})
			if err == errHijacked {
				return
			}
			if err != nil {
				if c.Logger != nil {
					c.Logger.Debug("error handling stream", "error", err)
				}
			}
			c.hconn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "received HTTP/3 frame on bidirectional stream")
		}(str)
	}
}

func (c *SingleDestinationRoundTripper) maxHeaderBytes() uint64 {
	if c.MaxResponseHeaderBytes <= 0 {
		return defaultMaxResponseHeaderBytes
	}
	return uint64(c.MaxResponseHeaderBytes)
}

// RoundTripOpt executes a request and returns a response
func (c *SingleDestinationRoundTripper) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	c.initOnce.Do(func() { c.init() })

	rsp, err := c.roundTripOpt(req, opt)
	if err != nil && req.Context().Err() != nil {
		// if the context was canceled, return the context cancellation error
		err = req.Context().Err()
	}
	return rsp, err
}

func (c *SingleDestinationRoundTripper) roundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	// Immediately send out this request, if this is a 0-RTT request.
	switch req.Method {
	case MethodGet0RTT:
		// don't modify the original request
		reqCopy := *req
		req = &reqCopy
		req.Method = http.MethodGet
	case MethodHead0RTT:
		// don't modify the original request
		reqCopy := *req
		req = &reqCopy
		req.Method = http.MethodHead
	default:
		// wait for the handshake to complete
		earlyConn, ok := c.Connection.(quic.EarlyConnection)
		if ok {
			select {
			case <-earlyConn.HandshakeComplete():
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
	}

	if opt.CheckSettings != nil {
		connCtx := c.Connection.Context()
		// wait for the server's SETTINGS frame to arrive
		select {
		case <-c.hconn.ReceivedSettings():
		case <-connCtx.Done():
			return nil, context.Cause(connCtx)
		}
		if err := opt.CheckSettings(*c.hconn.Settings()); err != nil {
			return nil, err
		}
	}

	str, err := c.Connection.OpenStreamSync(req.Context())
	if err != nil {
		return nil, err
	}

	// Request Cancellation:
	// This go routine keeps running even after RoundTripOpt() returns.
	// It is shut down when the application is done processing the body.
	reqDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-req.Context().Done():
			str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
			str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
		case <-reqDone:
		}
	}()

	rsp, err := c.doRequest(req, str, reqDone)
	if err != nil { // if any error occurred
		close(reqDone)
		<-done
		return nil, maybeReplaceError(err)
	}
	return rsp, maybeReplaceError(err)
}

func (c *SingleDestinationRoundTripper) OpenRequestStream(ctx context.Context) (RequestStream, error) {
	c.initOnce.Do(func() { c.init() })

	str, err := c.Connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return newRequestStream(
		newStream(str, c.hconn),
		c.requestWriter,
		nil,
		c.decoder,
		c.DisableCompression,
		c.maxHeaderBytes(),
	), nil
}

// cancelingReader reads from the io.Reader.
// It cancels writing on the stream if any error other than io.EOF occurs.
type cancelingReader struct {
	r   io.Reader
	str Stream
}

func (r *cancelingReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	if err != nil && err != io.EOF {
		r.str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
	}
	return n, err
}

func (c *SingleDestinationRoundTripper) sendRequestBody(str Stream, body io.ReadCloser, contentLength int64) error {
	defer body.Close()
	buf := make([]byte, bodyCopyBufferSize)
	sr := &cancelingReader{str: str, r: body}
	if contentLength == -1 {
		_, err := io.CopyBuffer(str, sr, buf)
		return err
	}

	// make sure we don't send more bytes than the content length
	n, err := io.CopyBuffer(str, io.LimitReader(sr, contentLength), buf)
	if err != nil {
		return err
	}
	var extra int64
	extra, err = io.CopyBuffer(io.Discard, sr, buf)
	n += extra
	if n > contentLength {
		str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
		return fmt.Errorf("http: ContentLength=%d with Body length %d", contentLength, n)
	}
	return err
}

func (c *SingleDestinationRoundTripper) doRequest(req *http.Request, str quic.Stream, reqDone chan<- struct{}) (*http.Response, error) {
	hstr := newRequestStream(
		newStream(str, c.hconn),
		c.requestWriter,
		reqDone,
		c.decoder,
		c.DisableCompression,
		c.maxHeaderBytes(),
	)
	if err := hstr.SendRequestHeader(req); err != nil {
		return nil, err
	}
	if req.Body == nil {
		hstr.Close()
	} else {
		// send the request body asynchronously
		go func() {
			contentLength := int64(-1)
			// According to the documentation for http.Request.ContentLength,
			// a value of 0 with a non-nil Body is also treated as unknown content length.
			if req.ContentLength > 0 {
				contentLength = req.ContentLength
			}
			if err := c.sendRequestBody(hstr, req.Body, contentLength); err != nil {
				if c.Logger != nil {
					c.Logger.Debug("error writing request", "error", err)
				}
			}
			hstr.Close()
		}()
	}

	res, err := hstr.ReadResponse()
	if err != nil {
		return nil, err
	}
	connState := c.Connection.ConnectionState().TLS
	res.TLS = &connState
	res.Request = req
	return res, nil
}
