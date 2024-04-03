package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
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

type dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error)

var dialAddr dialFunc = quic.DialAddrEarly

type roundTripperOpts struct {
	DisableCompression bool
	EnableDatagram     bool
	MaxHeaderBytes     int64
	AdditionalSettings map[uint64]uint64
	StreamHijacker     func(FrameType, quic.ConnectionTracingID, quic.Stream, error) (hijacked bool, err error)
	UniStreamHijacker  func(StreamType, quic.ConnectionTracingID, quic.ReceiveStream, error) (hijacked bool)
}

// client is a HTTP3 client doing requests
type client struct {
	tlsConf *tls.Config
	config  *quic.Config
	opts    *roundTripperOpts

	dialOnce     sync.Once
	dialer       dialFunc
	handshakeErr error

	hconn *connection

	requestWriter *requestWriter

	decoder *qpack.Decoder

	hostname string
	conn     atomic.Pointer[quic.EarlyConnection]

	logger utils.Logger
}

var _ roundTripCloser = &client{}

func newClient(hostname string, tlsConf *tls.Config, opts *roundTripperOpts, conf *quic.Config, dialer dialFunc) (roundTripCloser, error) {
	if conf == nil {
		conf = defaultQuicConfig.Clone()
		conf.EnableDatagrams = opts.EnableDatagram
	}
	if opts.EnableDatagram && !conf.EnableDatagrams {
		return nil, errors.New("HTTP Datagrams enabled, but QUIC Datagrams disabled")
	}
	if len(conf.Versions) == 0 {
		conf = conf.Clone()
		conf.Versions = []quic.Version{protocol.SupportedVersions[0]}
	}
	if len(conf.Versions) != 1 {
		return nil, errors.New("can only use a single QUIC version for dialing a HTTP/3 connection")
	}
	if conf.MaxIncomingStreams == 0 {
		conf.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	}
	logger := utils.DefaultLogger.WithPrefix("h3 client")

	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	if tlsConf.ServerName == "" {
		sni, _, err := net.SplitHostPort(hostname)
		if err != nil {
			// It's ok if net.SplitHostPort returns an error - it could be a hostname/IP address without a port.
			sni = hostname
		}
		tlsConf.ServerName = sni
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{versionToALPN(conf.Versions[0])}

	return &client{
		hostname:      authorityAddr(hostname),
		tlsConf:       tlsConf,
		requestWriter: newRequestWriter(logger),
		decoder:       qpack.NewDecoder(func(hf qpack.HeaderField) {}),
		config:        conf,
		opts:          opts,
		dialer:        dialer,
		logger:        logger,
	}, nil
}

func (c *client) dial(ctx context.Context) error {
	var err error
	var conn quic.EarlyConnection
	if c.dialer != nil {
		conn, err = c.dialer(ctx, c.hostname, c.tlsConf, c.config)
	} else {
		conn, err = dialAddr(ctx, c.hostname, c.tlsConf, c.config)
	}
	if err != nil {
		return err
	}
	c.conn.Store(&conn)

	// send the SETTINGs frame, using 0-RTT data, if possible
	go func() {
		if err := c.setupConn(conn); err != nil {
			c.logger.Debugf("Setting up connection failed: %s", err)
			conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeInternalError), "")
		}
	}()

	if c.opts.StreamHijacker != nil {
		go c.handleBidirectionalStreams(conn)
	}
	c.hconn = newConnection(
		conn,
		c.opts.EnableDatagram,
		c.opts.UniStreamHijacker,
		protocol.PerspectiveClient,
		c.logger,
	)
	go c.hconn.HandleUnidirectionalStreams()
	return nil
}

func (c *client) setupConn(conn quic.EarlyConnection) error {
	// open the control stream
	str, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	// send the SETTINGS frame
	b = (&settingsFrame{Datagram: c.opts.EnableDatagram, Other: c.opts.AdditionalSettings}).Append(b)
	_, err = str.Write(b)
	return err
}

func (c *client) handleBidirectionalStreams(conn quic.EarlyConnection) {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			c.logger.Debugf("accepting bidirectional stream failed: %s", err)
			return
		}
		go func(str quic.Stream) {
			_, err := parseNextFrame(str, func(ft FrameType, e error) (processed bool, err error) {
				id := conn.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
				return c.opts.StreamHijacker(ft, id, str, e)
			})
			if err == errHijacked {
				return
			}
			if err != nil {
				c.logger.Debugf("error handling stream: %s", err)
			}
			conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "received HTTP/3 frame on bidirectional stream")
		}(str)
	}
}

func (c *client) Close() error {
	conn := c.conn.Load()
	if conn == nil {
		return nil
	}
	return (*conn).CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "")
}

func (c *client) maxHeaderBytes() uint64 {
	if c.opts.MaxHeaderBytes <= 0 {
		return defaultMaxResponseHeaderBytes
	}
	return uint64(c.opts.MaxHeaderBytes)
}

// RoundTripOpt executes a request and returns a response
func (c *client) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	rsp, err := c.roundTripOpt(req, opt)
	if err != nil && req.Context().Err() != nil {
		// if the context was canceled, return the context cancellation error
		err = req.Context().Err()
	}
	return rsp, err
}

func (c *client) dialConn(ctx context.Context) error {
	c.dialOnce.Do(func() {
		c.handshakeErr = c.dial(ctx)
	})
	return c.handshakeErr
}

func (c *client) roundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	if authorityAddr(hostnameFromURL(req.URL)) != c.hostname {
		return nil, fmt.Errorf("http3 client BUG: RoundTripOpt called for the wrong client (expected %s, got %s)", c.hostname, req.Host)
	}

	if err := c.dialConn(req.Context()); err != nil {
		return nil, err
	}

	// At this point, c.conn is guaranteed to be set.
	conn := *c.conn.Load()

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
		select {
		case <-conn.HandshakeComplete():
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	if opt.CheckSettings != nil {
		// wait for the server's SETTINGS frame to arrive
		select {
		case <-c.hconn.ReceivedSettings():
		case <-conn.Context().Done():
			return nil, context.Cause(conn.Context())
		}
		if err := opt.CheckSettings(*c.hconn.Settings()); err != nil {
			return nil, err
		}
	}

	str, err := conn.OpenStreamSync(req.Context())
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

	rsp, err := c.doRequest(req, conn, str, reqDone)
	if err != nil { // if any error occurred
		close(reqDone)
		<-done
		return nil, maybeReplaceError(err)
	}
	return rsp, maybeReplaceError(err)
}

func (c *client) OpenStream(ctx context.Context) (RequestStream, error) {
	if err := c.dialConn(ctx); err != nil {
		return nil, err
	}
	conn := *c.conn.Load()
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return newRequestStream(
		newStream(str, func(e ErrCode) { conn.CloseWithError(quic.ApplicationErrorCode(e), "") }),
		c.hconn,
		c.requestWriter,
		nil,
		c.decoder,
		c.opts.DisableCompression,
		c.maxHeaderBytes(),
		func(e ErrCode) { conn.CloseWithError(quic.ApplicationErrorCode(e), "") },
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

func (c *client) sendRequestBody(str Stream, body io.ReadCloser, contentLength int64) error {
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

func (c *client) doRequest(req *http.Request, conn quic.EarlyConnection, str quic.Stream, reqDone chan<- struct{}) (*http.Response, error) {
	hstr := newRequestStream(
		newStream(str, func(e ErrCode) { conn.CloseWithError(quic.ApplicationErrorCode(e), "") }),
		c.hconn,
		c.requestWriter,
		reqDone,
		c.decoder,
		c.opts.DisableCompression,
		c.maxHeaderBytes(),
		func(e ErrCode) { conn.CloseWithError(quic.ApplicationErrorCode(e), "") },
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
				c.logger.Errorf("Error writing request: %s", err)
			}
			hstr.Close()
		}()
	}

	res, err := hstr.ReadResponse()
	if err != nil {
		return nil, err
	}
	connState := conn.ConnectionState().TLS
	res.TLS = &connState
	res.Request = req
	return res, nil
}

func (c *client) HandshakeComplete() bool {
	conn := c.conn.Load()
	if conn == nil {
		return false
	}
	select {
	case <-(*conn).HandshakeComplete():
		return true
	default:
		return false
	}
}
