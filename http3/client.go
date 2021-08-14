package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qtls"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
)

// MethodGet0RTT allows a GET request to be sent using 0-RTT.
// Note that 0-RTT data doesn't provide replay protection.
const MethodGet0RTT = "GET_0RTT"

const (
	defaultUserAgent              = "quic-go HTTP/3"
	defaultMaxResponseHeaderBytes = 10 * 1 << 20 // 10 MB
)

var defaultQuicConfig = &quic.Config{
	MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
	KeepAlive:          true,
	Versions:           []protocol.VersionNumber{protocol.VersionTLS},
}

var dialAddr = quic.DialAddrEarly

type roundTripperOpts struct {
	DisableCompression bool
	EnableDatagrams    bool
	MaxHeaderBytes     int64
	Settings           Settings
}

// client is a HTTP3 client doing requests
type client struct {
	tlsConf *tls.Config
	config  *quic.Config
	opts    *roundTripperOpts

	dialOnce     sync.Once
	dialer       func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error)
	handshakeErr error

	requestWriter *requestWriter

	authority string
	conn      ClientConn

	logger utils.Logger
}

func newClient(
	authority string,
	tlsConf *tls.Config,
	opts *roundTripperOpts,
	quicConfig *quic.Config,
	dialer func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error),
) (*client, error) {
	if quicConfig == nil {
		quicConfig = defaultQuicConfig.Clone()
	} else if len(quicConfig.Versions) == 0 {
		quicConfig = quicConfig.Clone()
		quicConfig.Versions = []quic.VersionNumber{defaultQuicConfig.Versions[0]}
	}
	if len(quicConfig.Versions) != 1 {
		return nil, errors.New("can only use a single QUIC version for dialing a HTTP/3 connection")
	}
	quicConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	quicConfig.EnableDatagrams = opts.EnableDatagrams
	logger := utils.DefaultLogger.WithPrefix("h3 client")

	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{versionToALPN(quicConfig.Versions[0])}

	return &client{
		authority:     authorityAddr("https", authority),
		tlsConf:       tlsConf,
		requestWriter: newRequestWriter(logger),
		config:        quicConfig,
		opts:          opts,
		dialer:        dialer,
		logger:        logger,
	}, nil
}

func (c *client) settings() Settings {
	if c.opts.Settings != nil {
		return c.opts.Settings
	}
	settings := Settings{}
	if c.opts.EnableDatagrams {
		settings.EnableDatagrams()
	}
	return settings
}

func (c *client) dial() error {
	var s quic.EarlySession
	var err error
	if c.dialer != nil {
		s, err = c.dialer("udp", c.authority, c.tlsConf, c.config)
	} else {
		s, err = dialAddr(c.authority, c.tlsConf, c.config)
	}
	if err != nil {
		return err
	}

	c.conn, err = Open(s, c.settings())
	if err != nil {
		c.logger.Errorf("unable to open HTTP/3 connection: %s", err)
		c.conn.CloseWithError(quic.ApplicationErrorCode(errorInternalError), "")
		return err
	}

	go c.handleUnidirectionalStreams()

	return nil
}

func (c *client) handleUnidirectionalStreams() {
	for {
		str, err := c.conn.AcceptUniStream(context.Background())
		if err != nil {
			c.logger.Debugf("accepting unidirectional stream failed: %s", err)
			return
		}

		// TODO: handle unknown stream types
		str.CancelRead(quic.StreamErrorCode(errorStreamCreationError))
	}
}

func (c *client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.CloseWithError(quic.ApplicationErrorCode(errorNoError), "")
}

func (c *client) maxHeaderBytes() uint64 {
	if c.opts.MaxHeaderBytes <= 0 {
		return defaultMaxResponseHeaderBytes
	}
	return uint64(c.opts.MaxHeaderBytes)
}

// RoundTrip executes a request and returns a response
func (c *client) RoundTrip(req *http.Request) (*http.Response, error) {
	if authorityAddr("https", hostnameFromRequest(req)) != c.authority {
		return nil, fmt.Errorf("http3 client BUG: RoundTrip called for the wrong client (expected %s, got %s)", c.authority, req.Host)
	}

	c.dialOnce.Do(func() {
		c.handshakeErr = c.dial()
	})

	if c.handshakeErr != nil {
		return nil, c.handshakeErr
	}

	// Immediately send out this request, if this is a 0-RTT request.
	if req.Method == MethodGet0RTT {
		req.Method = http.MethodGet
	} else {
		// wait for the handshake to complete
		select {
		case <-c.conn.HandshakeComplete().Done():
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	str, err := c.conn.OpenRequestStream(req.Context())
	if err != nil {
		return nil, err
	}

	// Request Cancellation:
	// This go routine keeps running even after RoundTrip() returns.
	// It is shut down when the application is done processing the body.
	reqDone := make(chan struct{})
	go func() {
		select {
		case <-req.Context().Done():
			str.CancelWrite(quic.StreamErrorCode(errorRequestCanceled))
			str.CancelRead(quic.StreamErrorCode(errorRequestCanceled))
		case <-reqDone:
		}
	}()

	rsp, rerr := c.doRequest(req, str, reqDone)
	if rerr.err != nil { // if any error occurred
		close(reqDone)
		if rerr.streamErr != 0 { // if it was a stream error
			str.CancelWrite(quic.StreamErrorCode(rerr.streamErr))
		}
		if rerr.connErr != 0 { // if it was a connection error
			var reason string
			if rerr.err != nil {
				reason = rerr.err.Error()
			}
			c.conn.CloseWithError(quic.ApplicationErrorCode(rerr.connErr), reason)
		}
	}
	return rsp, rerr.err
}

func (c *client) doRequest(
	req *http.Request,
	str quic.Stream,
	reqDone chan struct{},
) (*http.Response, requestError) {
	var requestGzip bool
	if !c.opts.DisableCompression && req.Method != "HEAD" && req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		requestGzip = true
	}
	if err := c.requestWriter.WriteRequest(str, req, requestGzip); err != nil {
		return nil, newStreamError(errorInternalError, err)
	}

	frame, err := parseNextFrame(str)
	if err != nil {
		return nil, newStreamError(errorFrameError, err)
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		return nil, newConnError(errorFrameUnexpected, errors.New("expected first frame to be a HEADERS frame"))
	}
	if hf.len > c.maxHeaderBytes() {
		return nil, newStreamError(errorFrameError, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", hf.len, c.maxHeaderBytes()))
	}
	headerBlock := make([]byte, hf.len)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		return nil, newStreamError(errorRequestIncomplete, err)
	}
	decoder := qpack.NewDecoder(nil)
	hfs, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		return nil, newConnError(errorGeneralProtocolError, err)
	}

	connState := qtls.ToTLSConnectionState(c.conn.ConnectionState().TLS)
	res := &http.Response{
		Proto:      "HTTP/3",
		ProtoMajor: 3,
		Header:     http.Header{},
		TLS:        &connState,
	}
	for _, hf := range hfs {
		switch hf.Name {
		case ":status":
			status, err := strconv.Atoi(hf.Value)
			if err != nil {
				return nil, newStreamError(errorGeneralProtocolError, errors.New("malformed non-numeric status pseudo header"))
			}
			res.StatusCode = status
			res.Status = hf.Value + " " + http.StatusText(status)
		default:
			res.Header.Add(hf.Name, hf.Value)
		}
	}
	respBody := newResponseBody(str, reqDone, func() {
		c.conn.CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), "")
	})

	// Rules for when to set Content-Length are defined in https://tools.ietf.org/html/rfc7230#section-3.3.2.
	_, hasTransferEncoding := res.Header["Transfer-Encoding"]
	isInformational := res.StatusCode >= 100 && res.StatusCode < 200
	isNoContent := res.StatusCode == 204
	isSuccessfulConnect := req.Method == http.MethodConnect && res.StatusCode >= 200 && res.StatusCode < 300
	if !hasTransferEncoding && !isInformational && !isNoContent && !isSuccessfulConnect {
		res.ContentLength = -1
		if clens, ok := res.Header["Content-Length"]; ok && len(clens) == 1 {
			if clen64, err := strconv.ParseInt(clens[0], 10, 64); err == nil {
				res.ContentLength = clen64
			}
		}
	}

	if requestGzip && res.Header.Get("Content-Encoding") == "gzip" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Body = newGzipReader(respBody)
		res.Uncompressed = true
	} else {
		res.Body = respBody
	}

	return res, requestError{}
}
