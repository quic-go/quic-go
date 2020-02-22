package http3

import (
	"bytes"
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
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
)

// MethodGet0RTT allows a GET request to be sent using 0-RTT.
// Note that 0-RTT data doesn't provide replay protection.
const MethodGet0RTT = "GET_0RTT"

const defaultUserAgent = "quic-go HTTP/3"
const defaultMaxResponseHeaderBytes = 10 * 1 << 20 // 10 MB

var defaultQuicConfig = &quic.Config{
	MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
	KeepAlive:          true,
}

var dialAddr = quic.DialAddrEarly

type roundTripperOpts struct {
	DisableCompression bool
	MaxHeaderBytes     int64
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

	decoder *qpack.Decoder

	hostname string
	session  quic.EarlySession

	logger utils.Logger

	clientContext context.Context
	clientCancel  context.CancelFunc
	goawayChan    chan protocol.StreamID
}

func newClient(
	hostname string,
	tlsConf *tls.Config,
	opts *roundTripperOpts,
	quicConfig *quic.Config,
	dialer func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error),
) *client {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{nextProtoH3}
	if quicConfig == nil {
		quicConfig = defaultQuicConfig
	}
	quicConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	logger := utils.DefaultLogger.WithPrefix("h3 client")

	ctx, cancel := context.WithCancel(context.Background())

	return &client{
		hostname:      authorityAddr("https", hostname),
		tlsConf:       tlsConf,
		requestWriter: newRequestWriter(logger),
		decoder:       qpack.NewDecoder(func(hf qpack.HeaderField) {}),
		config:        quicConfig,
		opts:          opts,
		dialer:        dialer,
		logger:        logger,
		clientContext: ctx,
		clientCancel:  cancel,
		goawayChan:    make(chan protocol.StreamID),
	}
}

func (c *client) dial() error {
	var err error
	if c.dialer != nil {
		c.session, err = c.dialer("udp", c.hostname, c.tlsConf, c.config)
	} else {
		c.session, err = dialAddr(c.hostname, c.tlsConf, c.config)
	}
	if err != nil {
		return err
	}

	// run the sesssion setup using 0-RTT data
	// go func() {
	if rerr := c.setupSession(); rerr.HasError() {
		c.logger.Debugf("Setting up session failed: %s", rerr)
		c.session.CloseWithError(quic.ErrorCode(rerr.connErr), "")
	}
	// }()

	return nil
}

func (c *client) setupSession() requestError {
	// open the control stream
	str, err := c.session.OpenUniStream()
	if err != nil {
		return newConnError(errorMissingSettings, err)
	}
	buf := &bytes.Buffer{}
	// write the type byte
	buf.Write([]byte{0x0})
	// send the SETTINGS frame
	(&settingsFrame{}).Write(buf)
	if _, err := str.Write(buf.Bytes()); err != nil {
		return newConnError(errorMissingSettings, err)
	}

	controlStreamIn, err := c.session.AcceptUniStream(context.Background())
	if err != nil {
		c.logger.Debugf("Accepting the incoming control stream failed.")
		return newConnError(errorInternalError, err)
	}

	br, ok := controlStreamIn.(byteReader)
	if !ok {
		br = &byteReaderImpl{controlStreamIn}
	}
	t, err := utils.ReadVarInt(br)
	if t != 0x0 {
		c.logger.Debugf("First stream must be a control stream")
		return newConnError(errorMissingSettings, err)
	}

	frame, err := parseNextFrame(controlStreamIn)
	if err != nil {
		c.logger.Debugf("Error encountered while parsing incoming frame")
		return newConnError(errorStreamCreationError, err)
	}
	sf, ok := frame.(*settingsFrame)
	if !ok {
		c.logger.Debugf("First incoming frame parsed was not a settings frame")
		return newConnError(errorMissingSettings, nil)
	}
	// TODO: do something with the settings frame
	c.logger.Debugf("Got settings frame: %+v", sf)
	go func() {
		for {
			frame, err := parseNextFrame(controlStreamIn)
			if err != nil {
				// Hack
				if err.Error() == "Application error 0x100" {
					c.logger.Debugf("Closing control streams")
					return
				}
				c.logger.Debugf("Error encountered while parsing incoming frame: %s", err)
				return
			}
			switch f := frame.(type) {
			case *goawayFrame:
				c.logger.Debugf("Received goaway frame, halting requests with streamID >= %d", f.StreamID)
				c.clientCancel()
				c.goawayChan <- f.StreamID
				c.clientContext, c.clientCancel = context.WithCancel(context.Background())
			default:
				c.logger.Debugf("Received frame %+v", f)
			}
		}
	}()

	return requestError{}
}

func (c *client) Close() error {
	return c.session.CloseWithError(quic.ErrorCode(errorNoError), "")
}

func (c *client) maxHeaderBytes() uint64 {
	if c.opts.MaxHeaderBytes <= 0 {
		return defaultMaxResponseHeaderBytes
	}
	return uint64(c.opts.MaxHeaderBytes)
}

// RoundTrip executes a request and returns a response
func (c *client) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.clientContext.Err() != nil {
		return nil, errors.New("server is no longer accepting requests")
	}
	if req.URL.Scheme != "https" {
		return nil, errors.New("http3: unsupported scheme")
	}
	if authorityAddr("https", hostnameFromRequest(req)) != c.hostname {
		return nil, fmt.Errorf("http3 client BUG: RoundTrip called for the wrong client (expected %s, got %s)", c.hostname, req.Host)
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
		case <-c.session.HandshakeComplete().Done():
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	ctx, cancel := context.WithCancel(c.clientContext)
	defer cancel()
	str, err := c.session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	// Request Cancellation:
	// This go routine keeps running even after RoundTrip() returns.
	// It is shut down when the application is done processing the body.
	reqDone := make(chan struct{})
	go c.requestCancelled(str, req, reqDone)

	rsp, rerr := c.doRequest(req, str, reqDone)
	if rerr.err != nil { // if any error occurred
		close(reqDone)
		if rerr.streamErr != 0 { // if it was a stream error
			str.CancelWrite(quic.ErrorCode(rerr.streamErr))
		}
		if rerr.connErr != 0 { // if it was a connection error
			var reason string
			if rerr.err != nil {
				reason = rerr.err.Error()
			}
			c.session.CloseWithError(quic.ErrorCode(rerr.connErr), reason)
		}
	}
	return rsp, rerr.err
}

func (c *client) requestCancelled(str quic.Stream, req *http.Request, reqDone <-chan struct{}) {
	select {
	case id := <-c.goawayChan:
		// if goaway was sent we need to check it and put it back on the channel
		// so other requests can check as well
		if str.StreamID() >= id {
			str.CancelWrite(quic.ErrorCode(errorRequestCanceled))
			str.CancelRead(quic.ErrorCode(errorRequestCanceled))
			return
		}
		c.goawayChan <- id
	case <-req.Context().Done():
		str.CancelWrite(quic.ErrorCode(errorRequestCanceled))
		str.CancelRead(quic.ErrorCode(errorRequestCanceled))

		return
	case <-reqDone:
		return
	}
	// continue processing request if our streamID < goaway streamID
	select {
	case <-req.Context().Done():
		str.CancelWrite(quic.ErrorCode(errorRequestCanceled))
		str.CancelRead(quic.ErrorCode(errorRequestCanceled))
	case <-reqDone:
	}
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
	if hf.Length > c.maxHeaderBytes() {
		return nil, newStreamError(errorFrameError, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", hf.Length, c.maxHeaderBytes()))
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		return nil, newStreamError(errorRequestIncomplete, err)
	}
	hfs, err := c.decoder.DecodeFull(headerBlock)
	if err != nil {
		// TODO: use the right error code
		return nil, newConnError(errorGeneralProtocolError, err)
	}

	res := &http.Response{
		Proto:      "HTTP/3",
		ProtoMajor: 3,
		Header:     http.Header{},
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
		c.session.CloseWithError(quic.ErrorCode(errorFrameUnexpected), "")
	})
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
