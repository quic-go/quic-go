package h2quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/idna"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type roundTripperOpts struct {
	DisableCompression bool
}

var dialAddr = quic.DialAddr

// client is a HTTP2 client doing QUIC requests
type client struct {
	mutex sync.RWMutex

	tlsConf *tls.Config
	config  *quic.Config
	opts    *roundTripperOpts

	hostname        string
	encryptionLevel protocol.EncryptionLevel
	handshakeErr    error
	dialOnce        sync.Once

	session       quic.Session
	headerStream  quic.Stream
	headerErr     *qerr.QuicError
	headerErrored chan struct{} // this channel is closed if an error occurs on the header stream
	requestWriter *requestWriter

	responses map[protocol.StreamID]chan *http.Response

	pushedResponses map[string]*http.Response
}

var _ http.RoundTripper = &client{}

var defaultQuicConfig = &quic.Config{
	RequestConnectionIDTruncation: true,
	KeepAlive:                     true,
}

// newClient creates a new client
func newClient(
	hostname string,
	tlsConfig *tls.Config,
	opts *roundTripperOpts,
	quicConfig *quic.Config,
) *client {
	config := defaultQuicConfig
	if quicConfig != nil {
		config = quicConfig
	}
	return &client{
		hostname:        authorityAddr("https", hostname),
		responses:       make(map[protocol.StreamID]chan *http.Response),
		pushedResponses: make(map[string]*http.Response),
		encryptionLevel: protocol.EncryptionUnencrypted,
		tlsConf:         tlsConfig,
		config:          config,
		opts:            opts,
		headerErrored:   make(chan struct{}),
	}
}

// dial dials the connection
func (c *client) dial() error {
	var err error
	c.session, err = dialAddr(c.hostname, c.tlsConf, c.config)
	if err != nil {
		return err
	}

	// once the version has been negotiated, open the header stream
	c.headerStream, err = c.session.OpenStream()
	if err != nil {
		return err
	}
	if c.headerStream.StreamID() != 3 {
		return errors.New("h2quic Client BUG: StreamID of Header Stream is not 3")
	}
	c.requestWriter = newRequestWriter(c.headerStream)
	go c.handleHeaderStream()
	return nil
}

func (c *client) handleHeaderStream() {
	decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
	h2framer := http2.NewFramer(nil, c.headerStream)

	var lastStream protocol.StreamID

	for {
		frame, err := h2framer.ReadFrame()
		if err != nil {
			c.headerErr = qerr.Error(qerr.HeadersStreamDataDecompressFailure, "cannot read frame")
			break
		}
		var mhframe *http2.MetaHeadersFrame
		lastStream = protocol.StreamID(frame.Header().StreamID)
		hframe, ok := frame.(*http2.HeadersFrame)
		if !ok {
			pushFrame, pushOk := frame.(*http2.PushPromiseFrame)
			if !pushOk {
				c.headerErr = qerr.Error(qerr.InvalidHeadersStreamData, "not a headers or push_promise frame")
				break
			}
			utils.Infof("Received PUSH_PROMISE on stream %d, push will be on stream %d, for original data on stream %d", c.headerStream.StreamID(), pushFrame.PromiseID, pushFrame.StreamID)
			err = c.handlePushPromise(decoder, pushFrame)
			if err != nil {
				break
			}
			continue
		}
		mhframe = &http2.MetaHeadersFrame{HeadersFrame: hframe}
		mhframe.Fields, err = decoder.DecodeFull(hframe.HeaderBlockFragment())
		if err != nil {
			c.headerErr = qerr.Error(qerr.InvalidHeadersStreamData, "cannot read header fields")
			break
		}

		rsp, err := responseFromHeaders(mhframe)
		if err != nil {
			c.headerErr = qerr.Error(qerr.InternalError, err.Error())
		}

		c.mutex.RLock()
		responseChan, ok := c.responses[protocol.StreamID(hframe.StreamID)]
		c.mutex.RUnlock()
		if !ok {
			c.headerErr = qerr.Error(qerr.InternalError, fmt.Sprintf("h2client BUG: response channel for stream %d not found", lastStream))
			break
		}

		responseChan <- rsp
	}

	// stop all running request
	utils.Debugf("Error handling header stream %d: %s", lastStream, c.headerErr.Error())
	close(c.headerErrored)
}

func (c *client) handlePushPromise(decoder *hpack.Decoder, pushFrame *http2.PushPromiseFrame) error {
	var err error
	mhframe := &http2.MetaHeadersFrame{}
	mhframe.Fields, err = decoder.DecodeFull(pushFrame.HeaderBlockFragment())
	if err != nil {
		c.headerErr = qerr.Error(qerr.InvalidHeadersStreamData, "cannot read header fields")
		return errors.New(c.headerErr.Error())
	}
	req, err := requestFromHeaders(mhframe.Fields)
	if err != nil {
		c.headerErr = qerr.Error(qerr.InvalidHeadersStreamData, err.Error())
		return err
	}

	pushStreamID := protocol.StreamID(pushFrame.PromiseID)
	responseChan := make(chan *http.Response)

	c.mutex.Lock()
	c.responses[pushStreamID] = responseChan
	c.mutex.Unlock()

	// Now somebody needs to handle this responseChan for the arrival of the
	go c.receivePushData(responseChan, req, pushStreamID)
	return nil
}

func (c *client) receivePushData(responseChan chan *http.Response, req *http.Request, pushStreamID protocol.StreamID) {
	utils.Infof("Waiting for pushed data in stream %d", pushStreamID)
	var res *http.Response
	var receivedResponse bool

	for !receivedResponse {
		select {
		case res = <-responseChan:
			receivedResponse = true
			c.mutex.Lock()
			delete(c.responses, pushStreamID)
			c.mutex.Unlock()
			utils.Infof("Got header response for push stream %d", pushStreamID)
		case <-c.headerErrored:
			// an error occured on the header stream
			_ = c.CloseWithError(c.headerErr)
			return
		}
	}

	// TODO: correctly set this variable
	// var streamEnded bool
	// isHead := (req.Method == "HEAD")
	res = setLength(res, false, true)

	if session, ok := c.session.(streamCreator); ok {
		dataStream, err := session.GetOrOpenStream(pushStreamID)
		if err != nil {
			utils.Errorf("Could not open stream %d", pushStreamID)
			_ = c.CloseWithError(err)
			return
		}
		if dataStream == nil {
			utils.Errorf("Received nil stream for streamID %d", pushStreamID)
			return
		}
		// if streamEnded || isHead {
		// 	res.Body = noBody
		// } else {

		cachedBody := &bytes.Buffer{}
		if res.ContentLength > 0 {
			cachedBody.Grow(int(res.ContentLength))
		}
		res.Body = ioutil.NopCloser(cachedBody)
		// if res.Header.Get("Content-Encoding") == "gzip" {
		// 	res.Header.Del("Content-Encoding")
		// 	res.Header.Del("Content-Length")
		// 	res.ContentLength = -1
		// 	res.Body = &gzipReader{body: res.Body}
		// 	res.Uncompressed = true
		// }
		// }

		// Add to cache
		res.Request = req
		c.mutex.Lock()
		c.pushedResponses[req.URL.Path] = res
		c.mutex.Unlock()
		utils.Infof("Added response for request '%s' to cache", req.URL.Path)

		// Only read from stream after adding to cache as this is blocking IO!
		_, err = cachedBody.ReadFrom(dataStream) // if this returns the dataStream is closed
		if err != nil {
			utils.Errorf("Could not read from push data stream %d", dataStream.StreamID())
		}
	}
}

// Roundtrip executes a request and returns a response
func (c *client) RoundTrip(req *http.Request) (*http.Response, error) {
	// TODO: add port to address, if it doesn't have one
	if req.URL.Scheme != "https" {
		return nil, errors.New("quic http2: unsupported scheme")
	}
	if authorityAddr("https", hostnameFromRequest(req)) != c.hostname {
		return nil, fmt.Errorf("h2quic Client BUG: RoundTrip called for the wrong client (expected %s, got %s)", c.hostname, req.Host)
	}

	c.mutex.Lock()
	if response, ok := c.pushedResponses[req.URL.Path]; ok {
		delete(c.pushedResponses, req.URL.Path)
		c.mutex.Unlock()
		utils.Infof("######## Fetched response for request '%s' from cache", req.URL.Path)
		return response, nil
	}
	c.mutex.Unlock()
	utils.Infof("######## Requesting from upstream: %s", req.URL.Path)

	c.dialOnce.Do(func() {
		c.handshakeErr = c.dial()
	})

	if c.handshakeErr != nil {
		return nil, c.handshakeErr
	}

	hasBody := (req.Body != nil)

	responseChan := make(chan *http.Response)
	dataStream, err := c.session.OpenStreamSync()
	if err != nil {
		_ = c.CloseWithError(err)
		return nil, err
	}
	c.mutex.Lock()
	c.responses[dataStream.StreamID()] = responseChan
	c.mutex.Unlock()

	var requestedGzip bool
	if !c.opts.DisableCompression && req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" && req.Method != http.MethodHead {
		requestedGzip = true
	}
	// TODO: add support for trailers
	endStream := !hasBody
	err = c.requestWriter.WriteRequest(req, dataStream.StreamID(), endStream, requestedGzip)
	if err != nil {
		_ = c.CloseWithError(err)
		return nil, err
	}

	resc := make(chan error, 1)
	if hasBody {
		go func() {
			resc <- c.writeRequestBody(dataStream, req.Body)
		}()
	}

	var res *http.Response

	var receivedResponse bool
	var bodySent bool

	if !hasBody {
		bodySent = true
	}

	for !(bodySent && receivedResponse) {
		select {
		case res = <-responseChan:
			receivedResponse = true
			c.mutex.Lock()
			delete(c.responses, dataStream.StreamID())
			c.mutex.Unlock()
		case err := <-resc:
			bodySent = true
			if err != nil {
				return nil, err
			}
		case <-c.headerErrored:
			// an error occured on the header stream
			_ = c.CloseWithError(c.headerErr)
			return nil, c.headerErr
		}
	}

	// TODO: correctly set this variable
	var streamEnded bool
	isHead := (req.Method == http.MethodHead)

	res = setLength(res, isHead, streamEnded)

	if streamEnded || isHead {
		res.Body = noBody
	} else {
		res.Body = dataStream
		if requestedGzip && res.Header.Get("Content-Encoding") == "gzip" {
			res.Header.Del("Content-Encoding")
			res.Header.Del("Content-Length")
			res.ContentLength = -1
			res.Body = &gzipReader{body: res.Body}
			res.Uncompressed = true
		}
	}

	res.Request = req
	return res, nil
}

func (c *client) writeRequestBody(dataStream quic.Stream, body io.ReadCloser) (err error) {
	defer func() {
		cerr := body.Close()
		if err == nil {
			// TODO: what to do with dataStream here? Maybe reset it?
			err = cerr
		}
	}()

	_, err = io.Copy(dataStream, body)
	if err != nil {
		// TODO: what to do with dataStream here? Maybe reset it?
		return err
	}
	return dataStream.Close()
}

// Close closes the client
func (c *client) CloseWithError(e error) error {
	if c.session == nil {
		return nil
	}
	return c.session.Close(e)
}

func (c *client) Close() error {
	return c.CloseWithError(nil)
}

// copied from net/transport.go

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}
