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
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
)

const defaultUserAgent = "quic-go HTTP/3"

var defaultQuicConfig = &quic.Config{KeepAlive: true}

var dialAddr = quic.DialAddr

type roundTripperOpts struct {
	DisableCompression bool
}

// client is a HTTP3 client doing requests
type client struct {
	tlsConf *tls.Config
	config  *quic.Config
	opts    *roundTripperOpts

	dialOnce     sync.Once
	dialer       func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error)
	handshakeErr error

	requestWriter *requestWriter

	decoder *qpack.Decoder

	hostname string
	session  quic.Session

	logger utils.Logger
}

func newClient(
	hostname string,
	tlsConf *tls.Config,
	opts *roundTripperOpts,
	quicConfig *quic.Config,
	dialer func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error),
) *client {
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	}
	if !strSliceContains(tlsConf.NextProtos, nextProtoH3) {
		tlsConf.NextProtos = append(tlsConf.NextProtos, nextProtoH3)
	}
	if quicConfig == nil {
		quicConfig = defaultQuicConfig
	}
	quicConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	logger := utils.DefaultLogger.WithPrefix("h3 client")

	return &client{
		hostname:      authorityAddr("https", hostname),
		tlsConf:       tlsConf,
		requestWriter: newRequestWriter(logger),
		decoder:       qpack.NewDecoder(func(hf qpack.HeaderField) {}),
		config:        quicConfig,
		opts:          opts,
		dialer:        dialer,
		logger:        logger,
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

	go func() {
		if err := c.setupSession(); err != nil {
			c.logger.Debugf("Setting up session failed: %s", err)
			c.session.CloseWithError(quic.ErrorCode(errorInternalError), "")
		}
	}()

	// TODO: send a SETTINGS frame
	return nil
}

func (c *client) setupSession() error {
	// open the control stream
	str, err := c.session.OpenUniStream()
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	// write the type byte
	buf.Write([]byte{0x0})
	// send the SETTINGS frame
	(&settingsFrame{}).Write(buf)
	if _, err := str.Write(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func (c *client) Close() error {
	return c.session.Close()
}

// Roundtrip executes a request and returns a response
// TODO: handle request cancelations
func (c *client) RoundTrip(req *http.Request) (*http.Response, error) {
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

	str, err := c.session.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}

	var requestGzip bool
	if !c.opts.DisableCompression && req.Method != "HEAD" && req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		requestGzip = true
	}
	if err := c.requestWriter.WriteRequest(str, req, requestGzip); err != nil {
		return nil, err
	}

	frame, err := parseNextFrame(str)
	if err != nil {
		return nil, err
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		return nil, errors.New("not a HEADERS frame")
	}
	// TODO: check size
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		return nil, err
	}
	hfs, err := c.decoder.DecodeFull(headerBlock)
	if err != nil {
		return nil, err
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
				return nil, errors.New("malformed non-numeric status pseudo header")
			}
			res.StatusCode = status
			res.Status = hf.Value + " " + http.StatusText(status)
		default:
			res.Header.Add(hf.Name, hf.Value)
		}
	}
	respBody := newResponseBody(&responseBody{str})
	if requestGzip && res.Header.Get("Content-Encoding") == "gzip" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Body = newGzipReader(respBody)
		res.Uncompressed = true
	} else {
		res.Body = respBody
	}

	return res, nil
}
