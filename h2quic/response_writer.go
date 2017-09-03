package h2quic

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type responseWriter struct {
	dataStreamID protocol.StreamID
	dataStream   quic.Stream

	headerStream      quic.Stream
	headerStreamMutex *sync.Mutex

	// Server Push
	session     streamCreator
	handler     http.Handler
	requestHost string

	header        http.Header
	status        int // status code passed to WriteHeader
	headerWritten bool

	settings *sessionSettings
}

func newResponseWriter(headerStream quic.Stream, headerStreamMutex *sync.Mutex, dataStream quic.Stream, dataStreamID protocol.StreamID, session streamCreator, handler http.Handler, requestHost string, settings *sessionSettings) *responseWriter {
	return &responseWriter{
		header:            http.Header{},
		headerStream:      headerStream,
		headerStreamMutex: headerStreamMutex,
		dataStream:        dataStream,
		dataStreamID:      dataStreamID,
		settings:          settings,
		session:           session,
		handler:           handler,
		requestHost:       requestHost,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}
	w.headerWritten = true
	w.status = status

	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})

	for k, v := range w.header {
		for index := range v {
			enc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	utils.Infof("Responding with %d", status)
	w.headerStreamMutex.Lock()
	defer w.headerStreamMutex.Unlock()
	h2framer := http2.NewFramer(w.headerStream, nil)
	err := h2framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      uint32(w.dataStreamID),
		EndHeaders:    true,
		BlockFragment: headers.Bytes(),
	})
	if err != nil {
		utils.Errorf("could not write h2 header: %s", err.Error())
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	if !bodyAllowedForStatus(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	return w.dataStream.Write(p)
}

func (w *responseWriter) Flush() {}

// This is a NOP. Use http.Request.Context
func (w *responseWriter) CloseNotify() <-chan bool { return make(<-chan bool) }

// Push should do:
// - construct a valid HTTP2 header for a request for the file to push.
// - open a new stream (server side)
// - send a PUSH_PROMISE containing the streamID of the new stream and the HTTP2 header
// - use the header to create a http request and use it in ServeHTTP(w ResponseWriter, r *Request) to serve the file to push.
// - TODO: check for recursive pushes.
func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	if !w.settings.pushEnabled {
		return http2.ErrPushLimitReached
	}
	if w.headerStream.StreamID()%2 == 0 { // Copied from net/http2/server.go
		return http2.ErrRecursivePush
	}
	opts, err := ValidateOptions(opts)
	if err != nil {
		return err
	}
	u, err := w.validateTarget(target, opts)
	if err != nil {
		return err
	}
	authority := u.Host
	path := u.RequestURI()
	contentLengthStr := "0" // a request does not have content

	// Construct HTTP headers for request in push promise
	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: opts.Method})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: u.Scheme})
	for k, v := range opts.Header {
		for index := range v {
			enc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	// Get new data stream
	newDataStream, err := w.session.OpenStream()
	if err != nil {
		if err == qerr.TooManyOpenStreams {
			return http2.ErrPushLimitReached
		}
		return err
	}
	newDataStreamID := newDataStream.StreamID()

	// Write push promise header
	utils.Debugf("Sending PUSH_PROMISE for target '%s', promised on stream %d", target, newDataStreamID)
	headerFramer := http2.NewFramer(w.headerStream, nil)
	w.headerStreamMutex.Lock()
	err = headerFramer.WritePushPromise(http2.PushPromiseParam{
		StreamID:      uint32(w.dataStreamID),
		PromiseID:     uint32(newDataStreamID),
		BlockFragment: headers.Bytes(),
		EndHeaders:    true,
	})
	w.headerStreamMutex.Unlock() // Do not defer as we will first call ServeHTTP(), which will need the mutex
	if err != nil {
		return err
	}

	// golang net/http2 constructs a 'fake' http2 request and feeds it to the serve() loop to let it be processed as a normal request.
	// But we will, for now, just serveHTTP() it here:
	pushRequest, err := requestFromHTTPHeader(opts.Header, path, authority, opts.Method, contentLengthStr)
	if err != nil {
		return err
	}
	pushRequest.RemoteAddr = w.session.RemoteAddr().String()
	pushRequestResponseWriter := newResponseWriter(w.headerStream, w.headerStreamMutex, newDataStream, newDataStreamID, w.session, w.handler, w.requestHost, w.settings)

	// Serve the fake request
	go serveHTTP(w.handler, pushRequestResponseWriter, pushRequest, true, nil)
	return nil
}

// test that we implement http.Flusher
var _ http.Flusher = &responseWriter{}

// test that we implement http.CloseNotifier
var _ http.CloseNotifier = &responseWriter{}

// test that we implement http.Pusher
var _ http.Pusher = &responseWriter{}

// copied from http2/http2.go
// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}

// Copied from net/http2/server.go
func checkValidHTTP2RequestHeaders(h http.Header) error {
	var connHeaders = []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Connection",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, k := range connHeaders {
		if _, ok := h[k]; ok {
			return fmt.Errorf("request header %q is not valid in HTTP/2", k)
		}
	}
	te := h["Te"]
	if len(te) > 0 && (len(te) > 1 || (te[0] != "trailers" && te[0] != "")) {
		return errors.New(`request header "TE" may only be "trailers" in HTTP/2`)
	}
	return nil
}

func ValidateOptions(opts *http.PushOptions) (*http.PushOptions, error) {
	if opts == nil {
		opts = &http.PushOptions{}
	}
	// Default options. Copied from net/http2/server.go
	if opts.Method == "" {
		opts.Method = http.MethodGet
	}
	if opts.Header == nil {
		opts.Header = http.Header{}
	}
	if opts.Method != http.MethodGet && opts.Method != http.MethodHead {
		return nil, fmt.Errorf("method %q must be GET or HEAD", opts.Method)
	}
	return opts, nil
}

func (w *responseWriter) validateTarget(target string, opts *http.PushOptions) (*url.URL, error) {
	// Validate the target. Copied from net/http2/server.go
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	wantScheme := "https"
	if u.Scheme == "" {
		if !strings.HasPrefix(target, "/") {
			return nil, fmt.Errorf("target must be an absolute URL or an absolute path: %q", target)
		}
		u.Scheme = wantScheme
		u.Host = w.requestHost
	} else {
		if u.Scheme != wantScheme {
			return nil, fmt.Errorf("cannot push URL with scheme %q from request with scheme %q", u.Scheme, wantScheme)
		}
		if u.Host == "" {
			return nil, errors.New("URL must have a host")
		}
	}
	for k := range opts.Header {
		if strings.HasPrefix(k, ":") {
			return nil, fmt.Errorf("promised request headers cannot include pseudo header %q", k)
		}
		switch strings.ToLower(k) {
		case "content-length", "content-encoding", "trailer", "te", "expect", "host":
			return nil, fmt.Errorf("promised request headers cannot include %q", k)
		}
	}
	if err = checkValidHTTP2RequestHeaders(opts.Header); err != nil {
		return nil, err
	}
	return u, nil
}
