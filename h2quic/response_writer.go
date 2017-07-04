package h2quic

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type responseWriter struct {
	dataStreamID protocol.StreamID
	dataStream   quic.Stream

	headerStream      quic.Stream
	headerStreamMutex *sync.Mutex

	session     streamCreator
	handlerFunc http.HandlerFunc

	header        http.Header
	status        int // status code passed to WriteHeader
	headerWritten bool
}

func newResponseWriter(headerStream quic.Stream, headerStreamMutex *sync.Mutex, dataStream quic.Stream, dataStreamID protocol.StreamID, session streamCreator, handlerFunc http.HandlerFunc) *responseWriter {
	return &responseWriter{
		header:            http.Header{},
		headerStream:      headerStream,
		headerStreamMutex: headerStreamMutex,
		dataStream:        dataStream,
		dataStreamID:      dataStreamID,
		session:           session,
		handlerFunc:       handlerFunc,
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

// TODO: Implement a functional CloseNotify method.
func (w *responseWriter) CloseNotify() <-chan bool { return make(<-chan bool) }

// Should do:
// - construct a valid HTTP2 header for a request for the file to push.
// - open a new stream (maybe this should be done after sending the promise, but then how do we know the new streamID?)
// - send a PUSH_PROMISE containing the streamID of the new stream and the HTTP2 header
// - use the header to create a http request and use it in ServeHTTP(w ResponseWriter, r *Request) to serve the file to push.
func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	// Default options.
	if opts.Method == "" {
		opts.Method = "GET"
	}
	if opts.Header == nil {
		opts.Header = http.Header{}
	}
	if opts.Method != "GET" && opts.Method != methodHEAD {
		return fmt.Errorf("method %q must be GET or HEAD", opts.Method)
	}
	// Validate the target.
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	wantScheme := "https"
	if u.Scheme == "" {
		if !strings.HasPrefix(target, "/") {
			return fmt.Errorf("target must be an absolute URL or an absolute path: %q", target)
		}
		u.Scheme = wantScheme
		u.Host = "www.example.com" // TODO: get from server?
	} else {
		if u.Scheme != wantScheme {
			return fmt.Errorf("cannot push URL with scheme %q from request with scheme %q", u.Scheme, wantScheme)
		}
		if u.Host == "" {
			return errors.New("URL must have a host")
		}
	}
	authority := u.Host
	path := u.RequestURI()
	contentLengthStr := "" // TODO

	// Get new data stream
	newDataStream, err := w.session.OpenStreamSync()
	if err != nil {
		return err
	}
	newDataStreamID := newDataStream.StreamID()

	// Construct HTTP headers for request in push promise
	var headers bytes.Buffer
	enc := hpack.NewEncoder(&headers)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: opts.Method})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	for k, v := range opts.Header {
		for index := range v {
			enc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}
	// Write push promise header
	pushPromiseFrame, err := PushPromiseFrame(newDataStreamID, headers.Bytes())
	if err != nil {
		return err
	}
	w.headerStreamMutex.Lock()
	n, err := w.headerStream.Write(pushPromiseFrame)
	w.headerStreamMutex.Unlock() // Do not defer as we will first call ServeHTTP(), which will need the mutex
	if err != nil {
		return err
	}
	if n != len(pushPromiseFrame) {
		return io.ErrShortWrite
	}
	// golang net/http2 constructs a 'fake' http2 request and feeds it to the serve() loop to let it be processed as a normal request.
	// But we will, for now, just ServeHTTP() it here:
	pushRequest, err := requestFromHTTPHeader(opts.Header, path, authority, opts.Method, contentLengthStr)
	if err != nil {
		return err
	}
	pushRequestResponseWriter := newResponseWriter(w.headerStream, w.headerStreamMutex, newDataStream, newDataStreamID, w.session, w.handlerFunc)
	w.handlerFunc.ServeHTTP(pushRequestResponseWriter, pushRequest)
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
