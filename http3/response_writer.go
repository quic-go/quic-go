package http3

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
)

// DataStreamer lets the caller take over the stream. After a call to DataStream
// the HTTP server library will not do anything else with the connection.
//
// It becomes the caller's responsibility to manage and close the stream.
//
// After a call to DataStream, the original Request.Body must not be used.
type DataStreamer interface {
	DataStream() quic.Stream
}

type responseWriter struct {
	stream MessageStream

	header         http.Header
	status         int // status code passed to WriteHeader
	headerWritten  bool
	dataStreamUsed bool // set when DataSteam() is called

	logger utils.Logger
}

var (
	_ http.ResponseWriter = &responseWriter{}
	_ http.Flusher        = &responseWriter{}
	_ DataStreamer        = &responseWriter{}
)

func newResponseWriter(stream MessageStream, logger utils.Logger) *responseWriter {
	return &responseWriter{
		header: http.Header{},
		stream: stream,
		logger: logger,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}

	if status < 100 || status >= 200 {
		w.headerWritten = true
	}
	w.status = status

	fields := make([]qpack.HeaderField, 0, len(w.header)+1)
	fields = append(fields, qpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
	for k, v := range w.header {
		for i := range v {
			fields = append(fields, qpack.HeaderField{Name: strings.ToLower(k), Value: v[i]})
		}
	}

	w.logger.Infof("Responding with %d", status)

	err := w.stream.WriteHeaders(fields)
	if err != nil {
		w.logger.Errorf("could not write headers frame: %s", err.Error())
	}
	if !w.headerWritten {
		w.Flush()
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	if !bodyAllowedForStatus(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	return w.stream.Write(p)
}

func (w *responseWriter) Flush() {
	// TODO: buffer?
}

func (w *responseWriter) usedDataStream() bool {
	return w.dataStreamUsed
}

func (w *responseWriter) DataStream() quic.Stream {
	w.dataStreamUsed = true
	w.Flush()
	// TODO: remove type assertion
	return w.stream.(*messageStream).str
}

func (w *responseWriter) WebTransport() (WebTransport, error) {
	return w.stream.WebTransport()
}

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
