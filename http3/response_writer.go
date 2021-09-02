package http3

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
)

type responseWriter struct {
	stream RequestStream

	header         http.Header
	trailers       []string
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

func newResponseWriter(stream RequestStream, logger utils.Logger) *responseWriter {
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
	fields = append(fields, qpack.HeaderField{Name: pseudoHeaderStatus, Value: strconv.Itoa(status)})
	for k, vv := range w.header {
		if strings.HasPrefix(k, http.TrailerPrefix) {
			continue
		}
		k = strings.ToLower(k)
		for _, v := range vv {
			if k == "trailer" {
				for _, t := range strings.Split(v, ",") {
					t = strings.TrimSpace(t)
					if t != "" {
						w.trailers = append(w.trailers, t)
					}
				}
			}
			fields = append(fields, qpack.HeaderField{Name: k, Value: v})
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
	return w.stream.DataWriter().Write(p)
}

func (w *responseWriter) Flush() {
	// TODO: buffer?
}

// See https://pkg.go.dev/net/http#example-ResponseWriter-Trailers.
func (w *responseWriter) writeTrailer() error {
	trailer := http.Header{}
	for _, k := range w.trailers {
		trailer[k] = append(trailer[k], w.header[k]...)
	}
	for k, vv := range w.header {
		if strings.HasPrefix(k, http.TrailerPrefix) {
			k = strings.TrimPrefix(k, http.TrailerPrefix)
			trailer[k] = append(trailer[k], vv...)
		}
	}
	fields := Trailers(trailer)
	if len(fields) == 0 {
		return nil
	}
	return w.stream.WriteHeaders(fields)
}

func (w *responseWriter) usedDataStream() bool {
	return w.dataStreamUsed
}

func (w *responseWriter) DataStream() quic.Stream {
	w.dataStreamUsed = true
	w.Flush()
	return w.stream
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
