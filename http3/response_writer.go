package http3

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"

	"github.com/marten-seemann/qpack"
)

// The DatagramHandler interface is implemented by ResponseWriters that allow an
// HTTP handler to send QUIC datagrams on the underlying connection.
// Both endpoints need to negotiate datagram support in order for this to work.
type DatagramHandler interface {
	SendMessage([]byte) error
	ReceiveMessage() ([]byte, error)
}

type responseWriter struct {
	stream  *bufio.Writer
	session quic.Session // needed to allow access to datagram sending / receiving

	header        http.Header
	status        int // status code passed to WriteHeader
	headerWritten bool

	logger utils.Logger
}

var (
	_ http.ResponseWriter = &responseWriter{}
	_ http.Flusher        = &responseWriter{}
	_ DatagramHandler     = &responseWriter{}
)

func newResponseWriter(stream io.Writer, session quic.Session, logger utils.Logger) *responseWriter {
	return &responseWriter{
		header:  http.Header{},
		stream:  bufio.NewWriter(stream),
		session: session,
		logger:  logger,
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
	enc := qpack.NewEncoder(&headers)
	enc.WriteField(qpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})

	for k, v := range w.header {
		for index := range v {
			enc.WriteField(qpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	buf := &bytes.Buffer{}
	(&headersFrame{Length: uint64(headers.Len())}).Write(buf)
	w.logger.Infof("Responding with %d", status)
	if _, err := w.stream.Write(buf.Bytes()); err != nil {
		w.logger.Errorf("could not write headers frame: %s", err.Error())
	}
	if _, err := w.stream.Write(headers.Bytes()); err != nil {
		w.logger.Errorf("could not write header frame payload: %s", err.Error())
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	if !bodyAllowedForStatus(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	df := &dataFrame{Length: uint64(len(p))}
	buf := &bytes.Buffer{}
	df.Write(buf)
	if _, err := w.stream.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return w.stream.Write(p)
}

func (w *responseWriter) Flush() {
	if err := w.stream.Flush(); err != nil {
		w.logger.Errorf("could not flush to stream: %s", err.Error())
	}
}

func (w *responseWriter) SendMessage(b []byte) error {
	return w.session.SendMessage(b)
}

func (w *responseWriter) ReceiveMessage() ([]byte, error) {
	return w.session.ReceiveMessage()
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
