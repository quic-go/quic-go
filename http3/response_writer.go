package http3

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/quic-go/qpack"
)

// The maximum length of an encoded HTTP/3 frame header is 16:
// The frame has a type and length field, both QUIC varints (maximum 8 bytes in length)
const frameHeaderLen = 16

// headerWriter wraps the stream, so that the first Write call flushes the header to the stream
type headerWriter struct {
	str    quic.Stream
	header http.Header
	status int // status code passed to WriteHeader

	logger utils.Logger
}

// writeHeader encodes and flush header to the stream
func (hw *headerWriter) writeHeader() error {
	var headers bytes.Buffer
	enc := qpack.NewEncoder(&headers)
	if err := enc.WriteField(qpack.HeaderField{Name: ":status", Value: strconv.Itoa(hw.status)}); err != nil {
		return err
	}

	for k, v := range hw.header {
		for index := range v {
			if err := enc.WriteField(qpack.HeaderField{Name: strings.ToLower(k), Value: v[index]}); err != nil {
				return err
			}
		}
	}

	buf := make([]byte, 0, frameHeaderLen+headers.Len())
	buf = (&headersFrame{Length: uint64(headers.Len())}).Append(buf)
	hw.logger.Infof("Responding with %d", hw.status)
	buf = append(buf, headers.Bytes()...)

	_, err := hw.str.Write(buf)
	return err
}

const maxSmallResponseSize = 4096

type responseWriter struct {
	*headerWriter
	conn Connection
	buf  []byte

	// for responses smaller than maxSmallResponseSize, we buffer calls to Write,
	// and automatically add the Content-Length header
	smallResponseBuf []byte

	contentLen     int64 // if handler set valid Content-Length header
	numWritten     int64 // bytes written
	headerComplete bool  // set once WriteHeader is called with a status code >= 200
	headerWritten  bool  // set once the response header has been serialized to the stream
	isHead         bool
}

var (
	_ http.ResponseWriter = &responseWriter{}
	_ http.Flusher        = &responseWriter{}
	_ Hijacker            = &responseWriter{}
)

func newResponseWriter(str quic.Stream, conn Connection, isHead bool, logger utils.Logger) *responseWriter {
	hw := &headerWriter{
		str:    str,
		header: http.Header{},
		logger: logger,
	}
	return &responseWriter{
		headerWriter: hw,
		buf:          make([]byte, frameHeaderLen),
		conn:         conn,
		isHead:       isHead,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerComplete {
		return
	}

	// http status must be 3 digits
	if status < 100 || status > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", status))
	}
	w.status = status

	// immediately write 1xx headers
	if status < 200 {
		w.writeHeader()
		return
	}

	// We're done with headers once we write a status >= 200.
	w.headerComplete = true
	// Add Date header.
	// This is what the standard library does.
	// Can be disabled by setting the Date header to nil.
	if _, ok := w.header["Date"]; !ok {
		w.header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}
	// Content-Length checking
	// use ParseUint instead of ParseInt, as negative values are invalid
	if clen := w.header.Get("Content-Length"); clen != "" {
		if cl, err := strconv.ParseUint(clen, 10, 63); err == nil {
			w.contentLen = int64(cl)
		} else {
			// emit a warning for malformed Content-Length and remove it
			w.logger.Errorf("Malformed Content-Length %s", clen)
			w.header.Del("Content-Length")
		}
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	bodyAllowed := bodyAllowedForStatus(w.status)
	if !w.headerComplete {
		// If body is not allowed, we don't need to (and we can't) sniff the content type.
		if bodyAllowed {
			// If no content type, apply sniffing algorithm to body.
			// We can't use `w.header.Get` here since if the Content-Type was set to nil, we shoundn't do sniffing.
			_, haveType := w.header["Content-Type"]

			// If the Transfer-Encoding or Content-Encoding was set and is non-blank,
			// we shouldn't sniff the body.
			hasTE := w.header.Get("Transfer-Encoding") != ""
			hasCE := w.header.Get("Content-Encoding") != ""
			if !hasCE && !haveType && !hasTE && len(p) > 0 {
				w.header.Set("Content-Type", http.DetectContentType(p))
			}
		}
		w.WriteHeader(http.StatusOK)
		bodyAllowed = true
	}
	if !bodyAllowed {
		return 0, http.ErrBodyNotAllowed
	}

	w.numWritten += int64(len(p))
	if w.contentLen != 0 && w.numWritten > w.contentLen {
		return 0, http.ErrContentLength
	}

	if w.isHead {
		return len(p), nil
	}

	if !w.headerWritten {
		// Buffer small responses.
		// This allows us to automatically set the Content-Length field.
		if len(w.smallResponseBuf)+len(p) < maxSmallResponseSize {
			w.smallResponseBuf = append(w.smallResponseBuf, p...)
			return len(p), nil
		}
	}
	return w.doWrite(p)
}

func (w *responseWriter) doWrite(p []byte) (int, error) {
	if !w.headerWritten {
		if err := w.writeHeader(); err != nil {
			return 0, maybeReplaceError(err)
		}
		w.headerWritten = true
	}

	l := uint64(len(w.smallResponseBuf) + len(p))
	if l == 0 {
		return 0, nil
	}
	df := &dataFrame{Length: l}
	w.buf = w.buf[:0]
	w.buf = df.Append(w.buf)
	if _, err := w.str.Write(w.buf); err != nil {
		return 0, maybeReplaceError(err)
	}
	if len(w.smallResponseBuf) > 0 {
		if _, err := w.str.Write(w.smallResponseBuf); err != nil {
			return 0, maybeReplaceError(err)
		}
		w.smallResponseBuf = nil
	}
	var n int
	if len(p) > 0 {
		var err error
		n, err = w.str.Write(p)
		if err != nil {
			return n, maybeReplaceError(err)
		}
	}
	return n, nil
}

func (w *responseWriter) FlushError() error {
	if !w.headerComplete {
		w.WriteHeader(http.StatusOK)
	}
	_, err := w.doWrite(nil)
	return err
}

func (w *responseWriter) Flush() {
	if err := w.FlushError(); err != nil {
		w.logger.Errorf("could not flush to stream: %s", err.Error())
	}
}

func (w *responseWriter) Connection() Connection {
	return w.conn
}

func (w *responseWriter) SetReadDeadline(deadline time.Time) error {
	return w.str.SetReadDeadline(deadline)
}

func (w *responseWriter) SetWriteDeadline(deadline time.Time) error {
	return w.str.SetWriteDeadline(deadline)
}

// copied from http2/http2.go
// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent:
		return false
	case status == http.StatusNotModified:
		return false
	}
	return true
}
