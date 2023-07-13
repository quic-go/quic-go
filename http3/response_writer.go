package http3

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/quic-go/qpack"
)

type responseWriter struct {
	conn        quic.Connection
	str         quic.Stream
	bufferedStr *bufio.Writer
	buf         []byte

	header        http.Header
	status        int // status code passed to WriteHeader
	headerWritten bool
	headerSent    bool
	contentLen    int64 // if handler set valid Content-Length header
	numWritten    int64 // bytes written

	logger utils.Logger
}

var (
	_ http.ResponseWriter = &responseWriter{}
	_ http.Flusher        = &responseWriter{}
	_ Hijacker            = &responseWriter{}
)

func newResponseWriter(str quic.Stream, conn quic.Connection, logger utils.Logger) *responseWriter {
	return &responseWriter{
		header:      http.Header{},
		buf:         make([]byte, 16),
		conn:        conn,
		str:         str,
		bufferedStr: bufio.NewWriter(str),
		logger:      logger,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

// flushHeader send header frame in wire format when:
// 1. 1XX status is written
// 1. Flush is called
// 2. Write can not longer buffer anymore data
func (w *responseWriter) flushHeader() error {
	var headers bytes.Buffer
	// leave some room to encode frame header
	headers.Write(w.buf[:cap(w.buf)])
	enc := qpack.NewEncoder(&headers)
	enc.WriteField(qpack.HeaderField{Name: ":status", Value: strconv.Itoa(w.status)})

	for k, v := range w.header {
		for index := range v {
			enc.WriteField(qpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	buf := headers.Bytes()[:0]
	// not counting preallocated room as length
	buf = (&headersFrame{Length: uint64(headers.Len() - cap(w.buf))}).Append(buf)
	w.logger.Infof("Responding with %d", w.status)

	// encodes frame header to the start of the buffer
	// abuses bytes.Buffer
	headers.Next(cap(w.buf) - len(buf))
	copy(headers.Bytes(), buf)

	// write to quic stream directly because data may be buffered
	_, err := headers.WriteTo(w.str)
	if err != nil {
		w.logger.Errorf("could not write header frame: %s", err.Error())
	}
	return err
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}

	if status < 100 || status >= 200 {
		w.headerWritten = true
		// Add Date header.
		// This is what the standard library does.
		// Can be disabled by setting the Date header to nil.
		if _, ok := w.header["Date"]; !ok {
			w.header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		}
		// Content-Length checking
		if clen := w.header.Get("Content-Length"); clen != "" {
			if cl, err := strconv.ParseInt(clen, 10, 64); err == nil {
				w.contentLen = cl
			} else {
				// emit a warning for malformed Content-Length and remove it
				w.logger.Errorf("Malformed Content-Length %s", clen)
				w.header.Del("Content-Length")
			}
		}
	}
	w.status = status

	if !w.headerWritten {
		w.flushHeader()
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	bodyAllowed := bodyAllowedForStatus(w.status)
	if !w.headerWritten {
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

	df := &dataFrame{Length: uint64(len(p))}
	w.buf = w.buf[:0]
	w.buf = df.Append(w.buf)

	// flush header if unable to buffer anymore
	if !w.headerSent && len(p)+len(w.buf) > w.bufferedStr.Available() {
		w.headerSent = true
		err := w.flushHeader()
		if err != nil {
			return 0, err
		}
	}

	if _, err := w.bufferedStr.Write(w.buf); err != nil {
		return 0, err
	}
	return w.bufferedStr.Write(p)
}

func (w *responseWriter) FlushError() error {
	// write status and flush header if necessary
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	if !w.headerSent {
		w.headerSent = true
		err := w.flushHeader()
		if err != nil {
			return err
		}
	}
	return w.bufferedStr.Flush()
}

func (w *responseWriter) Flush() {
	if err := w.FlushError(); err != nil {
		w.logger.Errorf("could not flush to stream: %s", err.Error())
	}
}

func (w *responseWriter) StreamCreator() StreamCreator {
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
