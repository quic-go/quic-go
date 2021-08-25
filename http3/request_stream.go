package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"
)

// A RequestStream is a QUIC stream for processing HTTP/3 requests.
type RequestStream interface {
	// TODO: integrate QPACK encoding and decoding with dynamic tables.

	// ReadFields reads a single HEADERS frame, used for HTTP headers or trailers.
	ReadFields() ([]qpack.HeaderField, error)

	// WriteFields writes a single HEADERS frame, used for HTTP headers or trailers.
	WriteFields([]qpack.HeaderField) error

	// DataReader returns an io.ReadCloser that reads from DATA frames.
	DataReader() io.ReadCloser

	// DataWriter returns an io.WriteCloser that writes to DATA frames.
	DataWriter() io.WriteCloser

	// WebTransport returns a WebTransport interface, if supported.
	// TODO: should this method live here?
	WebTransport() (WebTransport, error)
}

type requestStream struct {
	conn   *connection
	Stream quic.Stream

	Reader quicvarint.Reader

	writeMutex sync.Mutex // Protects writes
	Writer     quicvarint.Writer

	Fields chan []qpack.HeaderField
	Err    error

	bytesToRead    chan uint64
	bytesToSkip    chan uint64
	bytesRemaining uint64

	bodyReaderClosed chan struct{}
}

type frameReader struct {
	l    uint64
	r    io.Reader
	done chan struct{}
}

var _ RequestStream = &requestStream{}

func newRequestStream(conn *connection, str quic.Stream, first *FrameType) *requestStream {
	s := &requestStream{
		conn:             conn,
		Stream:           str,
		Reader:           quicvarint.NewReader(str),
		Writer:           quicvarint.NewWriter(str),
		Fields:           make(chan []qpack.HeaderField),
		bytesToRead:      make(chan uint64),
		bytesToSkip:      make(chan uint64),
		bodyReaderClosed: make(chan struct{}),
	}
	go s.handleIncomingFrames(first)
	return s
}

func (s *requestStream) handleIncomingFrames(first *FrameType) {
	defer s.conn.cleanup(s.Stream.StreamID())
	rerr := s.parseIncomingFrames(first)
	if rerr.err != nil {
		// TODO: log rerr.err
		if rerr.streamErr != 0 {
			s.Stream.CancelWrite(quic.StreamErrorCode(rerr.streamErr))
		}
		if rerr.connErr != 0 {
			var reason string
			if rerr.err != nil {
				reason = rerr.err.Error()
			}
			s.conn.session.CloseWithError(quic.ApplicationErrorCode(rerr.connErr), reason)
		}
		return
	}
	s.Close()
}

func (s *requestStream) parseIncomingFrames(first *FrameType) requestError {
	var t FrameType
	if first != nil {
		t = *first
	} else {
		i, err := quicvarint.Read(s.Reader)
		if err != nil {
			return newStreamError(errorRequestIncomplete, err)
		}
		t = FrameType(i)
	}

	// HTTP messages must begin with a HEADERS frame.
	if t != FrameTypeHeaders {
		return newConnError(errorFrameUnexpected, errors.New("expected first frame to be a HEADERS frame"))
	}

	for {
		// Read frame n
		n, err := quicvarint.Read(s.Reader)
		if err != nil {
			return newStreamError(errorRequestIncomplete, err)
		}

		switch t {
		case FrameTypeHeaders:
			max := s.conn.maxHeaderBytes()
			if n > max {
				return newStreamError(errorFrameError, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", n, max))
			}
			p := make([]byte, n)
			_, err := io.ReadFull(s.Stream, p)
			if err != nil {
				return newStreamError(errorRequestIncomplete, err)
			}
			go s.decodeFields(p)
			n = 0

		case FrameTypeData:
			select {
			case s.bytesToRead <- n:
				// Wait for the frame to be consumed
				n = <-s.bytesToSkip
			case <-s.bodyReaderClosed:
			}
		}

		// Skip unread payload bytes
		if n != 0 {
			_, err := io.CopyN(ioutil.Discard, s.Stream, int64(n))
			if err != nil {
				return newStreamError(errorRequestIncomplete, err)
			}
		}

		// Read frame type
		i, err := quicvarint.Read(s.Reader)
		if err != nil {
			return newStreamError(errorRequestIncomplete, err)
		}
		t = FrameType(i)
	}
}

func (s *requestStream) decodeFields(p []byte) {
	dec := qpack.NewDecoder(nil)
	fields, err := dec.DecodeFull(p)
	if err != nil {
		s.conn.session.CloseWithError(quic.ApplicationErrorCode(errorGeneralProtocolError), "QPACK decoding error")
	}
	s.Fields <- fields
}

func (s *requestStream) ReadFields() ([]qpack.HeaderField, error) {
	select {
	case fields := <-s.Fields:
		return fields, s.Err
	case <-s.Stream.Context().Done():
		return nil, s.Stream.Context().Err()
	}
}

// WriteFields writes a single QPACK-encoded HEADERS frame to s.
// It returns an error if the estimated size of the frame exceeds the peer’s
// MAX_FIELD_SECTION_SIZE. Headers are not modified or validated.
// It is the responsibility of the caller to ensure the fields are valid.
func (s *requestStream) WriteFields(fields []qpack.HeaderField) error {
	var l uint64
	for i := range fields {
		// https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html#name-dynamic-table-size
		l += uint64(len(fields[i].Name) + len(fields[i].Value) + 32)
	}
	max := s.conn.peerMaxHeaderBytes()
	if l > max {
		return fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", l, max)
	}

	buf := &bytes.Buffer{}
	encoder := qpack.NewEncoder(buf)
	for i := range fields {
		encoder.WriteField(fields[i])
	}

	// TODO: should we just instruct callers to not call WriteFields and use BodyWriter at the same time?
	s.writeMutex.Lock()
	defer s.writeMutex.Unlock()

	w := quicvarint.NewWriter(s.Stream)
	quicvarint.Write(w, uint64(FrameTypeHeaders))
	quicvarint.Write(w, uint64(buf.Len()))
	_, err := s.Stream.Write(buf.Bytes())
	return err
}

func (s *requestStream) Close() error {
	s.conn.cleanup(s.Stream.StreamID())
	return s.Stream.Close()
}

func (s *requestStream) CancelRead(code quic.StreamErrorCode) {
	s.conn.cleanup(s.Stream.StreamID())
	s.Stream.CancelRead(code)
}

func (s *requestStream) CancelWrite(code quic.StreamErrorCode) {
	s.conn.cleanup(s.Stream.StreamID())
	s.Stream.CancelWrite(code)
}

func (s *requestStream) AcceptDatagramContext(ctx context.Context) (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *requestStream) RegisterDatagramContext() (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *requestStream) DatagramNoContext() (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *requestStream) WebTransport() (WebTransport, error) {
	return newWebTransportSession(s.conn, s.Stream), nil
}

func (s *requestStream) DataReader() io.ReadCloser {
	return (*dataReader)(s)
}

func (s *requestStream) DataWriter() io.WriteCloser {
	return (*dataWriter)(s)
}

// dataReader aliases requestStream so (*requestStream).DataReader() can return itself.
type dataReader requestStream

var _ io.ReadCloser = &dataReader{}

func (r *dataReader) Read(p []byte) (n int, err error) {
	if r.bytesRemaining == 0 {
		select {
		case r.bytesRemaining = <-r.bytesToRead:
		case <-r.bodyReaderClosed:
			return 0, io.EOF
		}
	}
	if r.bytesRemaining < uint64(len(p)) {
		n, err = r.Stream.Read(p[:r.bytesRemaining])
	} else {
		n, err = r.Stream.Read(p)
	}
	r.bytesRemaining -= uint64(n)
	if r.bytesRemaining == 0 {
		r.bytesToSkip <- 0
	}
	return n, err
}

func (r *dataReader) Close() error {
	if r.bytesRemaining != 0 {
		r.bytesToSkip <- r.bytesRemaining
		r.bytesRemaining = 0
	}
	close(r.bodyReaderClosed)
	return nil
}

// dataWriter aliases requestStream so (*requestStream).DataWriter() can return itself.
type dataWriter requestStream

var _ io.WriteCloser = &dataWriter{}

func (w *dataWriter) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		s := p
		if len(p) > bodyCopyBufferSize {
			s = p[:bodyCopyBufferSize]
		}
		x, err := w.writeDataFrame(s)
		n += x
		p = p[x:]
		if err != nil {
			return n, err
		}
	}
	return n, err
}

func (w *dataWriter) writeDataFrame(p []byte) (n int, err error) {
	w.writeMutex.Lock()
	defer w.writeMutex.Unlock()
	quicvarint.Write(w.Writer, uint64(FrameTypeData))
	quicvarint.Write(w.Writer, uint64(len(p)))
	return w.Stream.Write(p)
}

func (w *dataWriter) Close() error {
	// TODO: CancelWrite on stream?
	// What should closing the body do?
	return nil
}
