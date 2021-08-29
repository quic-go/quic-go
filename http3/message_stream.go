package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"
)

// A MessageStream is a QUIC stream for processing HTTP/3 request and response messages.
type MessageStream interface {
	Stream() quic.Stream

	// Reads a single HTTP message.
	// For servers, ReadMessage reads an HTTP request.
	// For clients, ReadMessage reads an HTTP response.
	// An interim response (status codes 100-199) will have nil Trailers and Body.
	// Interim responses must be followed by additional response messages.
	ReadMessage() (Message, error)

	// WriteFields a single HEADERS frame.
	// Used for writing HTTP headers or trailers.
	// Should not be called concurrently with Write or ReadFrom.
	WriteFields([]qpack.HeaderField) error

	// Write writes 0 or more DATA frames.
	// Used for writing an HTTP request or response body.
	// Should not be called concurrently with WriteFields or ReadFrom.
	Write([]byte) (int, error)

	// ReadFrom implements io.ReaderFrom. It reads data from an io.Reader
	// and writes DATA frames to the underlying quic.Stream.
	ReadFrom(io.Reader) (int64, error)

	// TODO: integrate QPACK encoding and decoding with dynamic tables.

	Close() error

	// WebTransport returns a WebTransport interface, if supported.
	// TODO: should this method live here?
	WebTransport() (WebTransport, error)
}

type messageStream struct {
	conn   *connection
	stream quic.Stream

	r quicvarint.Reader
	w quicvarint.Writer

	once  sync.Once
	first *FrameType

	messages chan *incomingMessage
	readErr  error

	// Used to synchronize reading DATA frames, used for HTTP message bodies
	bytesToRead chan uint64
	bytesUnread chan uint64

	bodyReaderClosed chan struct{}
	readDone         chan struct{}
}

var (
	_ MessageStream = &messageStream{}
	_ io.Writer     = &messageStream{}
	_ io.ReaderFrom = &messageStream{}
	_ io.Closer     = &messageStream{}
)

// newMessageStream creates a new MessageStream. If first is non-nil, the
// parser will assume the first varint has already been read from the stream.
func newMessageStream(conn *connection, stream quic.Stream, first *FrameType) MessageStream {
	s := &messageStream{
		conn:             conn,
		stream:           stream,
		r:                quicvarint.NewReader(stream),
		w:                quicvarint.NewWriter(stream),
		first:            first,
		messages:         make(chan *incomingMessage),
		bytesToRead:      make(chan uint64),
		bytesUnread:      make(chan uint64),
		bodyReaderClosed: make(chan struct{}),
		readDone:         make(chan struct{}),
	}
	return s
}

func (s *messageStream) Stream() quic.Stream {
	return s.stream
}

// ReadMessage reads a single HTTP message from s or a read error, if any.
func (s *messageStream) ReadMessage() (Message, error) {
	s.once.Do(func() {
		go s.handleIncomingFrames()
	})
	select {
	case msg := <-s.messages:
		return msg, nil
	case <-s.readDone:
		return nil, s.readErr
	case <-s.stream.Context().Done():
		return nil, s.stream.Context().Err()
	}
}

// WriteFields writes a single QPACK-encoded HEADERS frame to s.
// It returns an error if the estimated size of the frame exceeds the peer’s
// MAX_FIELD_SECTION_SIZE. Headers are not modified or validated.
// It is the responsibility of the caller to ensure the fields are valid.
// It should not be called concurrently with Write or ReadFrom.
func (s *messageStream) WriteFields(fields []qpack.HeaderField) error {
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

	quicvarint.Write(s.w, uint64(FrameTypeHeaders))
	quicvarint.Write(s.w, uint64(buf.Len()))
	_, err := s.w.Write(buf.Bytes())
	return err
}

const bodyCopyBufferSize = 8 * 1024

// Write writes bytes to DATA frames to the underlying quic.Stream.
func (s *messageStream) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		pp := p
		if len(p) > bodyCopyBufferSize {
			pp = p[:bodyCopyBufferSize]
		}
		x, err := s.writeDataFrame(pp)
		p = p[x:]
		n += x
		if err != nil {
			return n, err
		}
	}
	return n, err
}

// ReadFrom implements io.ReaderFrom. It reads from r until an error
// or io.EOF and writes DATA frames to the underlying quic.Stream.
func (s *messageStream) ReadFrom(r io.Reader) (n int64, err error) {
	buf := make([]byte, bodyCopyBufferSize)
	for {
		l, rerr := r.Read(buf)
		if l == 0 {
			if rerr == nil {
				continue
			} else if rerr == io.EOF {
				return n, nil
			}
			return n, rerr
		}
		x, err := s.writeDataFrame(buf[:l])
		n += int64(x)
		if err != nil {
			return n, err
		}
		if rerr == io.EOF {
			return n, nil
		}
	}
}

func (s *messageStream) AcceptDatagramContext(ctx context.Context) (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *messageStream) RegisterDatagramContext() (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *messageStream) DatagramNoContext() (DatagramContext, error) {
	return nil, errors.New("TODO: not supported yet")
}

func (s *messageStream) WebTransport() (WebTransport, error) {
	return newWebTransportSession(s.conn, s.stream), nil
}

func (s *messageStream) Close() error {
	s.conn.cleanup(s.stream.StreamID())
	// s.stream.CancelRead(quic.StreamErrorCode(errorNoError))
	return s.stream.Close()
}

func (s *messageStream) handleIncomingFrames() {
	err := s.parseIncomingFrames()
	// code := errorNoError
	// if serr, ok := err.(*streamError); ok {
	// 	code = serr.Code
	// }
	// s.CancelRead(quic.StreamErrorCode(code))
	s.readErr = err
	close(s.readDone)
}

func (s *messageStream) parseIncomingFrames() error {
	var t FrameType
	if s.first != nil {
		t = *s.first
	} else {
		i, err := quicvarint.Read(s.r)
		if err != nil {
			return &streamError{Code: errorRequestIncomplete, Err: err}
		}
		t = FrameType(i)
	}

	// HTTP messages must begin with a HEADERS frame.
	if t != FrameTypeHeaders {
		return &connError{Code: errorFrameUnexpected, Err: &frameTypeError{Want: FrameTypeHeaders, Type: t}}
	}

	var msg *incomingMessage

	for {
		// Read frame length
		l, err := quicvarint.Read(s.r)
		if err != nil {
			return &streamError{Code: errorRequestIncomplete, Err: err}
		}

		switch t {
		case FrameTypeHeaders:
			max := s.conn.maxHeaderBytes()
			if l > max {
				return &streamError{Code: errorFrameError, Err: &frameLengthError{FrameType: t, Length: l, Max: max}}
			}

			p := make([]byte, l)
			_, err := io.ReadFull(s.stream, p)
			if err != nil {
				return &streamError{Code: errorRequestIncomplete, Err: err}
			}
			l = 0 // TODO: should this subtract the returned n from io.ReadFull?

			dec := qpack.NewDecoder(nil)
			fields, err := dec.DecodeFull(p)
			if err != nil {
				return &connError{Code: errorGeneralProtocolError, Err: err}
			}

			if msg == nil || msg.interim {
				// Start a new message
				interim, err := isInterim(fields)
				if err != nil {
					return &streamError{Code: errorGeneralProtocolError, Err: err}
				}
				msg = newIncomingMessage(s, fields, interim)
				s.messages <- msg
			} else if msg.trailers == nil {
				// Set trailers
				msg.trailers = fields
				close(msg.trailersRead)
			} else {
				// Unexpected HEADERS frame
				return &streamError{Code: errorFrameUnexpected, Err: &frameTypeError{Type: t}}
			}

		case FrameTypeData:
			if msg == nil || msg.interim {
				// Unexpected DATA frame (interim responses do not have response bodies)
				return &streamError{Code: errorFrameUnexpected, Err: &frameTypeError{Want: FrameTypeHeaders, Type: t}}
			} else if msg.trailers != nil {
				// Unexpected DATA frame following trailers
				return &streamError{Code: errorFrameUnexpected, Err: &frameTypeError{Type: t}}
			}

			// Wait for the frame to be consumed
		readLoop:
			for l > 0 {
				select {
				case s.bytesToRead <- l:
					l = <-s.bytesUnread
				case <-s.bodyReaderClosed:
					// Caller ignoring further DATA frames; discard any remaining payload
					break readLoop
				}
			}
		}

		// Skip unread payload bytes
		if l != 0 {
			_, err := io.CopyN(ioutil.Discard, s.stream, int64(l))
			if err != nil {
				return &streamError{Code: errorRequestIncomplete, Err: err}
			}
		}

		// Read frame type
		i, err := quicvarint.Read(s.r)
		if err != nil {
			if err == io.EOF {
				return err // TODO: is this right?
			}
			return &streamError{Code: errorRequestIncomplete, Err: err}
		}
		t = FrameType(i)
	}
}

func (s *messageStream) readBody(p []byte) (n int, err error) {
	var l uint64
	select {
	// Get DATA frame from parseIncomingFrames loop
	case l = <-s.bytesToRead:
	case <-s.bodyReaderClosed:
		return 0, errAlreadyClosed
	case <-s.readDone:
		return 0, s.readErr
	}
	if l < uint64(len(p)) {
		n, err = s.stream.Read(p[:l])
	} else {
		n, err = s.stream.Read(p)
	}
	l -= uint64(n)
	// Hand control back to parseIncomingFrames loop
	s.bytesUnread <- l
	return n, err
}

func (s *messageStream) closeBody() error {
	select {
	case <-s.bodyReaderClosed:
		return errAlreadyClosed
	default:
	}
	close(s.bodyReaderClosed)
	return nil
}

var errAlreadyClosed = errors.New("already closed")

func (s *messageStream) writeDataFrame(p []byte) (n int, err error) {
	quicvarint.Write(s.w, uint64(FrameTypeData))
	quicvarint.Write(s.w, uint64(len(p)))
	n, err = s.w.Write(p)
	return
}

func isInterim(headers []qpack.HeaderField) (bool, error) {
	for i := range headers {
		if headers[i].Name == ":status" {
			status, err := strconv.Atoi(headers[i].Value)
			if err != nil {
				return false, errors.New("malformed non-numeric :status pseudo header")
			}
			if status >= 100 && status < 200 {
				return true, nil
			}
		}
	}
	return false, nil
}
