package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	conn *connection
	str  quic.Stream

	fr *FrameReader
	w  quicvarint.Writer

	once sync.Once

	messages chan *incomingMessage
	readErr  error

	// Used to synchronize reading DATA frames, used for HTTP message bodies
	dataReady chan struct{}
	dataRead  chan struct{}

	bodyReaderClosed chan struct{}
	readDone         chan struct{}
}

var (
	_ MessageStream = &messageStream{}
	_ io.Writer     = &messageStream{}
	_ io.ReaderFrom = &messageStream{}
	_ io.Closer     = &messageStream{}
)

// newMessageStream creates a new MessageStream.
// If a frame has already been partially consumed from str, t specifies
// the frame type and n the number of bytes remaining in the frame payload.
func newMessageStream(conn *connection, str quic.Stream, t FrameType, n int64) MessageStream {
	s := &messageStream{
		conn:             conn,
		str:              str,
		fr:               &FrameReader{R: str, Type: t, N: n},
		w:                quicvarint.NewWriter(str),
		messages:         make(chan *incomingMessage),
		dataReady:        make(chan struct{}),
		dataRead:         make(chan struct{}),
		bodyReaderClosed: make(chan struct{}),
		readDone:         make(chan struct{}),
	}
	return s
}

func (s *messageStream) Stream() quic.Stream {
	return s.str
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
	case <-s.str.Context().Done():
		return nil, s.str.Context().Err()
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
	return newWebTransportSession(s.conn, s.str), nil
}

func (s *messageStream) Close() error {
	s.conn.cleanup(s.str.StreamID())
	// s.stream.CancelRead(quic.StreamErrorCode(errorNoError))
	return s.str.Close()
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
	var msg *incomingMessage

	for frameCount := 0; ; frameCount++ {
		err := s.fr.Next()
		if err != nil {
			// TODO(ydnar): is MessageStream responsible for H3 semantics,
			// and close the stream and/or connection?
			if err == io.EOF {
				return err
			}
			return &streamError{Code: errorRequestIncomplete, Err: err}
		}

		// HTTP messages must begin with a HEADERS frame.
		if frameCount == 0 && s.fr.Type != FrameTypeHeaders {
			return &connError{Code: errorFrameUnexpected, Err: &FrameTypeError{Want: FrameTypeHeaders, Type: s.fr.Type}}
		}

		switch s.fr.Type {
		case FrameTypeHeaders:
			max := s.conn.maxHeaderBytes()
			if s.fr.N > int64(max) {
				return &streamError{Code: errorFrameError, Err: &FrameLengthError{Type: s.fr.Type, Len: uint64(s.fr.N), Max: max}}
			}

			p := make([]byte, s.fr.N)
			_, err := io.ReadFull(s.fr, p)
			if err != nil {
				return &streamError{Code: errorRequestIncomplete, Err: err}
			}

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
				return &streamError{Code: errorFrameUnexpected, Err: &FrameTypeError{Type: s.fr.Type}}
			}

		case FrameTypeData:
			if msg == nil || msg.interim {
				// Unexpected DATA frame (interim responses do not have response bodies)
				return &streamError{Code: errorFrameUnexpected, Err: &FrameTypeError{Want: FrameTypeHeaders, Type: s.fr.Type}}
			} else if msg.trailers != nil {
				// Unexpected DATA frame following trailers
				return &streamError{Code: errorFrameUnexpected, Err: &FrameTypeError{Type: s.fr.Type}}
			}

			// Wait for the frame to be consumed
		readLoop:
			for s.fr.N > 0 {
				select {
				case s.dataReady <- struct{}{}:
					<-s.dataRead
				case <-s.bodyReaderClosed:
					// Caller ignoring further DATA frames; discard any remaining payload
					break readLoop
				}
			}
		}
	}
}

func (s *messageStream) readBody(p []byte) (n int, err error) {
	select {
	// Get DATA frame from parseIncomingFrames loop
	case <-s.dataReady:
	case <-s.bodyReaderClosed:
		return 0, errAlreadyClosed
	case <-s.readDone:
		return 0, s.readErr
	}
	if s.fr.N < int64(len(p)) {
		n, err = s.fr.Read(p[:s.fr.N])
	} else {
		n, err = s.fr.Read(p)
	}
	// Hand control back to parseIncomingFrames loop
	s.dataRead <- struct{}{}
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
