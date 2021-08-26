package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"github.com/marten-seemann/qpack"
)

/*

An HTTP/3 message is a HEADERS frame followed by zero or more DATA frames, optionally followed by a single HEADERS frame (the trailers).

Extension frames

*/

// A MessageStream is a QUIC stream for processing HTTP/3 request and response messages.
type MessageStream interface {
	StreamID() quic.StreamID

	Context() context.Context

	// Reads a single HTTP message.
	// For servers, ReadMessage reads an HTTP request.
	// For clients, ReadMessage reads an HTTP response.
	// An interim response (status codes 100-199) will have nil Trailers and Body.
	// Interim responses must be followed by additional response messages.
	ReadMessage() (Message, error)

	// Writes a single HTTP message.
	// For servers, WriteMessage writes an HTTP response. Multiple responses can be written.
	// For clients, WriteMessage writes an HTTP request.
	WriteMessage(Message) error

	// TODO: integrate QPACK encoding and decoding with dynamic tables.

	CancelRead(code quic.StreamErrorCode)
	CancelWrite(code quic.StreamErrorCode)
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

	messages chan *incomingMessage
	readErr  error

	// Used to synchronize reading DATA frames, used for HTTP message bodies
	bytesToRead chan uint64
	bytesUnread chan uint64

	bodyReaderClosed chan struct{}
	readDone         chan struct{}
}

var _ MessageStream = &messageStream{}

// newMessageStream creates a new MessageStream. If first is non-nil, the
// parser will assume the first varint has already been read from the stream.
func newMessageStream(conn *connection, stream quic.Stream, first *FrameType) *messageStream {
	s := &messageStream{
		conn:             conn,
		stream:           stream,
		r:                quicvarint.NewReader(stream),
		w:                quicvarint.NewWriter(stream),
		messages:         make(chan *incomingMessage),
		bytesToRead:      make(chan uint64),
		bytesUnread:      make(chan uint64),
		bodyReaderClosed: make(chan struct{}),
		readDone:         make(chan struct{}),
	}
	go s.handleIncomingFrames(first)
	return s
}

func (s *messageStream) StreamID() quic.StreamID {
	return s.stream.StreamID()
}

func (s *messageStream) Context() context.Context {
	return s.stream.Context()
}

// ReadMessage reads a single HTTP message from s or a read error, if any.
func (s *messageStream) ReadMessage() (Message, error) {
	select {
	case msg := <-s.messages:
		return msg, nil
	case <-s.readDone:
		return nil, s.readErr
	case <-s.stream.Context().Done():
		return nil, s.stream.Context().Err()
	}
}

// WriteMessage writes a single HTTP message to s. It does not validate
// the message, or enforce ordering of messages on a stream.
// It does not close the stream for writing.
// The message will be written as follows:
// A single HEADERS frame, followed by 0 or more DATA frames for the message body,
// followed by an optional HEADERS frame for the message trailers.
// WriteMessage will call Close on the message body on success.
func (s *messageStream) WriteMessage(msg Message) error {
	err := s.writeFieldsFrame(msg.Headers())
	if err != nil {
		return err
	}
	body := msg.Body()
	if body != nil {
		err = s.writeDataFrom(body)
		if err != nil {
			return err
		}
		err = body.Close()
		if err != nil {
			return err
		}
	}
	trailers := msg.Trailers()
	if trailers != nil {
		err = s.writeFieldsFrame(trailers)
		if err != nil {
			return err
		}
	}
	return nil
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
	s.conn.cleanup(s.StreamID())
	return s.stream.Close()
}

func (s *messageStream) CancelRead(code quic.StreamErrorCode) {
	s.conn.cleanup(s.StreamID())
	s.stream.CancelRead(code)
}

// func (s *messageStream) CancelWrite(code quic.StreamErrorCode) {
// 	s.conn.cleanup(s.Stream.StreamID())
// 	s.Stream.CancelWrite(code)
// }

func (s *messageStream) handleIncomingFrames(first *FrameType) {
	err := s.parseIncomingFrames(first)
	code := errorNoError
	if serr, ok := err.(*streamError); ok {
		code = serr.Code
	}
	s.CancelRead(quic.StreamErrorCode(code))
	s.readErr = err
	close(s.readDone)
	s.conn.cleanup(s.stream.StreamID())
}

func (s *messageStream) parseIncomingFrames(first *FrameType) error {
	var t FrameType
	if first != nil {
		t = *first
	} else {
		i, err := quicvarint.Read(s.r)
		if err != nil {
			return &streamError{Code: errorRequestIncomplete, Err: err}
		}
		t = FrameType(i)
	}

	// HTTP messages must begin with a HEADERS frame.
	if t != FrameTypeHeaders {
		return &connError{Code: errorFrameUnexpected, Err: &frameTypeError{Want: FrameTypeHeaders, Got: t}}
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
					return &connError{Code: errorGeneralProtocolError, Err: err}
				}
				msg = newIncomingMessage(s, fields, interim)
				s.messages <- msg
			} else if msg.trailers == nil {
				// Set trailers
				msg.trailers = fields
				close(msg.trailersRead)
			} else {
				// Unexpected HEADERS frame
				return &streamError{Code: errorFrameUnexpected, Err: &frameTypeError{Got: t}}
			}

		case FrameTypeData:
			if msg == nil || msg.interim {
				// Unexpected DATA frame (interim responses do not have response bodies)
				return &streamError{Code: errorFrameUnexpected, Err: &frameTypeError{Want: FrameTypeHeaders, Got: t}}
			} else if msg.trailers != nil {
				// Unexpected DATA frame following trailers
				return &streamError{Code: errorFrameUnexpected, Err: &frameTypeError{Got: t}}
			}

			// Wait for the frame to be consumed
			for l > 0 {
				select {
				case s.bytesToRead <- l:
					l = <-s.bytesUnread
				case <-s.bodyReaderClosed:
					// Caller ignoring further DATA frames; discard any remaining payload
					break
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

// writeFieldsFrame writes a single QPACK-encoded HEADERS frame to s.
// It returns an error if the estimated size of the frame exceeds the peer’s
// MAX_FIELD_SECTION_SIZE. Headers are not modified or validated.
// It is the responsibility of the caller to ensure the fields are valid.
func (s *messageStream) writeFieldsFrame(fields []qpack.HeaderField) error {
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

	w := quicvarint.NewWriter(s.stream)
	quicvarint.Write(w, uint64(FrameTypeHeaders))
	quicvarint.Write(w, uint64(buf.Len()))
	_, err := s.stream.Write(buf.Bytes())
	return err
}

func (s *messageStream) writeDataFrom(r io.Reader) error {
	buf := make([]byte, bodyCopyBufferSize)
	for {
		l, rerr := r.Read(buf)
		if l == 0 {
			if rerr == nil {
				continue
			} else if rerr == io.EOF {
				return nil
			}
		}
		_, err := s.writeDataFrame(buf[:l])
		if err != nil {
			return err
		}
		if rerr == io.EOF {
			return nil
		}
	}
}

// TODO: remove this method?
func (s *messageStream) writeData(p []byte) error {
	var err error
	for len(p) > 0 {
		pp := p
		if len(p) > bodyCopyBufferSize {
			pp = p[:bodyCopyBufferSize]
		}
		x, err := s.writeDataFrame(pp)
		p = p[x:]
		if err != nil {
			return err
		}
	}
	return err
}

func (s *messageStream) writeDataFrame(p []byte) (n int, err error) {
	quicvarint.Write(s.w, uint64(FrameTypeData))
	quicvarint.Write(s.w, uint64(len(p)))
	return s.stream.Write(p)
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
