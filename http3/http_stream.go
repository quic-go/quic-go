package http3

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go"
)

// A Stream is a HTTP/3 stream.
// When writing to and reading from the stream, data is framed in HTTP/3 DATA frames.
type Stream interface {
	quic.Stream

	// Datagrams currently as outlined in draft-ietf-masque-h3-datagram-10
	quic.DatagramSendReceiver
}

// The stream conforms to the quic.Stream interface, but instead of writing to and reading directly
// from the QUIC stream, it writes to and reads from the HTTP stream.
type stream struct {
	quic.Stream

	onFrameError          func()
	onClose               func(*stream)
	bytesRemainingInFrame uint64
	dgram                 quic.DatagramSendReceiver
}

var _ Stream = &stream{}

func newStream(str quic.Stream, dgram quic.DatagramSendReceiver, onFrameError func(), onClose func(*stream)) *stream {
	return &stream{Stream: str, onFrameError: onFrameError, onClose: onClose}
}

func (s *stream) Read(b []byte) (int, error) {
	if s.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := parseNextFrame(s.Stream, nil)
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *headersFrame:
				// skip HEADERS frames
				continue
			case *dataFrame:
				s.bytesRemainingInFrame = f.Length
				break parseLoop
			default:
				s.onFrameError()
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if s.bytesRemainingInFrame < uint64(len(b)) {
		n, err = s.Stream.Read(b[:s.bytesRemainingInFrame])
	} else {
		n, err = s.Stream.Read(b)
	}
	s.bytesRemainingInFrame -= uint64(n)
	return n, err
}

func (s *stream) Write(b []byte) (int, error) {
	buf := &bytes.Buffer{}
	(&dataFrame{Length: uint64(len(b))}).Write(buf)
	if _, err := s.Stream.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return s.Stream.Write(b)
}

func (s *stream) Close() error {
	s.onClose(s)
	return s.Stream.Close()
}

func (s *stream) SendMessage(data []byte) error {
	buf := &bytes.Buffer{}
	(&datagramFrame{QuarterStreamId: uint64(s.StreamID() / 4)}).Write(buf)
	buf.Write(data)
	return s.dgram.SendMessage(data)
}

func (s *stream) ReceiveMessage() ([]byte, error) {
	return []byte{}, nil
}

func (s *stream) onMessage(data []byte) {

}
