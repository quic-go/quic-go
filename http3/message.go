package http3

import (
	"io"

	"github.com/marten-seemann/qpack"
)

type Message interface {
	Headers() []qpack.HeaderField
	Trailers() []qpack.HeaderField
	Body() io.ReadCloser
}

type incomingMessage struct {
	stream       *messageStream
	headers      []qpack.HeaderField
	trailers     []qpack.HeaderField
	trailersRead chan struct{}
	interim      bool
}

var _ Message = &incomingMessage{}

func newIncomingMessage(stream *messageStream, headers []qpack.HeaderField, interim bool) *incomingMessage {
	var trailersRead chan struct{}
	if !interim {
		trailersRead = make(chan struct{})
	}
	return &incomingMessage{
		stream:       stream,
		headers:      headers,
		trailersRead: trailersRead,
		interim:      interim,
	}
}

func (m *incomingMessage) Headers() []qpack.HeaderField {
	return m.headers
}

func (m *incomingMessage) Trailers() []qpack.HeaderField {
	if m.interim {
		return nil
	}
	<-m.trailersRead
	return m.trailers
}

func (m *incomingMessage) Body() io.ReadCloser {
	if m.interim {
		return nil
	}
	return (*incomingMessageBody)(m)
}

type incomingMessageBody incomingMessage

func (m *incomingMessageBody) Read(p []byte) (n int, err error) {
	return m.stream.readBody(p)
}

func (m *incomingMessageBody) Close() error {
	return m.stream.closeBody()
}
