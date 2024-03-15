package http3

import (
	"bytes"
	"context"
	"fmt"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// Datagrammer allows sending and receiving of HTTP datagrams
type Datagrammer interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

type connectionDatagrammer struct {
	conn         quic.Connection
	datagrammers map[protocol.StreamID]*streamDatagrammer
}

func (d *connectionDatagrammer) run() error {
	for {
		data, err := d.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		// TODO: this is quite inefficient in terms of allocations
		buf := bytes.NewBuffer(data)
		quarterStreamID, err := quicvarint.Read(buf)
		if err != nil {
			d.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
		}
		streamID := protocol.StreamID(4 * quarterStreamID)
		datagrammer, ok := d.datagrammers[streamID]
		if !ok {
			// TODO: handle
		}
		datagrammer.enqueue(data[len(data)-buf.Len():])
	}
}

const streamDatagramQueueLen = 32

type streamDatagrammer struct {
	conn            quic.Connection // the underlying QUIC connection
	quarterStreamID protocol.StreamID

	queue chan []byte
}

var _ Datagrammer = &streamDatagrammer{}

// TODO: wire this up into the connection datagrammer
func newStreamDatagrammer(conn quic.Connection, streamID protocol.StreamID) *streamDatagrammer {
	if streamID%4 != 0 {
		panic(fmt.Sprintf("invalid stream ID for HTTP datagrams: %d", streamID))
	}
	return &streamDatagrammer{
		conn:            conn,
		quarterStreamID: streamID / 4,
		queue:           make(chan []byte, streamDatagramQueueLen),
	}
}

func (d *streamDatagrammer) SendDatagram(b []byte) error {
	// TODO: this creates a lot of garbage and an additional copy
	data := make([]byte, 0, len(b)+8)
	data = quicvarint.Append(data, uint64(d.quarterStreamID))
	data = append(data, b...)
	return d.conn.SendDatagram(data)
}

func (d *streamDatagrammer) enqueue(data []byte) {
	select {
	case d.queue <- data:
	default: // drop the datagram
	}
}

func (d *streamDatagrammer) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-d.conn.Context().Done():
		return nil, context.Cause(d.conn.Context())
	case data := <-d.queue:
		return data, nil
	}
}
