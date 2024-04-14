package http3

import (
	"context"
	"fmt"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
)

const maxQuarterStreamID = 1<<60 - 1

const streamDatagramQueueLen = 32

type datagrammer struct {
	conn     *connection
	streamID protocol.StreamID

	hasData chan struct{}
	queue   [][]byte // TODO: use a ring buffer

	mx         sync.Mutex
	state      datagramState
	sendErr    error
	receiveErr error
}

func newDatagrammer(conn *connection, streamID protocol.StreamID) *datagrammer {
	if streamID%4 != 0 {
		panic(fmt.Sprintf("invalid stream ID for HTTP datagrams: %d", streamID))
	}
	return &datagrammer{
		conn:     conn,
		streamID: streamID,
		state:    streamStateOpen,
		hasData:  make(chan struct{}, 1),
	}
}

func (d *datagrammer) SetState(tr quic.StreamTransition) (isDone bool) {
	var sendErr, receiveErr error
	var s datagramState
	switch tr.NewState {
	case quic.SendStreamStateDataSent:
		s = streamStateSendClosed
	case quic.SendStreamStateResetSent:
		s = streamStateSendClosed
		sendErr = tr.Error
	case quic.ReceiveStreamStateSizeKnown:
		s = streamStateReceiveClosed
	case quic.ReceiveStreamStateResetRecvd:
		s = streamStateReceiveClosed
		receiveErr = tr.Error
	default:
		return
	}

	d.mx.Lock()
	defer d.mx.Unlock()

	switch {
	case d.state == streamStateSendClosed && s == streamStateReceiveClosed:
		return true
	case d.state == streamStateReceiveClosed && s == streamStateSendClosed:
		return true
	default:

	}
	d.state = s
	if sendErr != nil {
		d.sendErr = sendErr
	}
	if receiveErr != nil {
		d.receiveErr = receiveErr
	}
	select {
	case d.hasData <- struct{}{}:
	default:
	}
	return false
}

func (d *datagrammer) Send(b []byte) error {
	d.mx.Lock()
	sendErr := d.sendErr
	d.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}

	return d.conn.sendDatagram(d.streamID, b)
}

func (d *datagrammer) enqueue(data []byte) {
	d.mx.Lock()
	defer d.mx.Unlock()

	if d.state == streamStateForbidden || d.state == streamStateReceiveClosed {
		return
	}
	if len(d.queue) >= streamDatagramQueueLen {
		return
	}
	d.queue = append(d.queue, data)
	select {
	case d.hasData <- struct{}{}:
	default:
	}
}

func (d *datagrammer) Receive(ctx context.Context) ([]byte, error) {
start:
	d.mx.Lock()
	if len(d.queue) > 1 {
		data := d.queue[0]
		d.queue = d.queue[1:]
		d.mx.Unlock()
		return data, nil
	}
	if d.receiveErr != nil {
		d.mx.Unlock()
		return nil, d.receiveErr
	}
	d.mx.Unlock()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-d.hasData:
	}
	goto start
}
