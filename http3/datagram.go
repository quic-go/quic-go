package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/quicvarint"
)

const DatagramRcvQueueLen = 128

type datagrammerMap struct {
	mutex   sync.RWMutex
	conn    quic.Connection
	streams map[protocol.StreamID]*streamAssociatedDatagrammer

	// supported means HTTP/3 datagram is supported on both sides
	supported                   bool
	settingNegotiationCtx       context.Context
	settingNegotiationCtxCancel context.CancelFunc

	logger utils.Logger

	runReceivingOnce sync.Once
}

func newDatagramManager(conn quic.Connection, logger utils.Logger) *datagrammerMap {
	m := &datagrammerMap{
		conn:    conn,
		streams: make(map[protocol.StreamID]*streamAssociatedDatagrammer),
		logger:  logger,
	}
	m.settingNegotiationCtx, m.settingNegotiationCtxCancel = context.WithCancel(context.Background())

	return m
}

func (m *datagrammerMap) runReceiving() {
	for {
		data, err := m.conn.ReceiveDatagram(context.Background())
		if err != nil {
			m.logger.Debugf("Stop receiving datagram: %s", err)
			return
		}
		buf := bytes.NewBuffer(data)
		quarterStreamID, err := quicvarint.Read(buf)
		if err != nil {
			m.logger.Debugf("Reading datagram Quarter Stream ID failed: %s", err)
			continue
		}
		streamID := quarterStreamID * 4
		m.mutex.RLock()
		stream, ok := m.streams[protocol.StreamID(streamID)]
		m.mutex.RUnlock()
		if !ok {
			m.logger.Debugf("Received datagram for unknown stream: %d", streamID)
			continue
		}
		stream.handleDatagram(buf.Bytes())
	}
}

func (m *datagrammerMap) OnSettingReiceived(setting bool) {
	m.supported = setting

	if setting {
		m.runReceivingOnce.Do(func() {
			go m.runReceiving()
		})
	}
	m.settingNegotiationCtxCancel()
}

func (m *datagrammerMap) SettingNegotiationComplete() <-chan struct{} {
	return m.settingNegotiationCtx.Done()
}

func (m *datagrammerMap) Supported() bool {
	return m.supported
}

// Datagrammer is an interface that can send and receive HTTP datagrams
type Datagrammer interface {
	// SendMessage sends an HTTP Datagram associated with an HTTP request.
	// It must only be called while the send side of the stream is still open, i.e.
	// * on the client side: before calling Close on the request body
	// * on the server side: before calling Close on the response body
	SendMessage([]byte) error
	// SendMessage receives an HTTP Datagram associated with an HTTP request:
	// * on the server side: datagrams can be received while the request handler hasn't returned, AND
	//      the client hasn't close the request stream yet
	// * on the client side: datagrams can be received with the server hasn't close the response stream
	ReceiveMessage(context.Context) ([]byte, error)
}

// streamAssociatedDatagrammer allows sending and receiving HTTP/3 datagrams before the associated quic
// stream is closed
type streamAssociatedDatagrammer struct {
	str  quic.Stream
	conn quic.Connection

	buf      []byte
	rcvMx    sync.Mutex
	rcvQueue [][]byte
	rcvd     chan struct{}

	manager *datagrammerMap
}

func (m *datagrammerMap) newStreamAssociatedDatagrammer(conn quic.Connection, str quic.Stream) *streamAssociatedDatagrammer {
	d := &streamAssociatedDatagrammer{
		str:     str,
		conn:    conn,
		rcvd:    make(chan struct{}),
		manager: m,
	}
	m.mutex.Lock()
	m.streams[str.StreamID()] = d
	m.mutex.Unlock()
	go func() {
		<-str.Context().Done()
		m.mutex.Lock()
		delete(m.streams, str.StreamID())
		m.mutex.Unlock()
	}()
	return d
}

func (d *streamAssociatedDatagrammer) SendMessage(data []byte) error {
	select {
	case <-d.str.Context().Done():
		return fmt.Errorf("the corresponding stream is closed")
	case <-d.manager.SettingNegotiationComplete():
	}

	if !d.manager.Supported() {
		return errors.New("datagram is not supported by peer")
	}
	d.buf = d.buf[:0]
	d.buf = (&datagramFrame{QuarterStreamID: uint64(d.str.StreamID() / 4)}).Append(d.buf)
	d.buf = append(d.buf, data...)
	return d.conn.SendDatagram(d.buf)
}

func (d *streamAssociatedDatagrammer) ReceiveMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.str.Context().Done():
		return nil, fmt.Errorf("the corresponding stream is closed")
	case <-d.manager.SettingNegotiationComplete():
	}

	if !d.manager.Supported() {
		return nil, errors.New("datagram is not supported by peer")
	}
	for {
		d.rcvMx.Lock()
		if len(d.rcvQueue) > 0 {
			data := d.rcvQueue[0]
			d.rcvQueue = d.rcvQueue[1:]
			d.rcvMx.Unlock()
			return data, nil
		}
		d.rcvMx.Unlock()
		select {
		case <-d.rcvd:
			continue
		case <-d.str.Context().Done():
			return nil, fmt.Errorf("the corresponding stream is closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (d *streamAssociatedDatagrammer) handleDatagram(data []byte) {
	d.rcvMx.Lock()
	if len(d.rcvQueue) < DatagramRcvQueueLen {
		d.rcvQueue = append(d.rcvQueue, data)
		select {
		case d.rcvd <- struct{}{}:
		default:
		}
	}
	d.rcvMx.Unlock()
}
