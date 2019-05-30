package quic

import (
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

//go:generate genny -in $GOFILE -out streams_map_outgoing_bidi.go gen "item=streamI Item=BidiStream streamTypeGeneric=protocol.StreamTypeBidi"
//go:generate genny -in $GOFILE -out streams_map_outgoing_uni.go gen "item=sendStreamI Item=UniStream streamTypeGeneric=protocol.StreamTypeUni"
type outgoingItemsMap struct {
	mutex sync.RWMutex

	openQueue []chan struct{}

	streams map[protocol.StreamID]item

	nextStream  protocol.StreamID // stream ID of the stream returned by OpenStream(Sync)
	maxStream   protocol.StreamID // the maximum stream ID we're allowed to open
	blockedSent bool              // was a STREAMS_BLOCKED sent for the current maxStream

	newStream            func(protocol.StreamID) item
	queueStreamIDBlocked func(*wire.StreamsBlockedFrame)

	closeErr error
}

func newOutgoingItemsMap(
	nextStream protocol.StreamID,
	newStream func(protocol.StreamID) item,
	queueControlFrame func(wire.Frame),
) *outgoingItemsMap {
	return &outgoingItemsMap{
		streams:              make(map[protocol.StreamID]item),
		nextStream:           nextStream,
		maxStream:            protocol.InvalidStreamID,
		newStream:            newStream,
		queueStreamIDBlocked: func(f *wire.StreamsBlockedFrame) { queueControlFrame(f) },
	}
}

func (m *outgoingItemsMap) OpenStream() (item, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.openStreamImpl()
}

func (m *outgoingItemsMap) OpenStreamSync() (item, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	str, err := m.openStreamImpl()
	if err == nil {
		return str, nil
	}
	if err != errTooManyOpenStreams {
		return nil, err
	}
	waitChan := make(chan struct{})
	m.openQueue = append(m.openQueue, waitChan)
	m.mutex.Unlock()

	<-waitChan
	m.mutex.Lock()
	str, err = m.openStreamImpl()
	if err != nil {
		return nil, err
	}
	m.triggerOpenSync()
	return str, nil
}

func (m *outgoingItemsMap) openStreamImpl() (item, error) {
	if m.closeErr != nil {
		return nil, m.closeErr
	}

	if m.nextStream > m.maxStream {
		if !m.blockedSent {
			var streamNum uint64
			if m.maxStream != protocol.InvalidStreamID {
				streamNum = m.maxStream.StreamNum()
			}
			m.queueStreamIDBlocked(&wire.StreamsBlockedFrame{
				Type:        streamTypeGeneric,
				StreamLimit: streamNum,
			})
			m.blockedSent = true
		}
		return nil, errTooManyOpenStreams
	}
	s := m.newStream(m.nextStream)
	m.streams[m.nextStream] = s
	m.nextStream += 4
	return s, nil
}

func (m *outgoingItemsMap) GetStream(id protocol.StreamID) (item, error) {
	m.mutex.RLock()
	if id >= m.nextStream {
		m.mutex.RUnlock()
		return nil, qerr.Error(qerr.StreamStateError, fmt.Sprintf("peer attempted to open stream %d", id))
	}
	s := m.streams[id]
	m.mutex.RUnlock()
	return s, nil
}

func (m *outgoingItemsMap) DeleteStream(id protocol.StreamID) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.streams[id]; !ok {
		return fmt.Errorf("Tried to delete unknown stream %d", id)
	}
	delete(m.streams, id)
	return nil
}

func (m *outgoingItemsMap) SetMaxStream(id protocol.StreamID) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if id <= m.maxStream {
		return
	}
	m.maxStream = id
	m.blockedSent = false
	m.triggerOpenSync()
}

// needs to be called with the mutex called
func (m *outgoingItemsMap) triggerOpenSync() {
	if len(m.openQueue) == 0 || m.nextStream > m.maxStream {
		return
	}
	close(m.openQueue[0])
	m.openQueue = m.openQueue[1:]
}

func (m *outgoingItemsMap) CloseWithError(err error) {
	m.mutex.Lock()
	m.closeErr = err
	for _, str := range m.streams {
		str.closeForShutdown(err)
	}
	for _, c := range m.openQueue {
		close(c)
	}
	m.mutex.Unlock()
}
