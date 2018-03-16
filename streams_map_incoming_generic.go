package quic

import (
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

//go:generate genny -in $GOFILE -out streams_map_incoming_bidi.go gen "item=streamI Item=BidiStream"
//go:generate genny -in $GOFILE -out streams_map_incoming_uni.go gen "item=receiveStreamI Item=UniStream"
type incomingItemsMap struct {
	mutex sync.RWMutex
	cond  sync.Cond

	// The map contains:
	// * the stream, if it is an active stream
	// * no entry, if the stream doesn't exist and is higher than the highest stream
	// * nil, if the stream doesn't exist and is smaller than the highest stream
	// * no entry, if the stream is smaller than the highest stream and already closed
	streams map[protocol.StreamID]item

	acceptQueue []item

	nextStream    protocol.StreamID // the next stream that the peer will open (if in order)
	maxStream     protocol.StreamID // the highest stream that the peer is allowed to open
	maxNumStreams int               // maximum number of streams

	newStream        func(protocol.StreamID) item
	queueMaxStreamID func(*wire.MaxStreamIDFrame)

	closeErr error
}

func newIncomingItemsMap(
	nextStream protocol.StreamID,
	initialMaxStreamID protocol.StreamID,
	maxNumStreams int,
	queueControlFrame func(wire.Frame),
	newStream func(protocol.StreamID) item,
) *incomingItemsMap {
	m := &incomingItemsMap{
		streams:          make(map[protocol.StreamID]item),
		maxStream:        initialMaxStreamID,
		maxNumStreams:    maxNumStreams,
		nextStream:       nextStream,
		newStream:        newStream,
		queueMaxStreamID: func(f *wire.MaxStreamIDFrame) { queueControlFrame(f) },
	}
	m.cond.L = &m.mutex
	return m
}

func (m *incomingItemsMap) AcceptStream() (item, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for {
		if m.closeErr != nil {
			return nil, m.closeErr
		}
		if len(m.acceptQueue) > 0 {
			str := m.acceptQueue[0]
			m.acceptQueue = m.acceptQueue[1:]
			m.maybeQueueMaxStreamID()
			return str, nil
		}
		m.cond.Wait()
	}
}

func (m *incomingItemsMap) GetOrOpenStream(id protocol.StreamID) (item, error) {
	m.mutex.RLock()
	if id > m.maxStream {
		m.mutex.RUnlock()
		return nil, fmt.Errorf("peer tried to open stream %d (current limit: %d)", id, m.maxStream)
	}
	if id < m.nextStream {
		s, ok := m.streams[id]
		// if the stream exists in the map, return it
		// if no entry exists in the map, the stream was already closed
		if !ok || s != nil {
			m.mutex.RUnlock()
			return s, nil
		}
		// if the value is nil, the stream should be created
	}
	m.mutex.RUnlock()

	m.mutex.Lock()
	// no need to check the two error conditions from above again
	// * maxStream can only increase, so if the id was valid before, it definitely is valid now
	// * highestStream is only modified by this function
	if id > m.nextStream {
		for newID := m.nextStream; newID < id; newID += 4 {
			m.streams[newID] = nil
		}
	}
	str := m.newStream(id)
	m.streams[id] = str
	m.acceptQueue = append(m.acceptQueue, str)
	if id >= m.nextStream {
		m.nextStream = id + 4
	}
	m.mutex.Unlock()
	m.cond.Signal()
	return str, nil
}

func (m *incomingItemsMap) DeleteStream(id protocol.StreamID) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if str, ok := m.streams[id]; !ok || str == nil {
		return fmt.Errorf("Tried to delete unknown stream %d", id)
	}
	delete(m.streams, id)
	m.maybeQueueMaxStreamID()
	return nil
}

func (m *incomingItemsMap) maybeQueueMaxStreamID() {
	// Note that streams that have been accepted, but haven't been accepted are counted twice.
	// This is necessary because a stream that is opened and deleted before it is accepted will be removed from the map, but not the accept queue.
	// This shouldn't be a problem since an application is expected to immediately accept new streams.
	numNewStreams := m.maxNumStreams - len(m.acceptQueue) - len(m.streams)
	if numNewStreams < 1 {
		return
	}
	// queue a MAX_STREAM_ID frame, giving the peer the option to open a new stream
	if maxStream := m.nextStream + protocol.StreamID((numNewStreams-1)*4); maxStream > m.maxStream {
		m.maxStream = maxStream
		m.queueMaxStreamID(&wire.MaxStreamIDFrame{StreamID: maxStream})
	}
}

func (m *incomingItemsMap) CloseWithError(err error) {
	m.mutex.Lock()
	m.closeErr = err
	m.mutex.Unlock()
	m.cond.Broadcast()
}
