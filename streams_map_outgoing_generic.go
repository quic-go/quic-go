package quic

import (
	"fmt"
	"sync"

	"github.com/cheekybits/genny/generic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type item generic.Type

//go:generate genny -in $GOFILE -out streams_map_outgoing_bidi.go gen "item=streamI Item=BidiStream"
//go:generate genny -in $GOFILE -out streams_map_outgoing_uni.go gen "item=sendStreamI Item=UniStream"
type outgoingItemsMap struct {
	mutex sync.RWMutex
	cond  sync.Cond

	streams map[protocol.StreamID]item

	nextStream protocol.StreamID
	maxStream  protocol.StreamID
	newStream  func(protocol.StreamID) item

	closeErr error
}

func newOutgoingItemsMap(nextStream protocol.StreamID, newStream func(protocol.StreamID) item) *outgoingItemsMap {
	m := &outgoingItemsMap{
		streams:    make(map[protocol.StreamID]item),
		nextStream: nextStream,
		newStream:  newStream,
	}
	m.cond.L = &m.mutex
	return m
}

func (m *outgoingItemsMap) OpenStream() (item, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.openStreamImpl()
}

func (m *outgoingItemsMap) OpenStreamSync() (item, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for {
		str, err := m.openStreamImpl()
		if err == nil {
			return str, err
		}
		if err != nil && err != qerr.TooManyOpenStreams {
			return nil, err
		}
		m.cond.Wait()
	}
}

func (m *outgoingItemsMap) openStreamImpl() (item, error) {
	if m.closeErr != nil {
		return nil, m.closeErr
	}
	if m.nextStream > m.maxStream {
		return nil, qerr.TooManyOpenStreams
	}
	s := m.newStream(m.nextStream)
	m.streams[m.nextStream] = s
	m.nextStream += 4
	return s, nil
}

func (m *outgoingItemsMap) GetStream(id protocol.StreamID) (item, error) {
	if id >= m.nextStream {
		return nil, qerr.Error(qerr.InvalidStreamID, fmt.Sprintf("peer attempted to open stream %d", id))
	}
	m.mutex.RLock()
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
	if id > m.maxStream {
		m.maxStream = id
		m.cond.Broadcast()
	}
	m.mutex.Unlock()
}

func (m *outgoingItemsMap) CloseWithError(err error) {
	m.mutex.Lock()
	m.closeErr = err
	m.cond.Broadcast()
	m.mutex.Unlock()
}
