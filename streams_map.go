package quic

import (
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/protocol"
)

type streamsMap struct {
	streams  map[protocol.StreamID]*stream
	nStreams int
	mutex    sync.RWMutex
}

func newStreamsMap() *streamsMap {
	return &streamsMap{
		streams: map[protocol.StreamID]*stream{},
	}
}

func (m *streamsMap) GetStream(id protocol.StreamID) (*stream, error) {
	m.mutex.RLock()
	s, ok := m.streams[id]
	m.mutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown stream: %d", id)
	}
	return s, nil
}

func (m *streamsMap) PutStream(s *stream) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, ok := m.streams[s.StreamID()]; ok {
		return fmt.Errorf("a stream with ID %d already exists", s.StreamID())
	}
	m.streams[s.StreamID()] = s
	m.nStreams++
	return nil
}

func (m *streamsMap) RemoveStream(id protocol.StreamID) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	s, ok := m.streams[id]
	if !ok || s == nil {
		return fmt.Errorf("attempted to remove non-existing stream: %d", id)
	}
	m.streams[id] = nil
	m.nStreams--
	return nil
}

func (m *streamsMap) NumberOfStreams() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.nStreams
}
