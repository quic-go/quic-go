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

type streamLambda func(*stream) (bool, error)

func newStreamsMap() *streamsMap {
	return &streamsMap{
		streams: map[protocol.StreamID]*stream{},
	}
}

func (m *streamsMap) GetStream(id protocol.StreamID) (*stream, bool) {
	m.mutex.RLock()
	s, ok := m.streams[id]
	m.mutex.RUnlock()
	if !ok {
		return nil, false
	}
	return s, true
}

func (m *streamsMap) Iterate(fn streamLambda) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, str := range m.streams {
		cont, err := fn(str)
		if err != nil {
			return err
		}
		if !cont {
			break
		}
	}
	return nil
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

// Attention: this function must only be called if a mutex has been acquired previously
func (m *streamsMap) RemoveStream(id protocol.StreamID) error {
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
