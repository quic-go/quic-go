package quic

import (
	"errors"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/protocol"
)

type streamsMap struct {
	streams     map[protocol.StreamID]*stream
	openStreams []protocol.StreamID
	mutex       sync.RWMutex

	roundRobinIndex int
}

type streamLambda func(*stream) (bool, error)

var (
	errMapAccess = errors.New("streamsMap: Error accessing the streams map")
)

func newStreamsMap() *streamsMap {
	maxNumStreams := uint32(float32(protocol.MaxStreamsPerConnection) * protocol.MaxStreamsMultiplier)
	return &streamsMap{
		streams:     map[protocol.StreamID]*stream{},
		openStreams: make([]protocol.StreamID, 0, maxNumStreams),
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

	for _, streamID := range m.openStreams {
		str, ok := m.streams[streamID]
		if !ok {
			return errMapAccess
		}
		if str == nil {
			return fmt.Errorf("BUG: Stream %d is closed, but still in openStreams map", streamID)
		}
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

func (m *streamsMap) RoundRobinIterate(fn streamLambda) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	numStreams := len(m.openStreams)
	startIndex := m.roundRobinIndex

	for i := 0; i < numStreams; i++ {
		streamID := m.openStreams[(i+startIndex)%numStreams]
		str, ok := m.streams[streamID]
		if !ok {
			return errMapAccess
		}
		if str == nil {
			return fmt.Errorf("BUG: Stream %d is closed, but still in openStreams map", streamID)
		}
		cont, err := fn(str)
		if err != nil {
			return err
		}
		if !cont {
			break
		}
		m.roundRobinIndex = (m.roundRobinIndex + 1) % numStreams
	}
	return nil
}

func (m *streamsMap) PutStream(s *stream) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	id := s.StreamID()
	if _, ok := m.streams[id]; ok {
		return fmt.Errorf("a stream with ID %d already exists", id)
	}

	m.streams[id] = s
	m.openStreams = append(m.openStreams, id)

	return nil
}

// Attention: this function must only be called if a mutex has been acquired previously
func (m *streamsMap) RemoveStream(id protocol.StreamID) error {
	s, ok := m.streams[id]
	if !ok || s == nil {
		return fmt.Errorf("attempted to remove non-existing stream: %d", id)
	}

	m.streams[id] = nil

	for i, s := range m.openStreams {
		if s == id {
			// delete the streamID from the openStreams slice
			m.openStreams = m.openStreams[:i+copy(m.openStreams[i:], m.openStreams[i+1:])]
			// adjust round-robin index, if necessary
			if i < m.roundRobinIndex {
				m.roundRobinIndex--
			}
			break
		}
	}

	return nil
}

// NumberOfStreams gets the number of open streams
func (m *streamsMap) NumberOfStreams() int {
	m.mutex.RLock()
	n := len(m.openStreams)
	m.mutex.RUnlock()
	return n
}
