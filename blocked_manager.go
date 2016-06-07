package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

type blockedManager struct {
	blockedStreams map[protocol.StreamID]protocol.ByteCount
	mutex          sync.Mutex
}

func newBlockedManager() *blockedManager {
	return &blockedManager{
		blockedStreams: make(map[protocol.StreamID]protocol.ByteCount),
	}
}

func (m *blockedManager) AddBlockedStream(streamID protocol.StreamID, offset protocol.ByteCount) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.blockedStreams[streamID] = offset
}

func (m *blockedManager) RemoveBlockedStream(streamID protocol.StreamID) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.blockedStreams, streamID)
}

func (m *blockedManager) GetBlockedFrame(streamID protocol.StreamID, offset protocol.ByteCount) *frames.BlockedFrame {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	blockedOffset, ok := m.blockedStreams[streamID]
	if !ok {
		return nil
	}
	if blockedOffset > offset {
		return nil
	}

	delete(m.blockedStreams, streamID)
	return &frames.BlockedFrame{StreamID: streamID}
}
