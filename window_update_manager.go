package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

type windowUpdateItem struct {
	Offset  protocol.ByteCount
	Counter uint8
}

// windowUpdateManager manages window update frames for receiving data
type windowUpdateManager struct {
	streamOffsets map[protocol.StreamID]*windowUpdateItem
	mutex         sync.RWMutex
}

// newWindowUpdateManager returns a new windowUpdateManager
func newWindowUpdateManager() *windowUpdateManager {
	return &windowUpdateManager{
		streamOffsets: make(map[protocol.StreamID]*windowUpdateItem),
	}
}

// SetStreamOffset sets an offset for a stream
func (m *windowUpdateManager) SetStreamOffset(streamID protocol.StreamID, n protocol.ByteCount) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	entry, ok := m.streamOffsets[streamID]
	if !ok {
		m.streamOffsets[streamID] = &windowUpdateItem{Offset: n}
		return
	}

	if n > entry.Offset {
		entry.Offset = n
		entry.Counter = 0
	}
}

// GetWindowUpdateFrames gets all the WindowUpdate frames that need to be sent
func (m *windowUpdateManager) GetWindowUpdateFrames() []*frames.WindowUpdateFrame {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var wuf []*frames.WindowUpdateFrame

	for key, value := range m.streamOffsets {
		if value.Counter >= protocol.WindowUpdateNumRepitions {
			continue
		}

		frame := frames.WindowUpdateFrame{
			StreamID:   key,
			ByteOffset: value.Offset,
		}
		value.Counter++
		wuf = append(wuf, &frame)
	}

	return wuf
}
