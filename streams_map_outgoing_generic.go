package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

//go:generate genny -in $GOFILE -out streams_map_outgoing_bidi.go gen "item=streamI Item=BidiStream streamTypeGeneric=protocol.StreamTypeBidi"
//go:generate genny -in $GOFILE -out streams_map_outgoing_uni.go gen "item=sendStreamI Item=UniStream streamTypeGeneric=protocol.StreamTypeUni"
type outgoingItemsMap struct {
	mutex sync.RWMutex
	cond  sync.Cond

	streams map[protocol.StreamNum]item

	nextStream  protocol.StreamNum // stream ID of the stream returned by OpenStream(Sync)
	maxStream   protocol.StreamNum // the maximum stream ID we're allowed to open
	blockedSent bool               // was a STREAMS_BLOCKED sent for the current maxStream

	newStream            func(protocol.StreamNum) item
	queueStreamIDBlocked func(*wire.StreamsBlockedFrame)

	closeErr error
}

func newOutgoingItemsMap(
	newStream func(protocol.StreamNum) item,
	queueControlFrame func(wire.Frame),
) *outgoingItemsMap {
	m := &outgoingItemsMap{
		streams:              make(map[protocol.StreamNum]item),
		maxStream:            protocol.InvalidStreamNum,
		nextStream:           1,
		newStream:            newStream,
		queueStreamIDBlocked: func(f *wire.StreamsBlockedFrame) { queueControlFrame(f) },
	}
	m.cond.L = &m.mutex
	return m
}

func (m *outgoingItemsMap) OpenStream() (item, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closeErr != nil {
		return nil, m.closeErr
	}

	str, err := m.openStreamImpl()
	if err != nil {
		return nil, streamOpenErr{err}
	}
	return str, nil
}

func (m *outgoingItemsMap) OpenStreamSync() (item, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for {
		if m.closeErr != nil {
			return nil, m.closeErr
		}
		str, err := m.openStreamImpl()
		if err == nil {
			return str, nil
		}
		if err != nil && err != errTooManyOpenStreams {
			return nil, streamOpenErr{err}
		}
		m.cond.Wait()
	}
}

func (m *outgoingItemsMap) openStreamImpl() (item, error) {
	if m.nextStream > m.maxStream {
		if !m.blockedSent {
			var streamNum protocol.StreamNum
			if m.maxStream != protocol.InvalidStreamNum {
				streamNum = m.maxStream
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
	m.nextStream++
	return s, nil
}

func (m *outgoingItemsMap) GetStream(num protocol.StreamNum) (item, error) {
	m.mutex.RLock()
	if num >= m.nextStream {
		m.mutex.RUnlock()
		return nil, streamError{
			message: "peer attempted to open stream %d",
			nums:    []protocol.StreamNum{num},
		}
	}
	s := m.streams[num]
	m.mutex.RUnlock()
	return s, nil
}

func (m *outgoingItemsMap) DeleteStream(num protocol.StreamNum) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.streams[num]; !ok {
		return streamError{
			message: "Tried to delete unknown stream %d",
			nums:    []protocol.StreamNum{num},
		}
	}
	delete(m.streams, num)
	return nil
}

func (m *outgoingItemsMap) SetMaxStream(num protocol.StreamNum) {
	m.mutex.Lock()
	if num > m.maxStream {
		m.maxStream = num
		m.blockedSent = false
		m.cond.Broadcast()
	}
	m.mutex.Unlock()
}

func (m *outgoingItemsMap) CloseWithError(err error) {
	m.mutex.Lock()
	m.closeErr = err
	for _, str := range m.streams {
		str.closeForShutdown(err)
	}
	m.cond.Broadcast()
	m.mutex.Unlock()
}
