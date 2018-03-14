package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// Implementations do not have to be thread safe, the caller is expected to handle locking.
type StreamScheduler interface {
	// Invoked when a stream is has data available.
	AddActiveStream(id protocol.StreamID)
	// Invoked when a stream is has no more data available.
	// This method is likely called immediately after a call to NextActiveStream.
	RemoveActiveStream(id protocol.StreamID)
	// Returns the next stream to send data from.
	NextActiveStream() protocol.StreamID
}

type roundRobbinStreamScheduler struct {
	streamQueue []protocol.StreamID
}

func (ss *roundRobbinStreamScheduler) AddActiveStream(id protocol.StreamID) {
	ss.streamQueue = append(ss.streamQueue, id)
}

func (ss *roundRobbinStreamScheduler) RemoveActiveStream(id protocol.StreamID) {
	// Check the end of the array first since this is likely called immediately after NextActiveStream
	if ss.streamQueue[len(ss.streamQueue)-1] == id {
		ss.streamQueue = ss.streamQueue[:len(ss.streamQueue)-1]
	}
	for i := 0; i < len(ss.streamQueue)-1; i++ {
		if ss.streamQueue[i] == id {
			ss.streamQueue = append(ss.streamQueue[:i], ss.streamQueue[i+1:]...)
			break
		}
	}
}

func (ss *roundRobbinStreamScheduler) NextActiveStream() protocol.StreamID {
	id := ss.streamQueue[0]
	ss.streamQueue = ss.streamQueue[1:]
	ss.streamQueue = append(ss.streamQueue, id)
	return id
}

type streamFramer struct {
	streamGetter streamGetter
	cryptoStream cryptoStreamI
	version      protocol.VersionNumber

	streamQueueMutex    sync.Mutex
	activeStreams       map[protocol.StreamID]struct{}
	streamScheduler     StreamScheduler
	hasCryptoStreamData bool
}

func newStreamFramer(
	cryptoStream cryptoStreamI,
	streamGetter streamGetter,
	v protocol.VersionNumber,
) *streamFramer {
	return &streamFramer{
		streamGetter:    streamGetter,
		cryptoStream:    cryptoStream,
		activeStreams:   make(map[protocol.StreamID]struct{}),
		streamScheduler: &roundRobbinStreamScheduler{},
		version:         v,
	}
}

func (f *streamFramer) AddActiveStream(id protocol.StreamID) {
	if id == f.version.CryptoStreamID() { // the crypto stream is handled separately
		f.streamQueueMutex.Lock()
		f.hasCryptoStreamData = true
		f.streamQueueMutex.Unlock()
		return
	}
	f.streamQueueMutex.Lock()
	if _, ok := f.activeStreams[id]; !ok {
		f.streamScheduler.AddActiveStream(id)
		f.activeStreams[id] = struct{}{}
	}
	f.streamQueueMutex.Unlock()
}

func (f *streamFramer) HasCryptoStreamData() bool {
	f.streamQueueMutex.Lock()
	hasCryptoStreamData := f.hasCryptoStreamData
	f.streamQueueMutex.Unlock()
	return hasCryptoStreamData
}

func (f *streamFramer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *wire.StreamFrame {
	f.streamQueueMutex.Lock()
	frame, hasMoreData := f.cryptoStream.popStreamFrame(maxLen)
	f.hasCryptoStreamData = hasMoreData
	f.streamQueueMutex.Unlock()
	return frame
}

func (f *streamFramer) PopStreamFrames(maxTotalLen protocol.ByteCount) []*wire.StreamFrame {
	var currentLen protocol.ByteCount
	var frames []*wire.StreamFrame
	f.streamQueueMutex.Lock()
	// pop STREAM frames, until less than MinStreamFrameSize bytes are left in the packet or there are no more active streams
	numActiveStreams := len(f.activeStreams)
	for i := 0; i < numActiveStreams; i++ {
		if maxTotalLen-currentLen < protocol.MinStreamFrameSize {
			break
		}
		id := f.streamScheduler.NextActiveStream()
		// This should never return an error. Better check it anyway.
		// The stream will only be in the streamQueue, if it enqueued itself there.
		str, err := f.streamGetter.GetOrOpenSendStream(id)
		// The stream can be nil if it completed after it said it had data.
		if str == nil || err != nil {
			delete(f.activeStreams, id)
			f.streamScheduler.RemoveActiveStream(id)
			continue
		}
		frame, hasMoreData := str.popStreamFrame(maxTotalLen - currentLen)
		if !hasMoreData { // no more data to send. Stream is not active any more
			delete(f.activeStreams, id)
			f.streamScheduler.RemoveActiveStream(id)
		}
		if frame == nil { // can happen if the receiveStream was canceled after it said it had data
			continue
		}
		frames = append(frames, frame)
		currentLen += frame.Length(f.version)
	}
	f.streamQueueMutex.Unlock()
	return frames
}
