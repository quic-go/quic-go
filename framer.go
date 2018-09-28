package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type framer struct {
	streamGetter streamGetter
	cryptoStream cryptoStream
	version      protocol.VersionNumber

	streamQueueMutex    sync.Mutex
	activeStreams       map[protocol.StreamID]struct{}
	streamQueue         []protocol.StreamID
	hasCryptoStreamData bool

	controlFrameMutex sync.Mutex
	controlFrames     []wire.Frame
}

func newFramer(
	cryptoStream cryptoStream,
	streamGetter streamGetter,
	v protocol.VersionNumber,
) *framer {
	return &framer{
		streamGetter:  streamGetter,
		cryptoStream:  cryptoStream,
		activeStreams: make(map[protocol.StreamID]struct{}),
		version:       v,
	}
}

func (f *framer) QueueControlFrame(frame wire.Frame) {
	f.controlFrameMutex.Lock()
	f.controlFrames = append(f.controlFrames, frame)
	f.controlFrameMutex.Unlock()
}

func (f *framer) AppendControlFrames(frames []wire.Frame, maxLen protocol.ByteCount) ([]wire.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	f.controlFrameMutex.Lock()
	for len(f.controlFrames) > 0 {
		frame := f.controlFrames[len(f.controlFrames)-1]
		frameLen := frame.Length(f.version)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, frame)
		length += frameLen
		f.controlFrames = f.controlFrames[:len(f.controlFrames)-1]
	}
	f.controlFrameMutex.Unlock()
	return frames, length
}

func (f *framer) AddActiveStream(id protocol.StreamID) {
	if id == f.version.CryptoStreamID() { // the crypto stream is handled separately
		f.streamQueueMutex.Lock()
		f.hasCryptoStreamData = true
		f.streamQueueMutex.Unlock()
		return
	}
	f.streamQueueMutex.Lock()
	if _, ok := f.activeStreams[id]; !ok {
		f.streamQueue = append(f.streamQueue, id)
		f.activeStreams[id] = struct{}{}
	}
	f.streamQueueMutex.Unlock()
}

func (f *framer) HasCryptoStreamData() bool {
	f.streamQueueMutex.Lock()
	hasCryptoStreamData := f.hasCryptoStreamData
	f.streamQueueMutex.Unlock()
	return hasCryptoStreamData
}

func (f *framer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *wire.StreamFrame {
	f.streamQueueMutex.Lock()
	frame, hasMoreData := f.cryptoStream.popStreamFrame(maxLen)
	f.hasCryptoStreamData = hasMoreData
	f.streamQueueMutex.Unlock()
	return frame
}

func (f *framer) AppendStreamFrames(frames []wire.Frame, maxLen protocol.ByteCount) []wire.Frame {
	var length protocol.ByteCount
	f.streamQueueMutex.Lock()
	// pop STREAM frames, until less than MinStreamFrameSize bytes are left in the packet
	numActiveStreams := len(f.streamQueue)
	for i := 0; i < numActiveStreams; i++ {
		if maxLen-length < protocol.MinStreamFrameSize {
			break
		}
		id := f.streamQueue[0]
		f.streamQueue = f.streamQueue[1:]
		// This should never return an error. Better check it anyway.
		// The stream will only be in the streamQueue, if it enqueued itself there.
		str, err := f.streamGetter.GetOrOpenSendStream(id)
		// The stream can be nil if it completed after it said it had data.
		if str == nil || err != nil {
			delete(f.activeStreams, id)
			continue
		}
		frame, hasMoreData := str.popStreamFrame(maxLen - length)
		if hasMoreData { // put the stream back in the queue (at the end)
			f.streamQueue = append(f.streamQueue, id)
		} else { // no more data to send. Stream is not active any more
			delete(f.activeStreams, id)
		}
		if frame == nil { // can happen if the receiveStream was canceled after it said it had data
			continue
		}
		frames = append(frames, frame)
		length += frame.Length(f.version)
	}
	f.streamQueueMutex.Unlock()
	return frames
}
