package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

type streamFramer struct {
	// TODO: Simplify by extracting the streams map into a separate object
	streams      *map[protocol.StreamID]*stream
	streamsMutex *sync.RWMutex

	flowControlManager flowcontrol.FlowControlManager

	retransmissionQueue []*frames.StreamFrame
}

func newStreamFramer(streams *map[protocol.StreamID]*stream, streamsMutex *sync.RWMutex, flowControlManager flowcontrol.FlowControlManager) *streamFramer {
	return &streamFramer{
		streams:            streams,
		streamsMutex:       streamsMutex,
		flowControlManager: flowControlManager,
	}
}

func (f *streamFramer) HasData() bool {
	if len(f.retransmissionQueue) > 0 {
		return true
	}
	f.streamsMutex.RLock()
	defer f.streamsMutex.RUnlock()
	for _, s := range *f.streams {
		if s == nil {
			continue
		}
		if s.lenOfDataForWriting() > 0 || s.shouldSendFin() {
			return true
		}
	}
	return false
}

func (f *streamFramer) AddFrameForRetransmission(frame *frames.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
}

func (f *streamFramer) EstimatedDataLen() protocol.ByteCount {
	// We don't accurately calculate the len of FIN frames. Instead we estimate
	// they're 5 bytes long on average, i.e. 2 bytes stream ID and 2 bytes offset.
	const estimatedLenOfFinFrame = 1 + 2 + 2

	var l protocol.ByteCount
	const max = protocol.MaxFrameAndPublicHeaderSize

	// Count retransmissions
	for _, frame := range f.retransmissionQueue {
		l += frame.DataLen()
		if l > max {
			return max
		}
	}

	// Count data in streams
	f.streamsMutex.RLock()
	defer f.streamsMutex.RUnlock()
	for _, s := range *f.streams {
		if s != nil {
			l += s.lenOfDataForWriting()
			if s.shouldSendFin() {
				l += estimatedLenOfFinFrame
			}
			if l > max {
				return max
			}
		}
	}
	return l
}

// TODO: Maybe remove error return value?
func (f *streamFramer) PopStreamFrame(maxLen protocol.ByteCount) (*frames.StreamFrame, error) {
	if frame := f.maybePopFrameForRetransmission(maxLen); frame != nil {
		return frame, nil
	}
	return f.maybePopNormalFrame(maxLen), nil
}

func (f *streamFramer) maybePopFrameForRetransmission(maxLen protocol.ByteCount) *frames.StreamFrame {
	if len(f.retransmissionQueue) == 0 {
		return nil
	}

	frame := f.retransmissionQueue[0]
	frame.DataLenPresent = true

	frameHeaderLen, _ := frame.MinLength(0) // can never error
	if maxLen < frameHeaderLen {
		return nil
	}

	splitFrame := maybeSplitOffFrame(frame, maxLen-frameHeaderLen)
	if splitFrame != nil { // StreamFrame was split
		return splitFrame
	}

	f.retransmissionQueue = f.retransmissionQueue[1:]
	return frame
}

func (f *streamFramer) maybePopNormalFrame(maxLen protocol.ByteCount) *frames.StreamFrame {
	frame := &frames.StreamFrame{DataLenPresent: true}
	f.streamsMutex.RLock()
	defer f.streamsMutex.RUnlock()
	for _, s := range *f.streams {
		if s == nil {
			continue
		}

		frame.StreamID = s.streamID
		// not perfect, but thread-safe since writeOffset is only written when getting data
		frame.Offset = s.writeOffset
		frameHeaderLen, _ := frame.MinLength(0) // can never error
		if maxLen < frameHeaderLen {
			continue
		}

		data := s.getDataForWriting(maxLen - frameHeaderLen)
		if data == nil {
			if s.shouldSendFin() {
				frame.FinBit = true
				s.sentFin()
				return frame
			}
			continue
		}

		frame.Data = data
		return frame
	}
	return nil
}

// maybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(frame), nil is returned and nothing is modified.
func maybeSplitOffFrame(frame *frames.StreamFrame, n protocol.ByteCount) *frames.StreamFrame {
	if n >= frame.DataLen() {
		return nil
	}

	defer func() {
		frame.Data = frame.Data[n:]
		frame.Offset += n
	}()

	return &frames.StreamFrame{
		FinBit:         false,
		StreamID:       frame.StreamID,
		Offset:         frame.Offset,
		Data:           frame.Data[:n],
		DataLenPresent: frame.DataLenPresent,
	}
}
