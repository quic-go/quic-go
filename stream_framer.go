package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
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
		// An error should never happen, and needlessly complicates the return values
		fcLimit, _ := f.getFCAllowanceForStream(s)
		if fcLimit == 0 {
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
			// An error should never happen, and needlessly complicates the return values
			fcLimit, _ := f.getFCAllowanceForStream(s)
			l += utils.MinByteCount(s.lenOfDataForWriting(), fcLimit)
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

func (f *streamFramer) PopStreamFrame(maxLen protocol.ByteCount) (*frames.StreamFrame, error) {
	if frame := f.maybePopFrameForRetransmission(maxLen); frame != nil {
		return frame, nil
	}
	return f.maybePopNormalFrame(maxLen)
}

func (f *streamFramer) maybePopFrameForRetransmission(maxLen protocol.ByteCount) *frames.StreamFrame {
	if len(f.retransmissionQueue) == 0 {
		return nil
	}

	frame := f.retransmissionQueue[0]
	frame.DataLenPresent = true

	frameHeaderLen, _ := frame.MinLength(protocol.VersionWhatever) // can never error
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

func (f *streamFramer) maybePopNormalFrame(maxBytes protocol.ByteCount) (*frames.StreamFrame, error) {
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
		frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if maxBytes < frameHeaderBytes {
			continue
		}
		maxLen := maxBytes - frameHeaderBytes

		fcAllowance, err := f.getFCAllowanceForStream(s)
		if err != nil {
			return nil, err
		}
		maxLen = utils.MinByteCount(maxLen, fcAllowance)

		if maxLen == 0 {
			continue
		}

		data := s.getDataForWriting(maxLen)
		if data == nil {
			if s.shouldSendFin() {
				frame.FinBit = true
				s.sentFin()
				return frame, nil
			}
			continue
		}

		frame.Data = data
		if err := f.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data))); err != nil {
			return nil, err
		}
		return frame, nil
	}
	return nil, nil
}

func (f *streamFramer) getFCAllowanceForStream(s *stream) (protocol.ByteCount, error) {
	flowControlWindow, err := f.flowControlManager.SendWindowSize(s.streamID)
	if err != nil {
		return 0, err
	}
	flowControlWindow -= s.writeOffset
	if flowControlWindow == 0 {
		return 0, nil
	}

	contributes, err := f.flowControlManager.StreamContributesToConnectionFlowControl(s.StreamID())
	if err != nil {
		return 0, err
	}
	connectionWindow := protocol.ByteCount(protocol.MaxByteCount)
	if contributes {
		connectionWindow = f.flowControlManager.RemainingConnectionWindowSize()
	}
	return utils.MinByteCount(flowControlWindow, connectionWindow), nil
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
