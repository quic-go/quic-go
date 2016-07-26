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
	blockedFrameQueue   []*frames.BlockedFrame
}

func newStreamFramer(streams *map[protocol.StreamID]*stream, streamsMutex *sync.RWMutex, flowControlManager flowcontrol.FlowControlManager) *streamFramer {
	return &streamFramer{
		streams:            streams,
		streamsMutex:       streamsMutex,
		flowControlManager: flowControlManager,
	}
}

func (f *streamFramer) AddFrameForRetransmission(frame *frames.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
}

func (f *streamFramer) PopStreamFrames(maxLen protocol.ByteCount) []*frames.StreamFrame {
	fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	return append(fs, f.maybePopNormalFrames(maxLen-currentLen)...)
}

func (f *streamFramer) PopBlockedFrame() *frames.BlockedFrame {
	if len(f.blockedFrameQueue) == 0 {
		return nil
	}
	frame := f.blockedFrameQueue[0]
	f.blockedFrameQueue = f.blockedFrameQueue[1:]
	return frame
}

func (f *streamFramer) maybePopFramesForRetransmission(maxLen protocol.ByteCount) (res []*frames.StreamFrame, currentLen protocol.ByteCount) {
	for len(f.retransmissionQueue) > 0 {
		frame := f.retransmissionQueue[0]
		frame.DataLenPresent = true

		frameHeaderLen, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderLen > maxLen {
			break
		}

		currentLen += frameHeaderLen

		splitFrame := maybeSplitOffFrame(frame, maxLen-currentLen)
		if splitFrame != nil { // StreamFrame was split
			res = append(res, splitFrame)
			currentLen += splitFrame.DataLen()
			break
		}

		f.retransmissionQueue = f.retransmissionQueue[1:]
		res = append(res, frame)
		currentLen += frame.DataLen()
	}
	return
}

func (f *streamFramer) maybePopNormalFrames(maxBytes protocol.ByteCount) (res []*frames.StreamFrame) {
	f.streamsMutex.RLock()
	defer f.streamsMutex.RUnlock()

	frame := &frames.StreamFrame{DataLenPresent: true}
	var currentLen protocol.ByteCount

	for _, s := range *f.streams {
		if s == nil {
			continue
		}

		frame.StreamID = s.streamID
		// not perfect, but thread-safe since writeOffset is only written when getting data
		frame.Offset = s.writeOffset
		frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderBytes > maxBytes {
			return // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
		}
		maxLen := maxBytes - currentLen - frameHeaderBytes

		if s.lenOfDataForWriting() != 0 {
			fcAllowance, _ := f.getFCAllowanceForStream(s) // can never error
			maxLen = utils.MinByteCount(maxLen, fcAllowance)
		}

		if maxLen == 0 {
			continue
		}

		data := s.getDataForWriting(maxLen)
		if data == nil {
			if s.shouldSendFin() {
				frame.FinBit = true
				s.sentFin()
				res = append(res, frame)
				currentLen += frameHeaderBytes + frame.DataLen()
				frame = &frames.StreamFrame{DataLenPresent: true}
			}
			continue
		}

		frame.Data = data
		f.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data)))

		// Finally, check if we are now FC blocked and should queue a BLOCKED frame
		individualFcOffset, _ := f.flowControlManager.SendWindowSize(s.streamID) // can never error
		if s.writeOffset == individualFcOffset {
			// We are now stream-level FC blocked
			f.blockedFrameQueue = append(f.blockedFrameQueue, &frames.BlockedFrame{StreamID: s.StreamID()})
		}
		if f.flowControlManager.RemainingConnectionWindowSize() == 0 {
			// We are now connection-level FC blocked
			f.blockedFrameQueue = append(f.blockedFrameQueue, &frames.BlockedFrame{StreamID: 0})
		}

		res = append(res, frame)
		currentLen += frameHeaderBytes + frame.DataLen()
		frame = &frames.StreamFrame{DataLenPresent: true}
	}
	return
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
