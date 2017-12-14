package quic

import (
	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type streamFramer struct {
	streamsMap   *streamsMap
	cryptoStream cryptoStreamI
	version      protocol.VersionNumber

	connFlowController flowcontrol.ConnectionFlowController

	retransmissionQueue []*wire.StreamFrame
	blockedFrameQueue   []wire.Frame
}

func newStreamFramer(
	cryptoStream cryptoStreamI,
	streamsMap *streamsMap,
	cfc flowcontrol.ConnectionFlowController,
	v protocol.VersionNumber,
) *streamFramer {
	return &streamFramer{
		streamsMap:         streamsMap,
		cryptoStream:       cryptoStream,
		connFlowController: cfc,
		version:            v,
	}
}

func (f *streamFramer) AddFrameForRetransmission(frame *wire.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
}

func (f *streamFramer) PopStreamFrames(maxLen protocol.ByteCount) []*wire.StreamFrame {
	fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	return append(fs, f.maybePopNormalFrames(maxLen-currentLen)...)
}

func (f *streamFramer) PopBlockedFrame() wire.Frame {
	if len(f.blockedFrameQueue) == 0 {
		return nil
	}
	frame := f.blockedFrameQueue[0]
	f.blockedFrameQueue = f.blockedFrameQueue[1:]
	return frame
}

func (f *streamFramer) HasFramesForRetransmission() bool {
	return len(f.retransmissionQueue) > 0
}

func (f *streamFramer) HasCryptoStreamFrame() bool {
	return f.cryptoStream.HasDataForWriting()
}

// TODO(lclemente): This is somewhat duplicate with the normal path for generating frames.
func (f *streamFramer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *wire.StreamFrame {
	return f.cryptoStream.PopStreamFrame(maxLen)
}

func (f *streamFramer) maybePopFramesForRetransmission(maxTotalLen protocol.ByteCount) (res []*wire.StreamFrame, currentLen protocol.ByteCount) {
	for len(f.retransmissionQueue) > 0 {
		frame := f.retransmissionQueue[0]
		frame.DataLenPresent = true

		frameHeaderLen := frame.MinLength(f.version) // can never error
		maxLen := maxTotalLen - currentLen
		if frameHeaderLen+frame.DataLen() > maxLen && maxLen < protocol.MinStreamFrameSize {
			break
		}

		splitFrame := maybeSplitOffFrame(frame, maxLen-frameHeaderLen)
		if splitFrame != nil { // StreamFrame was split
			res = append(res, splitFrame)
			currentLen += frameHeaderLen + splitFrame.DataLen()
			break
		}

		f.retransmissionQueue = f.retransmissionQueue[1:]
		res = append(res, frame)
		currentLen += frameHeaderLen + frame.DataLen()
	}
	return
}

func (f *streamFramer) maybePopNormalFrames(maxTotalLen protocol.ByteCount) (res []*wire.StreamFrame) {
	var currentLen protocol.ByteCount

	fn := func(s streamI) (bool, error) {
		if s == nil {
			return true, nil
		}

		maxLen := maxTotalLen - currentLen
		if maxLen < protocol.MinStreamFrameSize { // don't try to add new STREAM frames, if only little space is left in the packet
			return false, nil
		}
		frame := s.PopStreamFrame(maxLen)
		if frame == nil {
			return true, nil
		}

		// Finally, check if we are now FC blocked and should queue a BLOCKED frame
		if !frame.FinBit {
			if blocked, offset := s.IsFlowControlBlocked(); blocked {
				f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.StreamBlockedFrame{
					StreamID: s.StreamID(),
					Offset:   offset,
				})
			}
		}
		if blocked, offset := f.connFlowController.IsBlocked(); blocked {
			f.blockedFrameQueue = append(f.blockedFrameQueue, &wire.BlockedFrame{Offset: offset})
		}

		res = append(res, frame)
		currentLen += frame.MinLength(f.version) + frame.DataLen()

		if currentLen == maxTotalLen {
			return false, nil
		}

		frame = &wire.StreamFrame{DataLenPresent: true}
		return true, nil
	}

	f.streamsMap.RoundRobinIterate(fn)
	return
}

// maybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(frame), nil is returned and nothing is modified.
func maybeSplitOffFrame(frame *wire.StreamFrame, n protocol.ByteCount) *wire.StreamFrame {
	if n >= frame.DataLen() {
		return nil
	}

	defer func() {
		frame.Data = frame.Data[n:]
		frame.Offset += n
	}()

	return &wire.StreamFrame{
		FinBit:         false,
		StreamID:       frame.StreamID,
		Offset:         frame.Offset,
		Data:           frame.Data[:n],
		DataLenPresent: frame.DataLenPresent,
	}
}
