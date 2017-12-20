package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type streamFramer struct {
	streamsMap   *streamsMap
	cryptoStream cryptoStreamI
	version      protocol.VersionNumber

	retransmissionQueue []*wire.StreamFrame
}

func newStreamFramer(
	cryptoStream cryptoStreamI,
	streamsMap *streamsMap,
	v protocol.VersionNumber,
) *streamFramer {
	return &streamFramer{
		streamsMap:   streamsMap,
		cryptoStream: cryptoStream,
		version:      v,
	}
}

func (f *streamFramer) AddFrameForRetransmission(frame *wire.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
}

func (f *streamFramer) PopStreamFrames(maxLen protocol.ByteCount) []*wire.StreamFrame {
	fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	return append(fs, f.maybePopNormalFrames(maxLen-currentLen)...)
}

func (f *streamFramer) HasFramesForRetransmission() bool {
	return len(f.retransmissionQueue) > 0
}

func (f *streamFramer) HasCryptoStreamFrame() bool {
	return f.cryptoStream.hasDataForWriting()
}

// TODO(lclemente): This is somewhat duplicate with the normal path for generating frames.
func (f *streamFramer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *wire.StreamFrame {
	return f.cryptoStream.popStreamFrame(maxLen)
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
		frame := s.popStreamFrame(maxLen)
		if frame == nil {
			return true, nil
		}
		res = append(res, frame)
		currentLen += frame.MinLength(f.version) + frame.DataLen()
		if currentLen == maxTotalLen {
			return false, nil
		}
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
