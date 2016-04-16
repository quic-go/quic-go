package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/utils"
)

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
type Stream struct {
	StreamFrames   chan *frames.StreamFrame
	CurrentFrame   *frames.StreamFrame
	ReadPosInFrame int
}

// NewStream creates a new Stream
func NewStream() *Stream {
	return &Stream{
		StreamFrames: make(chan *frames.StreamFrame, 8), // ToDo: add config option for this number
	}
}

// Read reads data
func (s *Stream) Read(p []byte) (int, error) {
	bytesRead := 0
	for bytesRead < len(p) {
		if s.CurrentFrame == nil {
			select {
			case s.CurrentFrame = <-s.StreamFrames:
			default:
				if bytesRead == 0 {
					s.CurrentFrame = <-s.StreamFrames
				} else {
					return bytesRead, nil
				}
			}
			s.ReadPosInFrame = 0
		}
		m := utils.Min(len(p)-bytesRead, len(s.CurrentFrame.Data)-s.ReadPosInFrame)
		copy(p[bytesRead:], s.CurrentFrame.Data[s.ReadPosInFrame:])
		s.ReadPosInFrame += m
		bytesRead += m
		if s.ReadPosInFrame >= len(s.CurrentFrame.Data) {
			s.CurrentFrame = nil
		}
	}

	return bytesRead, nil
}

// AddStreamFrame adds a new stream frame
func (s *Stream) AddStreamFrame(frame *frames.StreamFrame) error {
	s.StreamFrames <- frame
	return nil
}
