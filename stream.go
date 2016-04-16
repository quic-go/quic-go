package quic

import (
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/frames"
)

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
type Stream struct {
	StreamFrames   []*frames.StreamFrame
	DataLen        uint64
	ReadPosFrameNo int
	ReadPosInFrame int
}

// NewStream creates a new Stream
func NewStream() *Stream {
	return &Stream{}
}

func (s *Stream) readByte() (byte, error) {
	if s.ReadPosInFrame == len(s.StreamFrames[s.ReadPosFrameNo].Data) {
		s.ReadPosFrameNo++
		if s.ReadPosFrameNo == len(s.StreamFrames) {
			return 0, io.EOF
		}
		s.ReadPosInFrame = 0
	}
	b := s.StreamFrames[s.ReadPosFrameNo].Data[s.ReadPosInFrame]
	s.ReadPosInFrame++
	return b, nil
}

// Read reads data
func (s *Stream) Read(p []byte) (int, error) {
	var err error
	n := 0
	if c := cap(p); c > 0 {
		for n < c {
			p[n], err = s.readByte()
			n++
			if err != nil {
				break
			}
		}
	}
	return n, nil
}

// AddStreamFrame adds a new stream frame
func (s *Stream) AddStreamFrame(frame *frames.StreamFrame) error {
	if frame.Offset != s.DataLen {
		return errors.New("Stream: Wrong offset")
	}
	s.StreamFrames = append(s.StreamFrames, frame)
	s.DataLen += uint64(len(frame.Data))
	return nil
}
