package quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
type Stream struct {
	Session        *Session
	StreamID       protocol.StreamID
	StreamFrames   chan *frames.StreamFrame
	CurrentFrame   *frames.StreamFrame
	ReadPosInFrame int
	WriteOffset    uint64
	ReadOffset     uint64
	frameQueue     []*frames.StreamFrame // TODO: replace with heap
}

// NewStream creates a new Stream
func NewStream(session *Session, StreamID protocol.StreamID) *Stream {
	return &Stream{
		Session:      session,
		StreamID:     StreamID,
		StreamFrames: make(chan *frames.StreamFrame, 8), // ToDo: add config option for this number
	}
}

// Read reads data
func (s *Stream) Read(p []byte) (int, error) {
	bytesRead := 0
	for bytesRead < len(p) {
		if s.CurrentFrame == nil {
			s.CurrentFrame = s.getNextFrameInOrder(bytesRead == 0)
			if s.CurrentFrame == nil {
				return bytesRead, nil
			}
			s.ReadPosInFrame = 0
		}
		m := utils.Min(len(p)-bytesRead, len(s.CurrentFrame.Data)-s.ReadPosInFrame)
		copy(p[bytesRead:], s.CurrentFrame.Data[s.ReadPosInFrame:])
		s.ReadPosInFrame += m
		bytesRead += m
		s.ReadOffset += uint64(m)
		if s.ReadPosInFrame >= len(s.CurrentFrame.Data) {
			s.CurrentFrame = nil
		}
	}

	return bytesRead, nil
}

func (s *Stream) getNextFrameInOrder(wait bool) *frames.StreamFrame {
	// First, check the queue
	for i, f := range s.frameQueue {
		if f.Offset == s.ReadOffset {
			// Move last element into position i
			s.frameQueue[i] = s.frameQueue[len(s.frameQueue)-1]
			s.frameQueue = s.frameQueue[:len(s.frameQueue)-1]
			return f
		}
	}

	// TODO: Handle error and break while(true) loop
	for {
		var nextFrameFromChannel *frames.StreamFrame
		if wait {
			nextFrameFromChannel = <-s.StreamFrames
		} else {
			select {
			case nextFrameFromChannel = <-s.StreamFrames:
			default:
				return nil
			}
		}

		if nextFrameFromChannel.Offset == s.ReadOffset {
			return nextFrameFromChannel
		}

		// Discard if we already know it
		if nextFrameFromChannel.Offset < s.ReadOffset {
			continue
		}

		// Append to queue
		s.frameQueue = append(s.frameQueue, nextFrameFromChannel)
	}
}

// ReadByte implements io.ByteReader
func (s *Stream) ReadByte() (byte, error) {
	// TODO: Optimize
	p := make([]byte, 1)
	n, err := s.Read(p)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		panic("Stream: should have returned error")
	}
	return p[0], nil
}

func (s *Stream) Write(p []byte) (int, error) {
	data := make([]byte, len(p))
	copy(data, p)
	err := s.Session.SendFrame(&frames.StreamFrame{
		StreamID: s.StreamID,
		Offset:   s.WriteOffset,
		Data:     data,
	})
	if err != nil {
		return 0, err
	}
	s.WriteOffset += uint64(len(p))
	return len(p), nil
}

// Close imlpements io.Closer
func (s *Stream) Close() error {
	fmt.Printf("Closing stream %d\n", s.StreamID)
	return s.Session.SendFrame(&frames.StreamFrame{
		StreamID: s.StreamID,
		Offset:   s.WriteOffset,
		FinBit:   true,
	})
}

// AddStreamFrame adds a new stream frame
func (s *Stream) AddStreamFrame(frame *frames.StreamFrame) error {
	s.StreamFrames <- frame
	return nil
}
