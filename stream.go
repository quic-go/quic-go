package quic

import (
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type streamHandler interface {
	QueueFrame(frames.Frame) error
	closeStream(protocol.StreamID)
}

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
type Stream struct {
	Session        streamHandler
	StreamID       protocol.StreamID
	StreamFrames   chan *frames.StreamFrame
	CurrentFrame   *frames.StreamFrame
	ReadPosInFrame int
	WriteOffset    uint64
	ReadOffset     uint64
	frameQueue     []*frames.StreamFrame // TODO: replace with heap
	currentErr     error
}

// NewStream creates a new Stream
func NewStream(session streamHandler, StreamID protocol.StreamID) *Stream {
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
			var err error
			s.CurrentFrame, err = s.getNextFrameInOrder(bytesRead == 0)
			if err != nil {
				return bytesRead, err
			}
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
			if s.CurrentFrame.FinBit {
				s.currentErr = io.EOF
				close(s.StreamFrames)
				s.CurrentFrame = nil
				s.Session.closeStream(s.StreamID)
				return bytesRead, io.EOF
			}
			s.CurrentFrame = nil
		}
	}

	return bytesRead, nil
}

func (s *Stream) getNextFrameInOrder(wait bool) (*frames.StreamFrame, error) {
	// First, check the queue
	for i, f := range s.frameQueue {
		if f.Offset == s.ReadOffset {
			// Move last element into position i
			s.frameQueue[i] = s.frameQueue[len(s.frameQueue)-1]
			s.frameQueue = s.frameQueue[:len(s.frameQueue)-1]
			return f, nil
		}
	}

	for {
		nextFrameFromChannel, err := s.nextFrameInChan(wait)
		if err != nil {
			return nil, err
		}
		if nextFrameFromChannel == nil {
			return nil, nil
		}

		if nextFrameFromChannel.Offset == s.ReadOffset {
			return nextFrameFromChannel, nil
		}

		// Discard if we already know it
		if nextFrameFromChannel.Offset < s.ReadOffset {
			continue
		}

		// Append to queue
		s.frameQueue = append(s.frameQueue, nextFrameFromChannel)
	}
}

func (s *Stream) nextFrameInChan(blocking bool) (f *frames.StreamFrame, err error) {
	var ok bool
	if blocking {
		select {
		case f, ok = <-s.StreamFrames:
		}
	} else {
		select {
		case f, ok = <-s.StreamFrames:
		default:
		}
	}
	if !ok {
		return nil, s.currentErr
	}
	return
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

// TODO: Test
func (s *Stream) Write(p []byte) (int, error) {
	data := make([]byte, len(p))
	copy(data, p)
	err := s.Session.QueueFrame(&frames.StreamFrame{
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
	return s.Session.QueueFrame(&frames.StreamFrame{
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

// RegisterError is called by session to indicate that an error occured and the
// stream should be closed.
func (s *Stream) RegisterError(err error) {
	s.currentErr = err
	s.Session.closeStream(s.StreamID)
	close(s.StreamFrames)
}
