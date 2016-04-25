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
type stream struct {
	session        streamHandler
	streamID       protocol.StreamID
	streamFrames   chan *frames.StreamFrame
	currentFrame   *frames.StreamFrame
	readPosInFrame int
	writeOffset    uint64
	readOffset     uint64
	frameQueue     []*frames.StreamFrame // TODO: replace with heap
	currentErr     error
}

// newStream creates a new Stream
func newStream(session streamHandler, StreamID protocol.StreamID) *stream {
	return &stream{
		session:      session,
		streamID:     StreamID,
		streamFrames: make(chan *frames.StreamFrame, 8), // ToDo: add config option for this number
	}
}

// Read reads data
func (s *stream) Read(p []byte) (int, error) {
	bytesRead := 0
	for bytesRead < len(p) {
		if s.currentFrame == nil {
			var err error
			s.currentFrame, err = s.getNextFrameInOrder(bytesRead == 0)
			if err != nil {
				return bytesRead, err
			}
			if s.currentFrame == nil {
				return bytesRead, nil
			}
			s.readPosInFrame = 0
		}
		m := utils.Min(len(p)-bytesRead, len(s.currentFrame.Data)-s.readPosInFrame)
		copy(p[bytesRead:], s.currentFrame.Data[s.readPosInFrame:])
		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += uint64(m)
		if s.readPosInFrame >= len(s.currentFrame.Data) {
			if s.currentFrame.FinBit {
				s.currentErr = io.EOF
				close(s.streamFrames)
				s.currentFrame = nil
				s.session.closeStream(s.streamID)
				return bytesRead, io.EOF
			}
			s.currentFrame = nil
		}
	}

	return bytesRead, nil
}

func (s *stream) getNextFrameInOrder(wait bool) (*frames.StreamFrame, error) {
	// First, check the queue
	for i, f := range s.frameQueue {
		if f.Offset == s.readOffset {
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

		if nextFrameFromChannel.Offset == s.readOffset {
			return nextFrameFromChannel, nil
		}

		// Discard if we already know it
		if nextFrameFromChannel.Offset < s.readOffset {
			continue
		}

		// Append to queue
		s.frameQueue = append(s.frameQueue, nextFrameFromChannel)
	}
}

func (s *stream) nextFrameInChan(blocking bool) (f *frames.StreamFrame, err error) {
	var ok bool
	if blocking {
		select {
		case f, ok = <-s.streamFrames:
		}
	} else {
		select {
		case f, ok = <-s.streamFrames:
		default:
		}
	}
	if !ok {
		return nil, s.currentErr
	}
	return
}

// ReadByte implements io.ByteReader
func (s *stream) ReadByte() (byte, error) {
	// TODO: Optimize
	p := make([]byte, 1)
	_, err := io.ReadFull(s, p)
	return p[0], err
}

func (s *stream) Write(p []byte) (int, error) {
	data := make([]byte, len(p))
	copy(data, p)
	err := s.session.QueueFrame(&frames.StreamFrame{
		StreamID: s.streamID,
		Offset:   s.writeOffset,
		Data:     data,
	})
	if err != nil {
		return 0, err
	}
	s.writeOffset += uint64(len(p))
	return len(p), nil
}

// Close implements io.Closer
func (s *stream) Close() error {
	fmt.Printf("Closing stream %d\n", s.streamID)
	return s.session.QueueFrame(&frames.StreamFrame{
		StreamID: s.streamID,
		Offset:   s.writeOffset,
		FinBit:   true,
	})
}

// AddStreamFrame adds a new stream frame
func (s *stream) AddStreamFrame(frame *frames.StreamFrame) error {
	s.streamFrames <- frame
	return nil
}

// RegisterError is called by session to indicate that an error occured and the
// stream should be closed.
func (s *stream) RegisterError(err error) {
	s.currentErr = err
	s.session.closeStream(s.streamID)
	close(s.streamFrames)
}
