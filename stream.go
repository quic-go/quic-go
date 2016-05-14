package quic

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type streamHandler interface {
	QueueStreamFrame(*frames.StreamFrame) error
}

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
type stream struct {
	streamID protocol.StreamID
	session  streamHandler

	readPosInFrame int
	writeOffset    protocol.ByteCount
	readOffset     protocol.ByteCount

	// Once set, err must not be changed!
	err   error
	mutex sync.Mutex

	eof int32 // really a bool

	frameQueue        streamFrameSorter
	newFrameOrErrCond sync.Cond

	flowControlWindow     protocol.ByteCount
	windowUpdateOrErrCond sync.Cond
}

// newStream creates a new Stream
func newStream(session streamHandler, connectionParameterManager *handshake.ConnectionParametersManager, StreamID protocol.StreamID) (*stream, error) {
	s := &stream{
		session:  session,
		streamID: StreamID,
	}

	s.newFrameOrErrCond.L = &s.mutex
	s.windowUpdateOrErrCond.L = &s.mutex

	s.flowControlWindow = connectionParameterManager.GetSendStreamFlowControlWindow()

	return s, nil
}

// Read implements io.Reader. It is not thread safe!
func (s *stream) Read(p []byte) (int, error) {
	if atomic.LoadInt32(&s.eof) != 0 {
		return 0, io.EOF
	}

	bytesRead := 0
	for bytesRead < len(p) {
		s.mutex.Lock()
		frame := s.frameQueue.Head()

		if frame == nil && bytesRead > 0 {
			defer s.mutex.Unlock()
			return bytesRead, s.err
		}

		for {
			// Stop waiting on errors
			if s.err != nil {
				break
			}
			if frame != nil {
				// Pop and continue if the frame doesn't have any new data
				if frame.Offset+protocol.ByteCount(len(frame.Data)) <= s.readOffset && !frame.FinBit {
					s.frameQueue.Pop()
					frame = s.frameQueue.Head()
					continue
				}
				// If the frame's offset is <= our current read pos, and we didn't
				// go into the previous if, we can read data from the frame.
				if frame.Offset <= s.readOffset {
					// Set our read position in the frame properly
					s.readPosInFrame = int(s.readOffset - frame.Offset)
					break
				}
			}
			s.newFrameOrErrCond.Wait()
			frame = s.frameQueue.Head()
		}
		s.mutex.Unlock()

		if frame == nil {
			atomic.StoreInt32(&s.eof, 1)
			// We have an err and no data, return the error
			return bytesRead, s.err
		}

		m := utils.Min(len(p)-bytesRead, len(frame.Data)-s.readPosInFrame)
		copy(p[bytesRead:], frame.Data[s.readPosInFrame:])
		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += protocol.ByteCount(m)
		if s.readPosInFrame >= len(frame.Data) {
			fin := frame.FinBit
			s.mutex.Lock()
			s.frameQueue.Pop()
			s.mutex.Unlock()
			if fin {
				atomic.StoreInt32(&s.eof, 1)
				return bytesRead, io.EOF
			}
		}
	}

	return bytesRead, nil
}

// ReadByte implements io.ByteReader
func (s *stream) ReadByte() (byte, error) {
	p := make([]byte, 1)
	_, err := io.ReadFull(s, p)
	return p[0], err
}

func (s *stream) UpdateFlowControlWindow(n protocol.ByteCount) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if n > s.flowControlWindow {
		s.flowControlWindow = n
		s.windowUpdateOrErrCond.Broadcast()
	}
}

func (s *stream) Write(p []byte) (int, error) {
	s.mutex.Lock()
	err := s.err
	s.mutex.Unlock()

	if err != nil {
		return 0, err
	}

	dataWritten := 0

	for dataWritten < len(p) {
		s.mutex.Lock()
		remainingBytesInWindow := int64(s.flowControlWindow) - int64(s.writeOffset)
		for remainingBytesInWindow == 0 && s.err == nil {
			s.windowUpdateOrErrCond.Wait()
			remainingBytesInWindow = int64(s.flowControlWindow) - int64(s.writeOffset)
		}
		s.mutex.Unlock()

		if remainingBytesInWindow == 0 {
			// We must have had an error
			return 0, s.err
		}

		dataLen := utils.Min(len(p), int(remainingBytesInWindow))
		data := make([]byte, dataLen)
		copy(data, p)
		err := s.session.QueueStreamFrame(&frames.StreamFrame{
			StreamID: s.streamID,
			Offset:   s.writeOffset,
			Data:     data,
		})
		if err != nil {
			return 0, err
		}

		dataWritten += dataLen
		s.writeOffset += protocol.ByteCount(dataLen)
	}

	return len(p), nil
}

// Close implements io.Closer
func (s *stream) Close() error {
	return s.session.QueueStreamFrame(&frames.StreamFrame{
		StreamID: s.streamID,
		Offset:   s.writeOffset,
		FinBit:   true,
	})
}

// AddStreamFrame adds a new stream frame
func (s *stream) AddStreamFrame(frame *frames.StreamFrame) error {
	s.mutex.Lock()
	s.frameQueue.Push(frame)
	s.mutex.Unlock()
	s.newFrameOrErrCond.Signal()
	return nil
}

// RegisterError is called by session to indicate that an error occurred and the
// stream should be closed.
func (s *stream) RegisterError(err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.err != nil { // s.err must not be changed!
		return
	}
	s.err = err
	s.windowUpdateOrErrCond.Signal()
	s.newFrameOrErrCond.Signal()
}

func (s *stream) finishedReading() bool {
	return atomic.LoadInt32(&s.eof) != 0
}
