package quic

import (
	"fmt"
	"io"
	"sync"

	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
//
// Read() and Write() may be called concurrently, but multiple calls to Read() or Write() individually must be synchronized manually.
type stream struct {
	mutex sync.Mutex

	streamID protocol.StreamID
	onData   func()

	readPosInFrame int
	writeOffset    protocol.ByteCount
	readOffset     protocol.ByteCount

	// Once set, the errors must not be changed!
	readErr  error
	writeErr error

	cancelled       utils.AtomicBool
	finishedReading utils.AtomicBool
	finishedWriting utils.AtomicBool

	frameQueue        *streamFrameSorter
	newFrameOrErrCond sync.Cond

	dataForWriting       []byte
	finSent              bool
	doneWritingOrErrCond sync.Cond

	flowControlManager flowcontrol.FlowControlManager
}

// newStream creates a new Stream
func newStream(StreamID protocol.StreamID, onData func(), flowControlManager flowcontrol.FlowControlManager) (*stream, error) {
	s := &stream{
		onData:             onData,
		streamID:           StreamID,
		flowControlManager: flowControlManager,
		frameQueue:         newStreamFrameSorter(),
	}

	s.newFrameOrErrCond.L = &s.mutex
	s.doneWritingOrErrCond.L = &s.mutex

	return s, nil
}

// Read implements io.Reader. It is not thread safe!
func (s *stream) Read(p []byte) (int, error) {
	if s.cancelled.Get() {
		return 0, s.readErr
	}
	if s.finishedReading.Get() {
		return 0, io.EOF
	}

	bytesRead := 0
	for bytesRead < len(p) {
		s.mutex.Lock()
		frame := s.frameQueue.Head()

		if frame == nil && bytesRead > 0 {
			s.mutex.Unlock()
			return bytesRead, s.readErr
		}

		var err error
		for {
			// Stop waiting on errors
			if s.readErr != nil {
				err = s.readErr
				break
			}
			if frame != nil {
				s.readPosInFrame = int(s.readOffset - frame.Offset)
				break
			}
			s.newFrameOrErrCond.Wait()
			frame = s.frameQueue.Head()
		}
		s.mutex.Unlock()
		// Here, either frame != nil xor err != nil

		// fmt.Printf("err: %#v, frame: %#v\n", err, frame)

		if frame == nil {
			s.finishedReading.Set(true)
			// We have an err and no data, return the error
			return bytesRead, err
		}

		m := utils.Min(len(p)-bytesRead, int(frame.DataLen())-s.readPosInFrame)

		if bytesRead > len(p) {
			return bytesRead, fmt.Errorf("BUG: bytesRead (%d) > len(p) (%d) in stream.Read", bytesRead, len(p))
		}
		if s.readPosInFrame > int(frame.DataLen()) {
			return bytesRead, fmt.Errorf("BUG: readPosInFrame (%d) > frame.DataLen (%d) in stream.Read", s.readPosInFrame, frame.DataLen())
		}
		copy(p[bytesRead:], frame.Data[s.readPosInFrame:])

		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += protocol.ByteCount(m)

		s.flowControlManager.AddBytesRead(s.streamID, protocol.ByteCount(m))
		s.onData() // so that a possible WINDOW_UPDATE is sent

		if s.readPosInFrame >= int(frame.DataLen()) {
			fin := frame.FinBit
			s.mutex.Lock()
			s.frameQueue.Pop()
			s.mutex.Unlock()
			if fin {
				s.finishedReading.Set(true)
				return bytesRead, io.EOF
			}
		}
	}

	return bytesRead, nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.writeErr != nil {
		return 0, s.writeErr
	}

	if len(p) == 0 {
		return 0, nil
	}

	s.dataForWriting = make([]byte, len(p))
	copy(s.dataForWriting, p)

	s.onData()

	for s.dataForWriting != nil && s.writeErr == nil {
		s.doneWritingOrErrCond.Wait()
	}

	if s.writeErr != nil {
		return 0, s.writeErr
	}

	return len(p), nil
}

func (s *stream) lenOfDataForWriting() protocol.ByteCount {
	s.mutex.Lock()
	var l protocol.ByteCount
	if s.writeErr == nil {
		l = protocol.ByteCount(len(s.dataForWriting))
	}
	s.mutex.Unlock()
	return l
}

func (s *stream) getDataForWriting(maxBytes protocol.ByteCount) []byte {
	s.mutex.Lock()
	if s.writeErr != nil {
		s.mutex.Unlock()
		return nil
	}
	if s.dataForWriting == nil {
		s.mutex.Unlock()
		return nil
	}
	var ret []byte
	if protocol.ByteCount(len(s.dataForWriting)) > maxBytes {
		ret = s.dataForWriting[:maxBytes]
		s.dataForWriting = s.dataForWriting[maxBytes:]
	} else {
		ret = s.dataForWriting
		s.dataForWriting = nil
		s.doneWritingOrErrCond.Signal()
	}
	s.writeOffset += protocol.ByteCount(len(ret))
	s.mutex.Unlock()
	return ret
}

// Close implements io.Closer
func (s *stream) Close() error {
	s.finishedWriting.Set(true)
	s.onData()
	return nil
}

func (s *stream) shouldSendFin() bool {
	s.mutex.Lock()
	res := s.finishedWriting.Get() && !s.finSent && s.writeErr == nil && s.dataForWriting == nil
	s.mutex.Unlock()
	return res
}

func (s *stream) sentFin() {
	s.mutex.Lock()
	s.finSent = true
	s.mutex.Unlock()
}

// AddStreamFrame adds a new stream frame
func (s *stream) AddStreamFrame(frame *frames.StreamFrame) error {
	maxOffset := frame.Offset + frame.DataLen()
	err := s.flowControlManager.UpdateHighestReceived(s.streamID, maxOffset)
	if err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	err = s.frameQueue.Push(frame)
	if err != nil && err != errDuplicateStreamData {
		return err
	}
	s.newFrameOrErrCond.Signal()
	return nil
}

// CloseRemote makes the stream receive a "virtual" FIN stream frame at a given offset
func (s *stream) CloseRemote(offset protocol.ByteCount) {
	s.AddStreamFrame(&frames.StreamFrame{FinBit: true, Offset: offset})
}

// Cancel is called by session to indicate that an error occurred
// The stream should will be closed immediately
func (s *stream) Cancel(err error) {
	s.finishedReading.Set(true)
	s.finishedWriting.Set(true)
	s.cancelled.Set(true)

	s.mutex.Lock()
	// errors must not be changed!
	if s.readErr == nil {
		s.readErr = err
		s.newFrameOrErrCond.Signal()
	}
	if s.writeErr == nil {
		s.writeErr = err
		s.doneWritingOrErrCond.Signal()
	}
	s.mutex.Unlock()
}

// resets the stream remotely
func (s *stream) RegisterRemoteError(err error) {
	s.finishedWriting.Set(true)
	s.mutex.Lock()
	// errors must not be changed!
	if s.writeErr == nil {
		s.writeErr = err
		s.doneWritingOrErrCond.Signal()
	}
	s.mutex.Unlock()
}

func (s *stream) finishedRead() bool {
	return s.finishedReading.Get()
}

func (s *stream) finishedWriteAndSentFin() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.writeErr != nil || (s.finishedWriting.Get() && s.finSent)
}

func (s *stream) finished() bool {
	return s.finishedRead() && s.finishedWriteAndSentFin()
}

func (s *stream) StreamID() protocol.StreamID {
	return s.streamID
}
