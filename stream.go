package quic

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type streamHandler interface {
	queueStreamFrame(*frames.StreamFrame) error
	updateReceiveFlowControlWindow(streamID protocol.StreamID, byteOffset protocol.ByteCount) error
	streamBlocked(streamID protocol.StreamID, byteOffset protocol.ByteCount)
}

var (
	errFlowControlViolation           = qerr.FlowControlReceivedTooMuchData
	errConnectionFlowControlViolation = qerr.FlowControlReceivedTooMuchData
)

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
//
// Read() and Write() may be called concurrently, but multiple calls to Read() or Write() individually must be synchronized manually.
type stream struct {
	streamID protocol.StreamID
	session  streamHandler

	readPosInFrame int
	writeOffset    protocol.ByteCount
	readOffset     protocol.ByteCount

	// Once set, err must not be changed!
	err   error
	mutex sync.Mutex

	// eof is set if we are finished reading
	eof int32 // really a bool
	// closed is set when we are finished writing
	closed int32 // really a bool

	frameQueue        *streamFrameSorter
	newFrameOrErrCond sync.Cond

	flowController                     flowcontrol.FlowController
	connectionFlowController           flowcontrol.FlowController
	contributesToConnectionFlowControl bool

	windowUpdateOrErrCond sync.Cond
}

// newStream creates a new Stream
func newStream(session streamHandler, connectionParameterManager *handshake.ConnectionParametersManager, connectionFlowController flowcontrol.FlowController, StreamID protocol.StreamID) (*stream, error) {
	s := &stream{
		session:                            session,
		streamID:                           StreamID,
		connectionFlowController:           connectionFlowController,
		contributesToConnectionFlowControl: true,
		flowController:                     flowcontrol.NewFlowController(StreamID, connectionParameterManager),
		frameQueue:                         newStreamFrameSorter(),
	}

	// crypto and header stream don't contribute to connection level flow control
	// TODO: only include the header stream here when using HTTP2
	if s.streamID == 1 || s.streamID == 3 {
		s.contributesToConnectionFlowControl = false
	}

	s.newFrameOrErrCond.L = &s.mutex
	s.windowUpdateOrErrCond.L = &s.mutex

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
				if frame.Offset+frame.DataLen() <= s.readOffset && !frame.FinBit {
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

		m := utils.Min(len(p)-bytesRead, int(frame.DataLen())-s.readPosInFrame)
		copy(p[bytesRead:], frame.Data[s.readPosInFrame:])

		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += protocol.ByteCount(m)

		s.flowController.AddBytesRead(protocol.ByteCount(m))
		if s.contributesToConnectionFlowControl {
			s.connectionFlowController.AddBytesRead(protocol.ByteCount(m))
		}

		s.maybeTriggerWindowUpdate()

		if s.readPosInFrame >= int(frame.DataLen()) {
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

func (s *stream) ConnectionFlowControlWindowUpdated() {
	s.windowUpdateOrErrCond.Broadcast()
}

func (s *stream) UpdateSendFlowControlWindow(n protocol.ByteCount) bool {
	if s.flowController.UpdateSendWindow(n) {
		s.windowUpdateOrErrCond.Broadcast()
		return true
	}
	return false
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
		remainingBytesInWindow := utils.MinByteCount(s.flowController.SendWindowSize(), protocol.ByteCount(len(p)-dataWritten))
		if s.contributesToConnectionFlowControl {
			remainingBytesInWindow = utils.MinByteCount(remainingBytesInWindow, s.connectionFlowController.SendWindowSize())
		}
		for remainingBytesInWindow == 0 && s.err == nil {
			s.windowUpdateOrErrCond.Wait()
			remainingBytesInWindow = utils.MinByteCount(s.flowController.SendWindowSize(), protocol.ByteCount(len(p)-dataWritten))
			if s.contributesToConnectionFlowControl {
				remainingBytesInWindow = utils.MinByteCount(remainingBytesInWindow, s.connectionFlowController.SendWindowSize())
			}
		}
		s.mutex.Unlock()

		if remainingBytesInWindow == 0 {
			// We must have had an error
			return 0, s.err
		}

		dataLen := utils.MinByteCount(protocol.ByteCount(len(p)), remainingBytesInWindow)
		data := make([]byte, dataLen)
		copy(data, p[dataWritten:])
		err := s.session.queueStreamFrame(&frames.StreamFrame{
			StreamID: s.streamID,
			Offset:   s.writeOffset,
			Data:     data,
		})

		if err != nil {
			return 0, err
		}

		dataWritten += int(dataLen) // We cannot have written more than the int range
		s.flowController.AddBytesSent(protocol.ByteCount(dataLen))
		if s.contributesToConnectionFlowControl {
			s.connectionFlowController.AddBytesSent(protocol.ByteCount(dataLen))
		}
		s.writeOffset += protocol.ByteCount(dataLen)

		s.maybeTriggerBlocked()
	}

	return dataWritten, nil
}

// Close implements io.Closer
func (s *stream) Close() error {
	atomic.StoreInt32(&s.closed, 1)
	return s.session.queueStreamFrame(&frames.StreamFrame{
		StreamID: s.streamID,
		Offset:   s.writeOffset,
		FinBit:   true,
	})
}

// AddStreamFrame adds a new stream frame
func (s *stream) AddStreamFrame(frame *frames.StreamFrame) error {
	maxOffset := frame.Offset + frame.DataLen()
	increment := s.flowController.UpdateHighestReceived(maxOffset)
	if s.contributesToConnectionFlowControl {
		s.connectionFlowController.IncrementHighestReceived(increment)
	}
	if s.flowController.CheckFlowControlViolation() {
		return errFlowControlViolation
	}
	if s.connectionFlowController.CheckFlowControlViolation() {
		return errConnectionFlowControlViolation
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	err := s.frameQueue.Push(frame)
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

func (s *stream) maybeTriggerWindowUpdate() {
	// check for stream level window updates
	doUpdate, byteOffset := s.flowController.MaybeTriggerWindowUpdate()
	if doUpdate {
		s.session.updateReceiveFlowControlWindow(s.streamID, byteOffset)
	}

	// check for connection level window updates
	doUpdate, byteOffset = s.connectionFlowController.MaybeTriggerWindowUpdate()
	if doUpdate {
		s.session.updateReceiveFlowControlWindow(0, byteOffset)
	}
}

func (s *stream) maybeTriggerBlocked() {
	streamBlocked := s.flowController.MaybeTriggerBlocked()

	if streamBlocked {
		s.session.streamBlocked(s.streamID, s.writeOffset)
	}

	if s.contributesToConnectionFlowControl {
		connectionBlocked := s.connectionFlowController.MaybeTriggerBlocked()

		if connectionBlocked {
			// TODO: send out connection-level BlockedFrames at the right time
			// see https://github.com/lucas-clemente/quic-go/issues/113
			s.session.streamBlocked(0, 0)
		}
	}
}

// RegisterError is called by session to indicate that an error occurred and the
// stream should be closed.
func (s *stream) RegisterError(err error) {
	atomic.StoreInt32(&s.closed, 1)
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

func (s *stream) finishedWriting() bool {
	return atomic.LoadInt32(&s.closed) != 0
}

func (s *stream) finished() bool {
	return s.finishedReading() && s.finishedWriting()
}

func (s *stream) StreamID() protocol.StreamID {
	return s.streamID
}
