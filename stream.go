package quic

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type streamCanceledError struct {
	error
	errorCode protocol.ApplicationErrorCode
}

func (streamCanceledError) Canceled() bool                             { return true }
func (e streamCanceledError) ErrorCode() protocol.ApplicationErrorCode { return e.errorCode }

var _ StreamError = &streamCanceledError{}
var _ error = &streamCanceledError{}

const (
	errorCodeStopping      protocol.ApplicationErrorCode = 0
	errorCodeStoppingGQUIC protocol.ApplicationErrorCode = 7
)

type streamI interface {
	Stream

	HandleStreamFrame(*wire.StreamFrame) error
	HandleRstStreamFrame(*wire.RstStreamFrame) error
	HandleStopSendingFrame(*wire.StopSendingFrame)
	PopStreamFrame(maxBytes protocol.ByteCount) *wire.StreamFrame
	Finished() bool
	CloseForShutdown(error)
	// methods needed for flow control
	GetWindowUpdate() protocol.ByteCount
	HandleMaxStreamDataFrame(*wire.MaxStreamDataFrame)
	IsFlowControlBlocked() (bool, protocol.ByteCount)
}

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
//
// Read() and Write() may be called concurrently, but multiple calls to Read() or Write() individually must be synchronized manually.
type stream struct {
	mutex sync.Mutex

	ctx       context.Context
	ctxCancel context.CancelFunc

	streamID protocol.StreamID
	// onData tells the session that there's stuff to pack into a new packet
	onData func()
	// queueControlFrame queues a new control frame for sending
	// it does not call onData
	queueControlFrame func(wire.Frame)

	readPosInFrame int
	writeOffset    protocol.ByteCount
	readOffset     protocol.ByteCount

	closeForShutdownErr error
	cancelWriteErr      error
	cancelReadErr       error
	resetRemotelyErr    StreamError

	closedForShutdown bool // set when CloseForShutdown() is called
	finRead           bool // set once we read a frame with a FinBit
	finishedWriting   bool // set once Close() is called
	canceledWrite     bool // set when CancelWrite() is called, or a STOP_SENDING frame is received
	canceledRead      bool // set when CancelRead() is called
	finSent           bool // set when a STREAM_FRAME with FIN bit has b
	resetRemotely     bool // set when HandleRstStreamFrame() is called

	frameQueue   *streamFrameSorter
	readChan     chan struct{}
	readDeadline time.Time

	dataForWriting []byte
	writeChan      chan struct{}
	writeDeadline  time.Time

	flowController flowcontrol.StreamFlowController
	version        protocol.VersionNumber
}

var _ Stream = &stream{}
var _ streamI = &stream{}

type deadlineError struct{}

func (deadlineError) Error() string   { return "deadline exceeded" }
func (deadlineError) Temporary() bool { return true }
func (deadlineError) Timeout() bool   { return true }

var errDeadline net.Error = &deadlineError{}

// newStream creates a new Stream
func newStream(StreamID protocol.StreamID,
	onData func(),
	queueControlFrame func(wire.Frame),
	flowController flowcontrol.StreamFlowController,
	version protocol.VersionNumber,
) *stream {
	s := &stream{
		onData:            onData,
		queueControlFrame: queueControlFrame,
		streamID:          StreamID,
		flowController:    flowController,
		frameQueue:        newStreamFrameSorter(),
		readChan:          make(chan struct{}, 1),
		writeChan:         make(chan struct{}, 1),
		version:           version,
	}
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	return s
}

// Read implements io.Reader. It is not thread safe!
func (s *stream) Read(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finRead {
		return 0, io.EOF
	}
	if s.canceledRead {
		return 0, s.cancelReadErr
	}
	if s.resetRemotely {
		return 0, s.resetRemotelyErr
	}
	if s.closedForShutdown {
		return 0, s.closeForShutdownErr
	}

	bytesRead := 0
	for bytesRead < len(p) {
		frame := s.frameQueue.Head()
		if frame == nil && bytesRead > 0 {
			return bytesRead, s.closeForShutdownErr
		}

		for {
			// Stop waiting on errors
			if s.closedForShutdown {
				return bytesRead, s.closeForShutdownErr
			}
			if s.canceledRead {
				return bytesRead, s.cancelReadErr
			}
			if s.resetRemotely {
				return bytesRead, s.resetRemotelyErr
			}

			deadline := s.readDeadline
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return bytesRead, errDeadline
			}

			if frame != nil {
				s.readPosInFrame = int(s.readOffset - frame.Offset)
				break
			}

			s.mutex.Unlock()
			if deadline.IsZero() {
				<-s.readChan
			} else {
				select {
				case <-s.readChan:
				case <-time.After(deadline.Sub(time.Now())):
				}
			}
			s.mutex.Lock()
			frame = s.frameQueue.Head()
		}

		if bytesRead > len(p) {
			return bytesRead, fmt.Errorf("BUG: bytesRead (%d) > len(p) (%d) in stream.Read", bytesRead, len(p))
		}
		if s.readPosInFrame > int(frame.DataLen()) {
			return bytesRead, fmt.Errorf("BUG: readPosInFrame (%d) > frame.DataLen (%d) in stream.Read", s.readPosInFrame, frame.DataLen())
		}

		s.mutex.Unlock()

		copy(p[bytesRead:], frame.Data[s.readPosInFrame:])
		m := utils.Min(len(p)-bytesRead, int(frame.DataLen())-s.readPosInFrame)
		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += protocol.ByteCount(m)

		s.mutex.Lock()
		// when a RST_STREAM was received, the was already informed about the final byteOffset for this stream
		if !s.resetRemotely {
			s.flowController.AddBytesRead(protocol.ByteCount(m))
		}
		s.onData() // so that a possible WINDOW_UPDATE is sent

		if s.readPosInFrame >= int(frame.DataLen()) {
			s.frameQueue.Pop()
			s.finRead = frame.FinBit
			if frame.FinBit {
				return bytesRead, io.EOF
			}
		}
	}
	return bytesRead, nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finishedWriting {
		return 0, fmt.Errorf("write on closed stream %d", s.streamID)
	}
	if s.canceledWrite {
		return 0, s.cancelWriteErr
	}
	if s.closeForShutdownErr != nil {
		return 0, s.closeForShutdownErr
	}
	if len(p) == 0 {
		return 0, nil
	}

	s.dataForWriting = make([]byte, len(p))
	copy(s.dataForWriting, p)
	s.onData()

	var err error
	for {
		deadline := s.writeDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			err = errDeadline
			break
		}
		if s.dataForWriting == nil || s.canceledWrite || s.closedForShutdown {
			break
		}

		s.mutex.Unlock()
		if deadline.IsZero() {
			<-s.writeChan
		} else {
			select {
			case <-s.writeChan:
			case <-time.After(deadline.Sub(time.Now())):
			}
		}
		s.mutex.Lock()
	}

	if s.closeForShutdownErr != nil {
		err = s.closeForShutdownErr
	} else if s.cancelWriteErr != nil {
		err = s.cancelWriteErr
	}
	return len(p) - len(s.dataForWriting), err
}

// PopStreamFrame returns the next STREAM frame that is supposed to be sent on this stream
// maxBytes is the maximum length this frame (including frame header) will have.
func (s *stream) PopStreamFrame(maxBytes protocol.ByteCount) *wire.StreamFrame {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.closeForShutdownErr != nil {
		return nil
	}

	frame := &wire.StreamFrame{
		StreamID:       s.streamID,
		Offset:         s.writeOffset,
		DataLenPresent: true,
	}
	frameLen := frame.MinLength(s.version)
	if frameLen >= maxBytes { // a STREAM frame must have at least one byte of data
		return nil
	}
	frame.Data, frame.FinBit = s.getDataForWriting(maxBytes - frameLen)
	if len(frame.Data) == 0 && !frame.FinBit {
		return nil
	}
	if frame.FinBit {
		s.finSent = true
	}
	return frame
}

func (s *stream) getDataForWriting(maxBytes protocol.ByteCount) ([]byte, bool /* should send FIN */) {
	if s.dataForWriting == nil {
		return nil, s.finishedWriting && !s.finSent
	}

	// TODO(#657): Flow control for the crypto stream
	if s.streamID != s.version.CryptoStreamID() {
		maxBytes = utils.MinByteCount(maxBytes, s.flowController.SendWindowSize())
	}
	if maxBytes == 0 {
		return nil, false
	}

	var ret []byte
	if protocol.ByteCount(len(s.dataForWriting)) > maxBytes {
		ret = s.dataForWriting[:maxBytes]
		s.dataForWriting = s.dataForWriting[maxBytes:]
	} else {
		ret = s.dataForWriting
		s.dataForWriting = nil
		s.signalWrite()
	}
	s.writeOffset += protocol.ByteCount(len(ret))
	s.flowController.AddBytesSent(protocol.ByteCount(len(ret)))
	return ret, s.finishedWriting && s.dataForWriting == nil && !s.finSent
}

func (s *stream) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.canceledWrite {
		return fmt.Errorf("Close called for canceled stream %d", s.streamID)
	}
	if s.canceledRead && !s.version.UsesIETFFrameFormat() {
		s.queueControlFrame(&wire.RstStreamFrame{
			StreamID:   s.streamID,
			ByteOffset: s.writeOffset,
			ErrorCode:  0,
		})
	}
	s.finishedWriting = true
	s.ctxCancel()
	s.onData()
	return nil
}

func (s *stream) HandleStreamFrame(frame *wire.StreamFrame) error {
	maxOffset := frame.Offset + frame.DataLen()
	if err := s.flowController.UpdateHighestReceived(maxOffset, frame.FinBit); err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.frameQueue.Push(frame); err != nil && err != errDuplicateStreamData {
		return err
	}
	s.signalRead()
	return nil
}

// signalRead performs a non-blocking send on the readChan
func (s *stream) signalRead() {
	select {
	case s.readChan <- struct{}{}:
	default:
	}
}

// signalWrite performs a non-blocking send on the writeChan
func (s *stream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
	default:
	}
}

func (s *stream) SetReadDeadline(t time.Time) error {
	s.mutex.Lock()
	oldDeadline := s.readDeadline
	s.readDeadline = t
	s.mutex.Unlock()
	// if the new deadline is before the currently set deadline, wake up Read()
	if t.Before(oldDeadline) {
		s.signalRead()
	}
	return nil
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	oldDeadline := s.writeDeadline
	s.writeDeadline = t
	s.mutex.Unlock()
	if t.Before(oldDeadline) {
		s.signalWrite()
	}
	return nil
}

func (s *stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)  // SetReadDeadline never errors
	_ = s.SetWriteDeadline(t) // SetWriteDeadline never errors
	return nil
}

// CloseRemote makes the stream receive a "virtual" FIN stream frame at a given offset
func (s *stream) CloseRemote(offset protocol.ByteCount) {
	s.HandleStreamFrame(&wire.StreamFrame{FinBit: true, Offset: offset})
}

// CloseForShutdown closes a stream abruptly.
// It makes Read and Write unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *stream) CloseForShutdown(err error) {
	s.mutex.Lock()
	s.closedForShutdown = true
	s.closeForShutdownErr = err
	s.mutex.Unlock()
	s.signalRead()
	s.signalWrite()
	s.ctxCancel()
}

func (s *stream) CancelWrite(errorCode protocol.ApplicationErrorCode) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.cancelWriteImpl(errorCode, fmt.Errorf("Write on stream %d canceled with error code %d", s.streamID, errorCode))
}

// must be called after locking the mutex
func (s *stream) cancelWriteImpl(errorCode protocol.ApplicationErrorCode, writeErr error) error {
	if s.canceledWrite {
		return nil
	}
	if s.finishedWriting {
		return fmt.Errorf("CancelWrite for closed stream %d", s.streamID)
	}
	s.canceledWrite = true
	s.cancelWriteErr = writeErr
	s.signalWrite()
	s.queueControlFrame(&wire.RstStreamFrame{
		StreamID:   s.streamID,
		ByteOffset: s.writeOffset,
		ErrorCode:  errorCode,
	})
	// TODO(#991): cancel retransmissions for this stream
	s.onData()
	s.ctxCancel()
	return nil
}

func (s *stream) CancelRead(errorCode protocol.ApplicationErrorCode) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finRead {
		return nil
	}
	if s.canceledRead {
		return nil
	}
	s.canceledRead = true
	s.cancelReadErr = fmt.Errorf("Read on stream %d canceled with error code %d", s.streamID, errorCode)
	s.signalRead()
	if s.version.UsesIETFFrameFormat() {
		s.queueControlFrame(&wire.StopSendingFrame{
			StreamID:  s.streamID,
			ErrorCode: errorCode,
		})
	}
	return nil
}

func (s *stream) HandleRstStreamFrame(frame *wire.RstStreamFrame) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.closedForShutdown {
		return nil
	}
	if err := s.flowController.UpdateHighestReceived(frame.ByteOffset, true); err != nil {
		return err
	}
	if !s.version.UsesIETFFrameFormat() {
		s.handleStopSendingFrameImpl(&wire.StopSendingFrame{
			StreamID:  s.streamID,
			ErrorCode: frame.ErrorCode,
		})
		// In gQUIC, error code 0 has a special meaning.
		// The peer will reliably continue transmitting, but is not interested in reading from the stream.
		// We should therefore just continue reading from the stream, until we encounter the FIN bit.
		if frame.ErrorCode == 0 {
			return nil
		}
	}

	// ignore duplicate RST_STREAM frames for this stream (after checking their final offset)
	if s.resetRemotely {
		return nil
	}
	s.resetRemotely = true
	s.resetRemotelyErr = streamCanceledError{
		errorCode: frame.ErrorCode,
		error:     fmt.Errorf("Stream %d was reset with error code %d", s.streamID, frame.ErrorCode),
	}
	s.signalRead()
	return nil
}

func (s *stream) HandleStopSendingFrame(frame *wire.StopSendingFrame) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.handleStopSendingFrameImpl(frame)
}

// must be called after locking the mutex
func (s *stream) handleStopSendingFrameImpl(frame *wire.StopSendingFrame) {
	writeErr := streamCanceledError{
		errorCode: frame.ErrorCode,
		error:     fmt.Errorf("Stream %d was reset with error code %d", s.streamID, frame.ErrorCode),
	}
	errorCode := errorCodeStopping
	if !s.version.UsesIETFFrameFormat() {
		errorCode = errorCodeStoppingGQUIC
	}
	s.cancelWriteImpl(errorCode, writeErr)
}

func (s *stream) Finished() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sendSideClosed := s.finSent || s.canceledWrite
	receiveSideClosed := s.finRead || s.resetRemotely

	return s.closedForShutdown || // if the stream was abruptly closed for shutting down
		sendSideClosed && receiveSideClosed
}

func (s *stream) Context() context.Context {
	return s.ctx
}

func (s *stream) StreamID() protocol.StreamID {
	return s.streamID
}

func (s *stream) HandleMaxStreamDataFrame(frame *wire.MaxStreamDataFrame) {
	s.flowController.UpdateSendWindow(frame.ByteOffset)
}

func (s *stream) IsFlowControlBlocked() (bool, protocol.ByteCount) {
	return s.flowController.IsBlocked()
}

func (s *stream) GetWindowUpdate() protocol.ByteCount {
	return s.flowController.GetWindowUpdate()
}
