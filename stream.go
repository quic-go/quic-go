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

type streamI interface {
	Stream

	HandleStreamFrame(*wire.StreamFrame) error
	HandleRstStreamFrame(*wire.RstStreamFrame) error
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

	// Once set, the errors must not be changed!
	err error

	// closedForShutdown is set when Cancel() is called
	closedForShutdown utils.AtomicBool
	// finishedReading is set once we read a frame with a FinBit
	finishedReading utils.AtomicBool
	// finisedWriting is set once Close() is called
	finishedWriting utils.AtomicBool
	// resetLocally is set if Reset() is called
	resetLocally utils.AtomicBool
	// resetRemotely is set if HandleRstStreamFrame() is called
	resetRemotely utils.AtomicBool

	frameQueue   *streamFrameSorter
	readChan     chan struct{}
	readDeadline time.Time

	dataForWriting []byte
	finSent        utils.AtomicBool
	rstSent        utils.AtomicBool
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
	err := s.err
	s.mutex.Unlock()
	if s.closedForShutdown.Get() || s.resetLocally.Get() {
		return 0, err
	}
	if s.finishedReading.Get() {
		return 0, io.EOF
	}

	bytesRead := 0
	for bytesRead < len(p) {
		s.mutex.Lock()
		frame := s.frameQueue.Head()
		if frame == nil && bytesRead > 0 {
			err = s.err
			s.mutex.Unlock()
			return bytesRead, err
		}

		var err error
		for {
			// Stop waiting on errors
			if s.resetLocally.Get() || s.closedForShutdown.Get() {
				err = s.err
				break
			}

			deadline := s.readDeadline
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				err = errDeadline
				break
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
		s.mutex.Unlock()

		if err != nil {
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

		// when a RST_STREAM was received, the was already informed about the final byteOffset for this stream
		if !s.resetRemotely.Get() {
			s.flowController.AddBytesRead(protocol.ByteCount(m))
		}
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

	if s.resetLocally.Get() || s.err != nil {
		return 0, s.err
	}
	if s.finishedWriting.Get() {
		return 0, fmt.Errorf("write on closed stream %d", s.streamID)
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
		if s.dataForWriting == nil || s.err != nil {
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

	if s.err != nil {
		err = s.err
	}
	return len(p) - len(s.dataForWriting), err
}

func (s *stream) GetWriteOffset() protocol.ByteCount {
	return s.writeOffset
}

// PopStreamFrame returns the next STREAM frame that is supposed to be sent on this stream
// maxBytes is the maximum length this frame (including frame header) will have.
func (s *stream) PopStreamFrame(maxBytes protocol.ByteCount) *wire.StreamFrame {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.err != nil {
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
		s.finSent.Set(true)
	}
	return frame
}

func (s *stream) getDataForWriting(maxBytes protocol.ByteCount) ([]byte, bool /* should send FIN */) {
	if s.dataForWriting == nil {
		return nil, s.finishedWriting.Get() && !s.finSent.Get()
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
	return ret, s.finishedWriting.Get() && s.dataForWriting == nil && !s.finSent.Get()
}

// Close implements io.Closer
func (s *stream) Close() error {
	s.finishedWriting.Set(true)
	s.ctxCancel()
	s.onData()
	return nil
}

func (s *stream) shouldSendReset() bool {
	if s.rstSent.Get() {
		return false
	}
	return (s.resetLocally.Get() || s.resetRemotely.Get()) && !s.finishedWriteAndSentFin()
}

// HandleStreamFrame adds a new stream frame
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

// signalRead performs a non-blocking send on the writeChan
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
	s.closedForShutdown.Set(true)
	s.ctxCancel()
	// errors must not be changed!
	if s.err == nil {
		s.err = err
		s.signalRead()
		s.signalWrite()
	}
	s.mutex.Unlock()
}

// resets the stream locally
func (s *stream) Reset(err error) {
	if s.resetLocally.Get() {
		return
	}
	s.mutex.Lock()
	s.resetLocally.Set(true)
	s.ctxCancel()
	// errors must not be changed!
	if s.err == nil {
		s.err = err
		s.signalRead()
		s.signalWrite()
	}
	if s.shouldSendReset() {
		s.queueControlFrame(&wire.RstStreamFrame{
			StreamID:   s.streamID,
			ByteOffset: s.writeOffset,
		})
		s.onData()
		s.rstSent.Set(true)
	}
	s.mutex.Unlock()
}

func (s *stream) HandleRstStreamFrame(frame *wire.RstStreamFrame) error {
	if s.resetRemotely.Get() {
		return nil
	}
	s.mutex.Lock()
	s.resetRemotely.Set(true)
	s.ctxCancel()
	// errors must not be changed!
	if s.err == nil {
		s.err = fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode)
		s.signalWrite()
	}
	if err := s.flowController.UpdateHighestReceived(frame.ByteOffset, true); err != nil {
		return err
	}
	if s.shouldSendReset() {
		s.queueControlFrame(&wire.RstStreamFrame{
			StreamID:   s.streamID,
			ByteOffset: s.writeOffset,
		})
		s.onData()
		s.rstSent.Set(true)
	}
	s.mutex.Unlock()
	return nil
}

func (s *stream) finishedWriteAndSentFin() bool {
	return s.finishedWriting.Get() && s.finSent.Get()
}

func (s *stream) Finished() bool {
	return s.closedForShutdown.Get() ||
		(s.finishedReading.Get() && s.finishedWriteAndSentFin()) ||
		(s.resetRemotely.Get() && s.rstSent.Get()) ||
		(s.finishedReading.Get() && s.rstSent.Get()) ||
		(s.finishedWriteAndSentFin() && s.resetRemotely.Get())
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
