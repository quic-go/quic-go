package quic

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type sendStream struct {
	mutex sync.Mutex

	ctx       context.Context
	ctxCancel context.CancelFunc

	streamID protocol.StreamID
	sender   streamSender

	writeOffset protocol.ByteCount

	cancelWriteErr      error
	closeForShutdownErr error

	closedForShutdown bool // set when CloseForShutdown() is called
	finishedWriting   bool // set once Close() is called
	canceledWrite     bool // set when CancelWrite() is called, or a STOP_SENDING frame is received
	finSent           bool // set when a STREAM_FRAME with FIN bit has b

	dataForWriting []byte
	writeChan      chan struct{}
	writeDeadline  time.Time

	flowController flowcontrol.StreamFlowController
	version        protocol.VersionNumber
}

var _ SendStream = &sendStream{}

func newSendStream(
	streamID protocol.StreamID,
	sender streamSender,
	flowController flowcontrol.StreamFlowController,
	version protocol.VersionNumber,
) *sendStream {
	s := &sendStream{
		streamID:       streamID,
		sender:         sender,
		flowController: flowController,
		writeChan:      make(chan struct{}, 1),
		version:        version,
	}
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	return s
}

func (s *sendStream) StreamID() protocol.StreamID {
	return s.streamID // same for receiveStream and sendStream
}

func (s *sendStream) Write(p []byte) (int, error) {
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
	if !s.writeDeadline.IsZero() && !time.Now().Before(s.writeDeadline) {
		return 0, errDeadline
	}
	if len(p) == 0 {
		return 0, nil
	}

	s.dataForWriting = make([]byte, len(p))
	copy(s.dataForWriting, p)
	s.sender.scheduleSending()

	var bytesWritten int
	var err error
	for {
		bytesWritten = len(p) - len(s.dataForWriting)
		deadline := s.writeDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			s.dataForWriting = nil
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
	return bytesWritten, err
}

// popStreamFrame returns the next STREAM frame that is supposed to be sent on this stream
// maxBytes is the maximum length this frame (including frame header) will have.
func (s *sendStream) popStreamFrame(maxBytes protocol.ByteCount) *wire.StreamFrame {
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
	} else if s.streamID != s.version.CryptoStreamID() { // TODO(#657): Flow control for the crypto stream
		if isBlocked, offset := s.flowController.IsNewlyBlocked(); isBlocked {
			s.sender.queueControlFrame(&wire.StreamBlockedFrame{
				StreamID: s.streamID,
				Offset:   offset,
			})
		}
	}
	return frame
}

func (s *sendStream) getDataForWriting(maxBytes protocol.ByteCount) ([]byte, bool /* should send FIN */) {
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

func (s *sendStream) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.canceledWrite {
		return fmt.Errorf("Close called for canceled stream %d", s.streamID)
	}
	s.finishedWriting = true
	s.sender.scheduleSending()
	s.ctxCancel()
	return nil
}

func (s *sendStream) CancelWrite(errorCode protocol.ApplicationErrorCode) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.cancelWriteImpl(errorCode, fmt.Errorf("Write on stream %d canceled with error code %d", s.streamID, errorCode))
}

// must be called after locking the mutex
func (s *sendStream) cancelWriteImpl(errorCode protocol.ApplicationErrorCode, writeErr error) error {
	if s.canceledWrite {
		return nil
	}
	if s.finishedWriting {
		return fmt.Errorf("CancelWrite for closed stream %d", s.streamID)
	}
	s.canceledWrite = true
	s.cancelWriteErr = writeErr
	s.signalWrite()
	s.sender.queueControlFrame(&wire.RstStreamFrame{
		StreamID:   s.streamID,
		ByteOffset: s.writeOffset,
		ErrorCode:  errorCode,
	})
	// TODO(#991): cancel retransmissions for this stream
	s.ctxCancel()
	return nil
}

func (s *sendStream) handleStopSendingFrame(frame *wire.StopSendingFrame) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.handleStopSendingFrameImpl(frame)
}

func (s *sendStream) handleMaxStreamDataFrame(frame *wire.MaxStreamDataFrame) {
	s.flowController.UpdateSendWindow(frame.ByteOffset)
}

// must be called after locking the mutex
func (s *sendStream) handleStopSendingFrameImpl(frame *wire.StopSendingFrame) {
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

func (s *sendStream) Context() context.Context {
	return s.ctx
}

func (s *sendStream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	oldDeadline := s.writeDeadline
	s.writeDeadline = t
	s.mutex.Unlock()
	if t.Before(oldDeadline) {
		s.signalWrite()
	}
	return nil
}

// CloseForShutdown closes a stream abruptly.
// It makes Write unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *sendStream) closeForShutdown(err error) {
	s.mutex.Lock()
	s.closedForShutdown = true
	s.closeForShutdownErr = err
	s.mutex.Unlock()
	s.signalWrite()
	s.ctxCancel()
}

func (s *sendStream) finished() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.closedForShutdown || // if the stream was abruptly closed for shutting down
		s.finSent || s.canceledWrite
}

func (s *sendStream) getWriteOffset() protocol.ByteCount {
	return s.writeOffset
}

// signalWrite performs a non-blocking send on the writeChan
func (s *sendStream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
	default:
	}
}
