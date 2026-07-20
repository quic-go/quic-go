package quic

import (
	"fmt"
	"sync"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

type qmuxState struct {
	maxRecordSize protocol.ByteCount

	// recordQueueSpace is signaled when the receive queue drains below its limit,
	// allowing the read loop to resume reading records from the underlying transport.
	recordQueueSpace chan struct{}

	mutex                        sync.Mutex
	writtenFrameBatchesAvailable chan struct{}
	writtenFrameBatches          []qmuxWrittenFrameBatch
	nextStreamOffsets            map[protocol.StreamID]protocol.ByteCount
	nextPingSeq                  uint64
	pendingPing                  bool
	pingResponse                 *uint64
}

type qmuxWrittenFrameBatch struct {
	frames       []ackhandler.Frame
	streamFrames []ackhandler.StreamFrame
}

func (s *qmuxState) queueWrittenFrameBatch(p qmuxWrittenFrameBatch) {
	s.mutex.Lock()
	s.writtenFrameBatches = append(s.writtenFrameBatches, p)
	s.mutex.Unlock()
	select {
	case s.writtenFrameBatchesAvailable <- struct{}{}:
	default:
	}
}

func (s *qmuxState) popWrittenFrameBatches() []qmuxWrittenFrameBatch {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if len(s.writtenFrameBatches) == 0 {
		return nil
	}
	packets := s.writtenFrameBatches
	s.writtenFrameBatches = nil
	return packets
}

func acknowledgeWrittenFrames(p qmuxWrittenFrameBatch) {
	for _, f := range p.frames {
		if f.Handler != nil && f.Frame != nil {
			f.Handler.OnAcked(f.Frame)
		}
	}
	for _, f := range p.streamFrames {
		if f.Handler != nil && f.Frame != nil {
			f.Handler.OnAcked(f.Frame)
		}
	}
}

func (s *qmuxState) checkStreamFrameOrdering(f *wire.StreamFrame) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	expected := s.nextStreamOffsets[f.StreamID]
	if f.Offset != expected {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("non-contiguous QMux STREAM frame for stream %d: got offset %d, expected %d", f.StreamID, f.Offset, expected),
		}
	}
	if s.nextStreamOffsets == nil {
		s.nextStreamOffsets = make(map[protocol.StreamID]protocol.ByteCount)
	}
	s.nextStreamOffsets[f.StreamID] = expected + f.DataLen()
	return nil
}

// removeStreamOffset drops the receive-side offset tracking for a stream once it has completed,
// preventing unbounded growth of the map over the lifetime of a connection.
func (s *qmuxState) removeStreamOffset(id protocol.StreamID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.nextStreamOffsets, id)
}

func (s *qmuxState) nextPingRequest() uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.nextPingSeq++
	s.pendingPing = true
	return s.nextPingSeq
}

func (s *qmuxState) queuePingResponse(seq uint64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.pingResponse == nil || seq > *s.pingResponse {
		s.pingResponse = &seq
	}
}

func (s *qmuxState) popPingResponse() (uint64, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.pingResponse == nil {
		return 0, false
	}
	seq := *s.pingResponse
	s.pingResponse = nil
	return seq, true
}

func (s *qmuxState) receivedPingResponse(seq uint64) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if seq > s.nextPingSeq {
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("QX_PING response sequence %d exceeds greatest request sequence %d", seq, s.nextPingSeq),
		}
	}
	if !s.pendingPing || seq < s.nextPingSeq {
		return false, nil
	}
	s.pendingPing = false
	return true, nil
}
