package quic

import (
	"context"
	"fmt"
	"sync"

	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

// StreamLimitReachedError is returned from Connection.OpenStream and Connection.OpenUniStream
// when it is not possible to open a new stream because the number of opens streams reached
// the peer's stream limit.
type StreamLimitReachedError struct{}

func (e StreamLimitReachedError) Error() string { return "too many open streams" }

type streamsMap struct {
	ctx         context.Context // not used for cancellations, but carries the values associated with the connection
	perspective protocol.Perspective

	maxIncomingBidiStreams uint64
	maxIncomingUniStreams  uint64

	sender            streamSender
	queueControlFrame func(wire.Frame)
	newFlowController func(protocol.StreamID) flowcontrol.StreamFlowController

	mutex               sync.Mutex
	outgoingBidiStreams *outgoingStreamsMap[*Stream]
	outgoingUniStreams  *outgoingStreamsMap[*SendStream]
	incomingBidiStreams *incomingStreamsMap[*Stream]
	incomingUniStreams  *incomingStreamsMap[*ReceiveStream]
	reset               bool
}

var _ streamManager = &streamsMap{}

func newStreamsMap(
	ctx context.Context,
	sender streamSender,
	queueControlFrame func(wire.Frame),
	newFlowController func(protocol.StreamID) flowcontrol.StreamFlowController,
	maxIncomingBidiStreams uint64,
	maxIncomingUniStreams uint64,
	perspective protocol.Perspective,
) *streamsMap {
	m := &streamsMap{
		ctx:                    ctx,
		perspective:            perspective,
		queueControlFrame:      queueControlFrame,
		newFlowController:      newFlowController,
		maxIncomingBidiStreams: maxIncomingBidiStreams,
		maxIncomingUniStreams:  maxIncomingUniStreams,
		sender:                 sender,
	}
	m.initMaps()
	return m
}

func (m *streamsMap) initMaps() {
	m.outgoingBidiStreams = newOutgoingStreamsMap(
		protocol.StreamTypeBidi,
		func(id protocol.StreamID) *Stream {
			return newStream(m.ctx, id, m.sender, m.newFlowController(id))
		},
		m.queueControlFrame,
		m.perspective,
	)
	m.incomingBidiStreams = newIncomingStreamsMap(
		protocol.StreamTypeBidi,
		func(id protocol.StreamID) *Stream {
			return newStream(m.ctx, id, m.sender, m.newFlowController(id))
		},
		m.maxIncomingBidiStreams,
		m.queueControlFrame,
		m.perspective,
	)
	m.outgoingUniStreams = newOutgoingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *SendStream {
			return newSendStream(m.ctx, id, m.sender, m.newFlowController(id))
		},
		m.queueControlFrame,
		m.perspective,
	)
	m.incomingUniStreams = newIncomingStreamsMap(
		protocol.StreamTypeUni,
		func(id protocol.StreamID) *ReceiveStream {
			return newReceiveStream(id, m.sender, m.newFlowController(id))
		},
		m.maxIncomingUniStreams,
		m.queueControlFrame,
		m.perspective,
	)
}

func (m *streamsMap) OpenStream() (*Stream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.outgoingBidiStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	return mm.OpenStream()
}

func (m *streamsMap) OpenStreamSync(ctx context.Context) (*Stream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.outgoingBidiStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	return mm.OpenStreamSync(ctx)
}

func (m *streamsMap) OpenUniStream() (*SendStream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.outgoingUniStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	return mm.OpenStream()
}

func (m *streamsMap) OpenUniStreamSync(ctx context.Context) (*SendStream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.outgoingUniStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	return mm.OpenStreamSync(ctx)
}

func (m *streamsMap) AcceptStream(ctx context.Context) (*Stream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.incomingBidiStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	return mm.AcceptStream(ctx)
}

func (m *streamsMap) AcceptUniStream(ctx context.Context) (*ReceiveStream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.incomingUniStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	return mm.AcceptStream(ctx)
}

func (m *streamsMap) DeleteStream(id protocol.StreamID) error {
	switch id.Type() {
	case protocol.StreamTypeUni:
		if id.InitiatedBy() == m.perspective {
			return m.outgoingUniStreams.DeleteStream(id)
		}
		return m.incomingUniStreams.DeleteStream(id)
	case protocol.StreamTypeBidi:
		if id.InitiatedBy() == m.perspective {
			return m.outgoingBidiStreams.DeleteStream(id)
		}
		return m.incomingBidiStreams.DeleteStream(id)
	}
	panic("")
}

func (m *streamsMap) GetOrOpenReceiveStream(id protocol.StreamID) (*ReceiveStream, error) {
	str, err := m.getOrOpenReceiveStream(id)
	if err != nil {
		return nil, &qerr.TransportError{
			ErrorCode:    qerr.StreamStateError,
			ErrorMessage: err.Error(),
		}
	}
	return str, nil
}

func (m *streamsMap) getOrOpenReceiveStream(id protocol.StreamID) (*ReceiveStream, error) {
	switch id.Type() {
	case protocol.StreamTypeUni:
		if id.InitiatedBy() == m.perspective {
			// an outgoing unidirectional stream is a send stream, not a receive stream
			return nil, fmt.Errorf("peer attempted to open receive stream %d", id)
		}
		return m.incomingUniStreams.GetOrOpenStream(id)
	case protocol.StreamTypeBidi:
		if id.InitiatedBy() == m.perspective {
			str, err := m.outgoingBidiStreams.GetStream(id)
			if str == nil && err == nil {
				return nil, nil
			}
			return str.ReceiveStream, err
		} else {
			str, err := m.incomingBidiStreams.GetOrOpenStream(id)
			if str == nil && err == nil {
				return nil, nil
			}
			return str.ReceiveStream, err
		}
	}
	panic("")
}

func (m *streamsMap) GetOrOpenSendStream(id protocol.StreamID) (*SendStream, error) {
	str, err := m.getOrOpenSendStream(id)
	if err != nil {
		return nil, &qerr.TransportError{
			ErrorCode:    qerr.StreamStateError,
			ErrorMessage: err.Error(),
		}
	}
	return str, nil
}

func (m *streamsMap) getOrOpenSendStream(id protocol.StreamID) (*SendStream, error) {
	switch id.Type() {
	case protocol.StreamTypeUni:
		if id.InitiatedBy() == m.perspective {
			str, err := m.outgoingUniStreams.GetStream(id)
			if str == nil && err == nil {
				return nil, nil
			}
			return str, err
		}
		// an incoming unidirectional stream is a receive stream, not a send stream
		return nil, fmt.Errorf("peer attempted to open send stream %d", id)
	case protocol.StreamTypeBidi:
		if id.InitiatedBy() == m.perspective {
			str, err := m.outgoingBidiStreams.GetStream(id)
			if str == nil && err == nil {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return str.SendStream, nil
		} else {
			str, err := m.incomingBidiStreams.GetOrOpenStream(id)
			if str == nil && err == nil {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return str.SendStream, nil
		}
	}
	panic("")
}

func (m *streamsMap) HandleMaxStreamsFrame(f *wire.MaxStreamsFrame) {
	switch f.Type {
	case protocol.StreamTypeUni:
		m.outgoingUniStreams.SetMaxStream(f.MaxStreamNum.StreamID(protocol.StreamTypeUni, m.perspective))
	case protocol.StreamTypeBidi:
		m.outgoingBidiStreams.SetMaxStream(f.MaxStreamNum.StreamID(protocol.StreamTypeBidi, m.perspective))
	}
}

func (m *streamsMap) UpdateLimits(p *wire.TransportParameters) {
	m.outgoingBidiStreams.UpdateSendWindow(p.InitialMaxStreamDataBidiRemote)
	m.outgoingBidiStreams.SetMaxStream(p.MaxBidiStreamNum.StreamID(protocol.StreamTypeBidi, m.perspective))
	m.outgoingUniStreams.UpdateSendWindow(p.InitialMaxStreamDataUni)
	m.outgoingUniStreams.SetMaxStream(p.MaxUniStreamNum.StreamID(protocol.StreamTypeUni, m.perspective))
}

func (m *streamsMap) CloseWithError(err error) {
	m.outgoingBidiStreams.CloseWithError(err)
	m.outgoingUniStreams.CloseWithError(err)
	m.incomingBidiStreams.CloseWithError(err)
	m.incomingUniStreams.CloseWithError(err)
}

// ResetFor0RTT resets is used when 0-RTT is rejected. In that case, the streams maps are
// 1. closed with an Err0RTTRejected, making calls to Open{Uni}Stream{Sync} / Accept{Uni}Stream return that error.
// 2. reset to their initial state, such that we can immediately process new incoming stream data.
// Afterwards, calls to Open{Uni}Stream{Sync} / Accept{Uni}Stream will continue to return the error,
// until UseResetMaps() has been called.
func (m *streamsMap) ResetFor0RTT() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.reset = true
	m.CloseWithError(Err0RTTRejected)
	m.initMaps()
}

func (m *streamsMap) UseResetMaps() {
	m.mutex.Lock()
	m.reset = false
	m.mutex.Unlock()
}
