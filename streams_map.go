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

type streamError struct {
	message string
	nums    []protocol.StreamNum
}

func (e streamError) Error() string {
	return e.message
}

func convertStreamError(err error, stype protocol.StreamType, pers protocol.Perspective) error {
	strError, ok := err.(streamError)
	if !ok {
		return err
	}
	ids := make([]interface{}, len(strError.nums))
	for i, num := range strError.nums {
		ids[i] = num.StreamID(stype, pers)
	}
	return fmt.Errorf(strError.Error(), ids...)
}

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
		func(num protocol.StreamNum) *Stream {
			id := num.StreamID(protocol.StreamTypeBidi, m.perspective)
			return newStream(m.ctx, id, m.sender, m.newFlowController(id))
		},
		m.queueControlFrame,
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
		func(num protocol.StreamNum) *SendStream {
			id := num.StreamID(protocol.StreamTypeUni, m.perspective)
			return newSendStream(m.ctx, id, m.sender, m.newFlowController(id))
		},
		m.queueControlFrame,
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
	str, err := mm.OpenStream()
	return str, convertStreamError(err, protocol.StreamTypeBidi, m.perspective)
}

func (m *streamsMap) OpenStreamSync(ctx context.Context) (*Stream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.outgoingBidiStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	str, err := mm.OpenStreamSync(ctx)
	return str, convertStreamError(err, protocol.StreamTypeBidi, m.perspective)
}

func (m *streamsMap) OpenUniStream() (*SendStream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.outgoingUniStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	str, err := mm.OpenStream()
	return str, convertStreamError(err, protocol.StreamTypeBidi, m.perspective)
}

func (m *streamsMap) OpenUniStreamSync(ctx context.Context) (*SendStream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.outgoingUniStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	str, err := mm.OpenStreamSync(ctx)
	return str, convertStreamError(err, protocol.StreamTypeUni, m.perspective)
}

func (m *streamsMap) AcceptStream(ctx context.Context) (*Stream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.incomingBidiStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	str, err := mm.AcceptStream(ctx)
	return str, convertStreamError(err, protocol.StreamTypeBidi, m.perspective.Opposite())
}

func (m *streamsMap) AcceptUniStream(ctx context.Context) (*ReceiveStream, error) {
	m.mutex.Lock()
	reset := m.reset
	mm := m.incomingUniStreams
	m.mutex.Unlock()
	if reset {
		return nil, Err0RTTRejected
	}
	str, err := mm.AcceptStream(ctx)
	return str, convertStreamError(err, protocol.StreamTypeUni, m.perspective.Opposite())
}

func (m *streamsMap) DeleteStream(id protocol.StreamID) error {
	num := id.StreamNum()
	switch id.Type() {
	case protocol.StreamTypeUni:
		if id.InitiatedBy() == m.perspective {
			return convertStreamError(m.outgoingUniStreams.DeleteStream(num), protocol.StreamTypeUni, m.perspective)
		}
		return m.incomingUniStreams.DeleteStream(id)
	case protocol.StreamTypeBidi:
		if id.InitiatedBy() == m.perspective {
			return convertStreamError(m.outgoingBidiStreams.DeleteStream(num), protocol.StreamTypeBidi, m.perspective)
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
	num := id.StreamNum()
	switch id.Type() {
	case protocol.StreamTypeUni:
		if id.InitiatedBy() == m.perspective {
			// an outgoing unidirectional stream is a send stream, not a receive stream
			return nil, fmt.Errorf("peer attempted to open receive stream %d", id)
		}
		str, err := m.incomingUniStreams.GetOrOpenStream(id)
		return str, convertStreamError(err, protocol.StreamTypeUni, m.perspective)
	case protocol.StreamTypeBidi:
		if id.InitiatedBy() == m.perspective {
			str, err := m.outgoingBidiStreams.GetStream(num)
			if str == nil && err == nil {
				return nil, nil
			}
			return str.ReceiveStream, convertStreamError(err, protocol.StreamTypeBidi, id.InitiatedBy())
		} else {
			str, err := m.incomingBidiStreams.GetOrOpenStream(id)
			if str == nil && err == nil {
				return nil, nil
			}
			return str.ReceiveStream, convertStreamError(err, protocol.StreamTypeBidi, id.InitiatedBy())
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
	num := id.StreamNum()
	switch id.Type() {
	case protocol.StreamTypeUni:
		if id.InitiatedBy() == m.perspective {
			str, err := m.outgoingUniStreams.GetStream(num)
			if str == nil && err == nil {
				return nil, nil
			}
			return str, convertStreamError(err, protocol.StreamTypeUni, m.perspective)
		}
		// an incoming unidirectional stream is a receive stream, not a send stream
		return nil, fmt.Errorf("peer attempted to open send stream %d", id)
	case protocol.StreamTypeBidi:
		if id.InitiatedBy() == m.perspective {
			str, err := m.outgoingBidiStreams.GetStream(num)
			if str == nil && err == nil {
				return nil, nil
			}
			if err != nil {
				return nil, convertStreamError(err, protocol.StreamTypeBidi, id.InitiatedBy())
			}
			return str.SendStream, nil
		} else {
			str, err := m.incomingBidiStreams.GetOrOpenStream(id)
			if str == nil && err == nil {
				return nil, nil
			}
			if err != nil {
				return nil, convertStreamError(err, protocol.StreamTypeBidi, id.InitiatedBy())
			}
			return str.SendStream, nil
		}
	}
	panic("")
}

func (m *streamsMap) HandleMaxStreamsFrame(f *wire.MaxStreamsFrame) {
	switch f.Type {
	case protocol.StreamTypeUni:
		m.outgoingUniStreams.SetMaxStream(f.MaxStreamNum)
	case protocol.StreamTypeBidi:
		m.outgoingBidiStreams.SetMaxStream(f.MaxStreamNum)
	}
}

func (m *streamsMap) UpdateLimits(p *wire.TransportParameters) {
	m.outgoingBidiStreams.UpdateSendWindow(p.InitialMaxStreamDataBidiRemote)
	m.outgoingBidiStreams.SetMaxStream(p.MaxBidiStreamNum)
	m.outgoingUniStreams.UpdateSendWindow(p.InitialMaxStreamDataUni)
	m.outgoingUniStreams.SetMaxStream(p.MaxUniStreamNum)
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
