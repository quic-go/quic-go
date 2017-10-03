package handshake

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type paramsNegotiator struct {
	paramsNegotiatorBase
}

var _ ParamsNegotiator = &paramsNegotiator{}

// newParamsNegotiator creates a new connection parameters manager
func newParamsNegotiator(pers protocol.Perspective, v protocol.VersionNumber, params *TransportParameters) *paramsNegotiator {
	h := &paramsNegotiator{}
	h.perspective = pers
	h.version = v
	h.init(params)
	return h
}

func (h *paramsNegotiator) SetFromTransportParameters(params []transportParameter) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	var foundInitialMaxStreamData bool
	var foundInitialMaxData bool
	var foundInitialMaxStreamID bool
	var foundIdleTimeout bool

	for _, p := range params {
		switch p.Parameter {
		case initialMaxStreamDataParameterID:
			foundInitialMaxStreamData = true
			if len(p.Value) != 4 {
				return fmt.Errorf("wrong length for initial_max_stream_data: %d (expected 4)", len(p.Value))
			}
			h.sendStreamFlowControlWindow = protocol.ByteCount(binary.BigEndian.Uint32(p.Value))
			utils.Debugf("h.sendStreamFlowControlWindow: %#x", h.sendStreamFlowControlWindow)
		case initialMaxDataParameterID:
			foundInitialMaxData = true
			if len(p.Value) != 4 {
				return fmt.Errorf("wrong length for initial_max_data: %d (expected 4)", len(p.Value))
			}
			h.sendConnectionFlowControlWindow = protocol.ByteCount(binary.BigEndian.Uint32(p.Value))
			utils.Debugf("h.sendConnectionFlowControlWindow: %#x", h.sendConnectionFlowControlWindow)
		case initialMaxStreamIDParameterID:
			foundInitialMaxStreamID = true
			if len(p.Value) != 4 {
				return fmt.Errorf("wrong length for initial_max_stream_id: %d (expected 4)", len(p.Value))
			}
			// TODO: handle this value
		case idleTimeoutParameterID:
			foundIdleTimeout = true
			if len(p.Value) != 2 {
				return fmt.Errorf("wrong length for idle_timeout: %d (expected 2)", len(p.Value))
			}
			h.setRemoteIdleTimeout(time.Duration(binary.BigEndian.Uint16(p.Value)) * time.Second)
		case omitConnectionIDParameterID:
			if len(p.Value) != 0 {
				return fmt.Errorf("wrong length for omit_connection_id: %d (expected empty)", len(p.Value))
			}
			h.omitConnectionID = true
		}
	}

	if !(foundInitialMaxStreamData && foundInitialMaxData && foundInitialMaxStreamID && foundIdleTimeout) {
		return errors.New("missing parameter")
	}
	return nil
}

func (h *paramsNegotiator) GetTransportParameters() []transportParameter {
	initialMaxStreamData := make([]byte, 4)
	binary.BigEndian.PutUint32(initialMaxStreamData, uint32(h.GetReceiveStreamFlowControlWindow()))
	initialMaxData := make([]byte, 4)
	binary.BigEndian.PutUint32(initialMaxData, uint32(h.GetReceiveConnectionFlowControlWindow()))
	initialMaxStreamID := make([]byte, 4)
	// TODO: use a reasonable value here
	binary.BigEndian.PutUint32(initialMaxStreamID, math.MaxUint32)
	idleTimeout := make([]byte, 2)
	binary.BigEndian.PutUint16(idleTimeout, uint16(h.idleTimeout))
	maxPacketSize := make([]byte, 2)
	binary.BigEndian.PutUint16(maxPacketSize, uint16(protocol.MaxReceivePacketSize))
	params := []transportParameter{
		{initialMaxStreamDataParameterID, initialMaxStreamData},
		{initialMaxDataParameterID, initialMaxData},
		{initialMaxStreamIDParameterID, initialMaxStreamID},
		{idleTimeoutParameterID, idleTimeout},
		{maxPacketSizeParameterID, maxPacketSize},
	}
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if h.omitConnectionID {
		params = append(params, transportParameter{omitConnectionIDParameterID, []byte{}})
	}
	return params
}

func (h *paramsNegotiator) OmitConnectionID() bool {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.omitConnectionID
}
