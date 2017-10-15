package handshake

import (
	"bytes"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// errMalformedTag is returned when the tag value cannot be read
var (
	errMalformedTag                         = qerr.Error(qerr.InvalidCryptoMessageParameter, "malformed Tag value")
	errFlowControlRenegotiationNotSupported = qerr.Error(qerr.InvalidCryptoMessageParameter, "renegotiation of flow control parameters not supported")
)

type paramsNegotiatorGQUIC struct {
	paramsNegotiatorBase
}

var _ ParamsNegotiator = &paramsNegotiatorGQUIC{}

// newParamsNegotiatorGQUIC creates a new connection parameters manager
func newParamsNegotiatorGQUIC(pers protocol.Perspective, v protocol.VersionNumber, params *TransportParameters) *paramsNegotiatorGQUIC {
	h := &paramsNegotiatorGQUIC{}
	h.perspective = pers
	h.version = v
	h.init(params)
	return h
}

// SetFromMap reads all params.
func (h *paramsNegotiatorGQUIC) SetFromMap(params map[Tag][]byte) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if value, ok := params[TagTCID]; ok && h.perspective == protocol.PerspectiveServer {
		clientValue, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return errMalformedTag
		}
		h.omitConnectionID = (clientValue == 0)
	}
	if value, ok := params[TagMIDS]; ok {
		clientValue, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return errMalformedTag
		}
		h.maxOutgoingStreams = clientValue
	}
	if value, ok := params[TagICSL]; ok {
		clientValue, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return errMalformedTag
		}
		h.setRemoteIdleTimeout(time.Duration(clientValue) * time.Second)
	}
	if value, ok := params[TagSFCW]; ok {
		if h.flowControlNegotiated {
			return errFlowControlRenegotiationNotSupported
		}
		sendStreamFlowControlWindow, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return errMalformedTag
		}
		h.sendStreamFlowControlWindow = protocol.ByteCount(sendStreamFlowControlWindow)
	}
	if value, ok := params[TagCFCW]; ok {
		if h.flowControlNegotiated {
			return errFlowControlRenegotiationNotSupported
		}
		sendConnectionFlowControlWindow, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return errMalformedTag
		}
		h.sendConnectionFlowControlWindow = protocol.ByteCount(sendConnectionFlowControlWindow)
	}

	_, containsSFCW := params[TagSFCW]
	_, containsCFCW := params[TagCFCW]
	if containsCFCW || containsSFCW {
		h.flowControlNegotiated = true
	}

	return nil
}

// GetHelloMap gets all parameters needed for the Hello message.
func (h *paramsNegotiatorGQUIC) GetHelloMap() (map[Tag][]byte, error) {
	sfcw := bytes.NewBuffer([]byte{})
	utils.LittleEndian.WriteUint32(sfcw, uint32(protocol.ReceiveStreamFlowControlWindow))
	cfcw := bytes.NewBuffer([]byte{})
	utils.LittleEndian.WriteUint32(cfcw, uint32(protocol.ReceiveConnectionFlowControlWindow))
	mids := bytes.NewBuffer([]byte{})
	utils.LittleEndian.WriteUint32(mids, protocol.MaxIncomingStreams)
	icsl := bytes.NewBuffer([]byte{})
	utils.LittleEndian.WriteUint32(icsl, uint32(h.idleTimeout/time.Second))

	return map[Tag][]byte{
		TagICSL: icsl.Bytes(),
		TagMIDS: mids.Bytes(),
		TagCFCW: cfcw.Bytes(),
		TagSFCW: sfcw.Bytes(),
	}, nil
}

func (h *paramsNegotiatorGQUIC) OmitConnectionID() bool {
	if h.perspective == protocol.PerspectiveClient {
		return false
	}

	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.omitConnectionID
}
