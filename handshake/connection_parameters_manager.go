package handshake

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// ConnectionParametersManager stores the connection parameters
// Warning: Writes may only be done from the crypto stream, see the comment
// in GetSHLOMap().
type ConnectionParametersManager struct {
	mutex sync.RWMutex

	version protocol.VersionNumber

	flowControlNegotiated                bool
	hasReceivedMaxIncomingDynamicStreams bool

	truncateConnectionID                   bool
	maxStreamsPerConnection                uint32
	maxIncomingDynamicStreamsPerConnection uint32
	idleConnectionStateLifetime            time.Duration
	sendStreamFlowControlWindow            protocol.ByteCount
	sendConnectionFlowControlWindow        protocol.ByteCount
	receiveStreamFlowControlWindow         protocol.ByteCount
	receiveConnectionFlowControlWindow     protocol.ByteCount
}

var errTagNotInConnectionParameterMap = errors.New("ConnectionParametersManager: Tag not found in ConnectionsParameter map")

// ErrMalformedTag is returned when the tag value cannot be read
var (
	ErrMalformedTag                         = qerr.Error(qerr.InvalidCryptoMessageParameter, "malformed Tag value")
	ErrFlowControlRenegotiationNotSupported = qerr.Error(qerr.InvalidCryptoMessageParameter, "renegotiation of flow control parameters not supported")
)

// NewConnectionParamatersManager creates a new connection parameters manager
func NewConnectionParamatersManager(v protocol.VersionNumber) *ConnectionParametersManager {
	return &ConnectionParametersManager{
		version:                                v,
		idleConnectionStateLifetime:            protocol.DefaultIdleTimeout,
		sendStreamFlowControlWindow:            protocol.InitialStreamFlowControlWindow,     // can only be changed by the client
		sendConnectionFlowControlWindow:        protocol.InitialConnectionFlowControlWindow, // can only be changed by the client
		receiveStreamFlowControlWindow:         protocol.ReceiveStreamFlowControlWindow,
		receiveConnectionFlowControlWindow:     protocol.ReceiveConnectionFlowControlWindow,
		maxStreamsPerConnection:                protocol.MaxStreamsPerConnection, // this is the value negotiated based on what the client sent
		maxIncomingDynamicStreamsPerConnection: protocol.MaxStreamsPerConnection, // "incoming" seen from the client's perspective
	}
}

// SetFromMap reads all params
func (h *ConnectionParametersManager) SetFromMap(params map[Tag][]byte) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for key, value := range params {
		switch key {
		case TagTCID:
			clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.truncateConnectionID = (clientValue == 0)
		case TagMSPC:
			clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.maxStreamsPerConnection = h.negotiateMaxStreamsPerConnection(clientValue)
		case TagMIDS:
			clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.maxIncomingDynamicStreamsPerConnection = h.negotiateMaxIncomingDynamicStreamsPerConnection(clientValue)
			h.hasReceivedMaxIncomingDynamicStreams = true
		case TagICSL:
			clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.idleConnectionStateLifetime = h.negotiateIdleConnectionStateLifetime(time.Duration(clientValue) * time.Second)
		case TagSFCW:
			if h.flowControlNegotiated {
				return ErrFlowControlRenegotiationNotSupported
			}
			sendStreamFlowControlWindow, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.sendStreamFlowControlWindow = protocol.ByteCount(sendStreamFlowControlWindow)
		case TagCFCW:
			if h.flowControlNegotiated {
				return ErrFlowControlRenegotiationNotSupported
			}
			sendConnectionFlowControlWindow, err := utils.ReadUint32(bytes.NewBuffer(value))
			if err != nil {
				return ErrMalformedTag
			}
			h.sendConnectionFlowControlWindow = protocol.ByteCount(sendConnectionFlowControlWindow)
		}
	}

	_, containsSFCW := params[TagSFCW]
	_, containsCFCW := params[TagCFCW]
	if containsCFCW || containsSFCW {
		h.flowControlNegotiated = true
	}

	return nil
}

func (h *ConnectionParametersManager) negotiateMaxStreamsPerConnection(clientValue uint32) uint32 {
	return utils.MinUint32(clientValue, protocol.MaxStreamsPerConnection)
}

func (h *ConnectionParametersManager) negotiateMaxIncomingDynamicStreamsPerConnection(clientValue uint32) uint32 {
	return utils.MinUint32(clientValue, protocol.MaxIncomingDynamicStreamsPerConnection)
}

func (h *ConnectionParametersManager) negotiateIdleConnectionStateLifetime(clientValue time.Duration) time.Duration {
	return utils.MinDuration(clientValue, protocol.MaxIdleTimeout)
}

// GetSHLOMap gets all values (except crypto values) needed for the SHLO
func (h *ConnectionParametersManager) GetSHLOMap() map[Tag][]byte {
	sfcw := bytes.NewBuffer([]byte{})
	utils.WriteUint32(sfcw, uint32(h.GetReceiveStreamFlowControlWindow()))
	cfcw := bytes.NewBuffer([]byte{})
	utils.WriteUint32(cfcw, uint32(h.GetReceiveConnectionFlowControlWindow()))
	mspc := bytes.NewBuffer([]byte{})
	utils.WriteUint32(mspc, h.maxStreamsPerConnection)
	icsl := bytes.NewBuffer([]byte{})
	utils.WriteUint32(icsl, uint32(h.GetIdleConnectionStateLifetime()/time.Second))

	tags := map[Tag][]byte{
		TagICSL: icsl.Bytes(),
		TagMSPC: mspc.Bytes(),
		TagCFCW: cfcw.Bytes(),
		TagSFCW: sfcw.Bytes(),
	}

	if h.version > protocol.Version34 {
		mids := bytes.NewBuffer([]byte{})
		utils.WriteUint32(mids, protocol.MaxIncomingDynamicStreamsPerConnection)
		tags[TagMIDS] = mids.Bytes()
	}

	return tags
}

// GetSendStreamFlowControlWindow gets the size of the stream-level flow control window for sending data
func (h *ConnectionParametersManager) GetSendStreamFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.sendStreamFlowControlWindow
}

// GetSendConnectionFlowControlWindow gets the size of the stream-level flow control window for sending data
func (h *ConnectionParametersManager) GetSendConnectionFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.sendConnectionFlowControlWindow
}

// GetReceiveStreamFlowControlWindow gets the size of the stream-level flow control window for receiving data
func (h *ConnectionParametersManager) GetReceiveStreamFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.receiveStreamFlowControlWindow
}

// GetReceiveConnectionFlowControlWindow gets the size of the stream-level flow control window for receiving data
func (h *ConnectionParametersManager) GetReceiveConnectionFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.receiveConnectionFlowControlWindow
}

// GetMaxOutgoingStreams gets the maximum number of outgoing streams per connection
func (h *ConnectionParametersManager) GetMaxOutgoingStreams() uint32 {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.version > protocol.Version34 && h.hasReceivedMaxIncomingDynamicStreams {
		return h.maxIncomingDynamicStreamsPerConnection
	}
	return h.maxStreamsPerConnection
}

// GetMaxIncomingStreams get the maximum number of incoming streams per connection
func (h *ConnectionParametersManager) GetMaxIncomingStreams() uint32 {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	var val uint32
	if h.version <= protocol.Version34 {
		val = h.maxStreamsPerConnection
	} else {
		val = protocol.MaxIncomingDynamicStreamsPerConnection
	}

	return utils.MaxUint32(val+protocol.MaxStreamsMinimumIncrement, uint32(float64(val)*protocol.MaxStreamsMultiplier))
}

// GetIdleConnectionStateLifetime gets the idle timeout
func (h *ConnectionParametersManager) GetIdleConnectionStateLifetime() time.Duration {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.idleConnectionStateLifetime
}

// TruncateConnectionID determines if the client requests truncated ConnectionIDs
func (h *ConnectionParametersManager) TruncateConnectionID() bool {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.truncateConnectionID
}
