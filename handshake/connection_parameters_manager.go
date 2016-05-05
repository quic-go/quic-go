package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/lucas-clemente/quic-go/protocol"
)

// ConnectionParametersManager stores the connection parameters
type ConnectionParametersManager struct {
	params map[Tag][]byte
	// TODO: We can probably remove this mutex.
	mutex sync.RWMutex
}

// ErrTagNotInConnectionParameterMap is returned when a tag is not present in the connection parameters
var ErrTagNotInConnectionParameterMap = errors.New("Tag not found in ConnectionsParameter map")

// NewConnectionParamatersManager creates a new connection parameters manager
func NewConnectionParamatersManager() *ConnectionParametersManager {
	return &ConnectionParametersManager{
		params: map[Tag][]byte{
			TagSFCW: {0x0, 0x40, 0x0, 0x0},    // Stream Flow Control Window
			TagCFCW: {0x0, 0x40, 0x0, 0x0},    // Connection Flow Control Window
			TagICSL: {0x1e, 0x00, 0x00, 0x00}, // idle connection state lifetime = 30s
			TagMSPC: {0x64, 0x00, 0x00, 0x00}, // Max streams per connection = 100
		},
	}
}

// SetFromMap reads all params
func (h *ConnectionParametersManager) SetFromMap(params map[Tag][]byte) error {
	h.mutex.Lock()
	for key, value := range params {
		h.params[key] = value
	}
	h.mutex.Unlock()
	return nil
}

// GetRawValue gets the byte-slice for a tag
func (h *ConnectionParametersManager) GetRawValue(tag Tag) ([]byte, error) {
	h.mutex.RLock()
	rawValue, ok := h.params[tag]
	h.mutex.RUnlock()

	if !ok {
		return nil, ErrTagNotInConnectionParameterMap
	}
	return rawValue, nil
}

// GetSHLOMap gets all values (except crypto values) needed for the SHLO
func (h *ConnectionParametersManager) GetSHLOMap() map[Tag][]byte {
	// TODO: This races.
	return h.params
}

// GetStreamFlowControlWindow gets the size of the stream-level flow control window
func (h *ConnectionParametersManager) GetStreamFlowControlWindow() (protocol.ByteCount, error) {
	rawValue, err := h.GetRawValue(TagSFCW)

	if err != nil {
		return 0, err
	}

	var value uint32
	buf := bytes.NewBuffer(rawValue)
	err = binary.Read(buf, binary.LittleEndian, &value)
	if err != nil {
		return 0, err
	}

	return protocol.ByteCount(value), nil
}
