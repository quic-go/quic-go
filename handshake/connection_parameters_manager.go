package handshake

import (
	"errors"
	"sync"
)

// ConnectionParametersManager stores the connection parameters
type ConnectionParametersManager struct {
	params map[Tag][]byte
	mutex  sync.RWMutex
}

// ErrTagNotInConnectionParameterMap is returned when a tag is not present in the connection parameters
var ErrTagNotInConnectionParameterMap = errors.New("Tag not found in ConnectionsParameter map")

// NewConnectionParamatersManager creates a new connection parameters manager
func NewConnectionParamatersManager() *ConnectionParametersManager {
	cpm := &ConnectionParametersManager{
		params: make(map[Tag][]byte),
	}
	return cpm
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
	return map[Tag][]byte{
		TagICSL: []byte{0x1e, 0x00, 0x00, 0x00}, //30
		TagMSPC: []byte{0x64, 0x00, 0x00, 0x00}, //100
	}
}
