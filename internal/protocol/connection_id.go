package protocol

import (
	"crypto/rand"
	"encoding/binary"
)

// A ConnectionID in QUIC
type ConnectionID uint64

// GenerateConnectionID generates a connection ID using cryptographic random
func GenerateConnectionID() (ConnectionID, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return ConnectionID(binary.LittleEndian.Uint64(b)), nil
}
