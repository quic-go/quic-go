package protocol

import (
	"bytes"
	"crypto/rand"
)

// A ConnectionID in QUIC
type ConnectionID []byte

// GenerateConnectionID generates a connection ID using cryptographic random
func GenerateConnectionID() (ConnectionID, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return ConnectionID(b), nil
}

// Equal says if two connection IDs are equal
func (c ConnectionID) Equal(other ConnectionID) bool {
	return bytes.Equal(c, other)
}
