package crypto

import "io"

// An AEAD implements QUIC's authenticated encryption and associated data
type AEAD interface {
	Open(associatedData []byte, ciphertext io.Reader) (io.Reader, error)
}
