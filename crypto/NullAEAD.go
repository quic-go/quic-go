package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
)

// NullAEAD handles not-yet encrypted packets
type NullAEAD struct{}

var _ AEAD = &NullAEAD{}

// Open and verify the ciphertext
func (*NullAEAD) Open(associatedData []byte, r io.Reader) (*bytes.Reader, error) {
	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < 12 {
		return nil, errors.New("NullAEAD: ciphertext cannot be less than 12 bytes long")
	}

	hash := New128a()
	hash.Write(associatedData)
	hash.Write(ciphertext[12:])
	testHigh, testLow := hash.Sum128()

	low := binary.LittleEndian.Uint64(ciphertext)
	high := binary.LittleEndian.Uint32(ciphertext[8:])

	if uint32(testHigh&0xffffffff) != high || testLow != low {
		return nil, errors.New("NullAEAD: failed to authenticate received data")
	}
	return bytes.NewReader(ciphertext[12:]), nil
}
