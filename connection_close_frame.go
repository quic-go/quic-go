package quic

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/utils"
)

// A ConnectionCloseFrame in QUIC
type ConnectionCloseFrame struct {
	ErrorCode    uint32
	ReasonPhrase string
}

// Write writes an ACK frame.
func (f *ConnectionCloseFrame) Write(b *bytes.Buffer) error {
	return errors.New("ConnectionCloseFrame: Write not yet implemented")
}

// ParseConnectionCloseFrame reads an ACK frame
func ParseConnectionCloseFrame(r *bytes.Reader) (*ConnectionCloseFrame, error) {
	frame := &ConnectionCloseFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.ErrorCode, err = utils.ReadUint32(r)
	if err != nil {
		return nil, err
	}

	reasonPhraseLen, err := utils.ReadUint16(r)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(reasonPhraseLen); i++ {
		val, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		frame.ReasonPhrase += string(val)
	}

	return frame, nil
}
