package frames

import (
	"bytes"
	"errors"
	"math"

	"github.com/lucas-clemente/quic-go/utils"
)

// A ConnectionCloseFrame in QUIC
type ConnectionCloseFrame struct {
	ErrorCode    uint32
	ReasonPhrase string
}

// ParseConnectionCloseFrame reads a CONNECTION_CLOSE frame
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

// Write writes an CONNECTION_CLOSE frame.
func (f *ConnectionCloseFrame) Write(b *bytes.Buffer) error {
	b.WriteByte(0x02)
	utils.WriteUint32(b, f.ErrorCode)

	if len(f.ReasonPhrase) > math.MaxUint16 {
		return errors.New("ConnectionFrame: ReasonPhrase too long")
	}

	reasonPhraseLen := uint16(len(f.ReasonPhrase))
	utils.WriteUint16(b, reasonPhraseLen)

	for i := 0; i < int(reasonPhraseLen); i++ {
		b.WriteByte(uint8(f.ReasonPhrase[i]))
	}

	return nil
}
