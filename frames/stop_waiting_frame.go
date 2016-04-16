package frames

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/utils"
)

// A StopWaitingFrame in QUIC
type StopWaitingFrame struct {
	Entropy           byte
	LeastUnackedDelta uint64
}

func (f *StopWaitingFrame) Write(b *bytes.Buffer) error {
	return errors.New("StopWaitingFrame: Write not yet implemented")
}

// ParseStopWaitingFrame parses a StopWaiting frame
func ParseStopWaitingFrame(r *bytes.Reader, packetNumberLen uint8) (*StopWaitingFrame, error) {
	frame := &StopWaitingFrame{}

	// read the TypeByte
	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.Entropy, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.LeastUnackedDelta, err = utils.ReadUintN(r, packetNumberLen)
	if err != nil {
		return nil, err
	}

	return frame, nil
}
