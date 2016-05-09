package frames

import (
	"bytes"
	"errors"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// A StopWaitingFrame in QUIC
type StopWaitingFrame struct {
	Entropy      byte
	LeastUnacked protocol.PacketNumber
}

func (f *StopWaitingFrame) Write(b *bytes.Buffer, packetNumber protocol.PacketNumber, packetNumberLen protocol.PacketNumberLen, version protocol.VersionNumber) error {
	// packetNumber is the packet number of the packet that this StopWaitingFrame will be sent with
	typeByte := uint8(0x06)
	b.WriteByte(typeByte)

	b.WriteByte(f.Entropy)

	if f.LeastUnacked > packetNumber {
		return errors.New("StopWaitingFrame: LeastUnacked can't be greater than the packet number")
	}
	leastUnackedDelta := uint64(packetNumber - f.LeastUnacked)

	utils.WriteUint48(b, leastUnackedDelta)
	return nil
}

// MinLength of a written frame
func (f *StopWaitingFrame) MinLength() int {
	return 1 + 1 + 6
}

// ParseStopWaitingFrame parses a StopWaiting frame
func ParseStopWaitingFrame(r *bytes.Reader, packetNumber protocol.PacketNumber, packetNumberLen protocol.PacketNumberLen) (*StopWaitingFrame, error) {
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

	leastUnackedDelta, err := utils.ReadUintN(r, uint8(packetNumberLen))
	if err != nil {
		return nil, err
	}

	if leastUnackedDelta > uint64(packetNumber) {
		return nil, errors.New("StopWaitingFrame: Invalid LeastUnackedDelta")
	}

	frame.LeastUnacked = protocol.PacketNumber(uint64(packetNumber) - leastUnackedDelta)

	return frame, nil
}
