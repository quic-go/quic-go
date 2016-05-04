package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
)

// A PingFrame is a ping frame
type PingFrame struct{}

// ParsePingFrame parses a Ping frame
func ParsePingFrame(r *bytes.Reader) (*PingFrame, error) {
	frame := &PingFrame{}

	_, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	return frame, nil
}

func (f *PingFrame) Write(b *bytes.Buffer, packetNumber protocol.PacketNumber, packetNumberLen uint8) error {
	typeByte := uint8(0x07)
	b.WriteByte(typeByte)
	return nil
}

// MinLength of a written frame
func (f *PingFrame) MinLength() int {
	return 1
}
