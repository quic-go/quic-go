package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/utils"
)

// An AckFrame in QUIC
type AckFrame struct {
	Entropy         byte
	LargestObserved uint32 // TODO: change to uint64
}

// WriteAckFrame writes an ack frame.
func (f *AckFrame) Write(b *bytes.Buffer) error {
	typeByte := uint8(0x48)
	b.WriteByte(typeByte)
	b.WriteByte(f.Entropy)
	utils.WriteUint32(b, f.LargestObserved)
	utils.WriteUint16(b, 1) // TODO: Ack delay time
	b.WriteByte(0x01)       // Just one timestamp
	b.WriteByte(0x00)       // Largest observed
	utils.WriteUint32(b, 0) // First timestamp
	return nil
}
