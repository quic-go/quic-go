package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
)

// A Frame in QUIC
type Frame interface {
	Write(b *bytes.Buffer, packetNumber protocol.PacketNumber, packetNumberLen uint8) error
	MaxLength() int
}
