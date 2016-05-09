package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
)

// A Frame in QUIC
type Frame interface {
	Write(b *bytes.Buffer, packetNumber protocol.PacketNumber, packetNumberLen protocol.PacketNumberLen, version protocol.VersionNumber) error
	MinLength() int
}
