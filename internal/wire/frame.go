package wire

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A Frame in QUIC
type Frame interface {
	Write(b utils.ByteWriter, version protocol.VersionNumber) error
	Length(version protocol.VersionNumber) protocol.ByteCount
}
