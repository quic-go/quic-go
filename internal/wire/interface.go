package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A Frame in QUIC
type Frame interface {
	Write(b []byte, version protocol.VersionNumber) ([]byte, error)
	Length(version protocol.VersionNumber) protocol.ByteCount
}

// A FrameParser parses QUIC frames, one by one.
type FrameParser interface {
	ParseNext(*bytes.Reader, protocol.EncryptionLevel) (Frame, error)
	SetAckDelayExponent(uint8)
}
