package frames

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

const version = protocol.VersionTLS

// PrefixLen is the number of bytes used for configuration
const PrefixLen = 1

func toEncLevel(v uint8) protocol.EncryptionLevel {
	switch v % 3 {
	default:
		return protocol.EncryptionInitial
	case 1:
		return protocol.EncryptionHandshake
	case 2:
		return protocol.Encryption1RTT
	}
}

// Fuzz fuzzes the QUIC frames.
//
//go:generate go run ./cmd/corpus.go
func Fuzz(data []byte) int {
	if len(data) < PrefixLen {
		return 0
	}
	encLevel := toEncLevel(data[0])
	data = data[PrefixLen:]

	parser := wire.NewFrameParser(true)
	parser.SetAckDelayExponent(protocol.DefaultAckDelayExponent)

	initialLen := len(data)

	var frames []wire.Frame

	for len(data) > 0 {
		l, f, err := parser.ParseNext(data, encLevel, version)
		if err != nil {
			break
		}
		data = data[l:]
		frames = append(frames, f)
	}
	parsedLen := initialLen - len(data)

	if len(frames) == 0 {
		return 0
	}

	var b []byte
	for _, f := range frames {
		if f == nil { // PADDING frame
			b = append(b, 0)
			continue
		}
		// We accept empty STREAM frames, but we don't write them.
		if sf, ok := f.(*wire.StreamFrame); ok {
			if sf.DataLen() == 0 {
				sf.PutBack()
				continue
			}
		}
		lenBefore := len(b)
		b, err := f.Append(b, version)
		if err != nil {
			panic(fmt.Sprintf("Error writing frame %#v: %s", f, err))
		}
		frameLen := len(b) - lenBefore
		if f.Length(version) != protocol.ByteCount(frameLen) {
			panic(fmt.Sprintf("Inconsistent frame length for %#v: expected %d, got %d", f, frameLen, f.Length(version)))
		}
		if sf, ok := f.(*wire.StreamFrame); ok {
			sf.PutBack()
		}
	}
	if len(b) > parsedLen {
		panic(fmt.Sprintf("Serialized length (%d) is longer than parsed length (%d)", len(b), parsedLen))
	}
	return 1
}
