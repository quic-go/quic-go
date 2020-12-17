package frames

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
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
//go:generate go run ./cmd/corpus.go
func Fuzz(data []byte) int {
	if len(data) < PrefixLen {
		return 0
	}
	encLevel := toEncLevel(data[0])
	data = data[PrefixLen:]

	parser := wire.NewFrameParser(true, version)
	parser.SetAckDelayExponent(protocol.DefaultAckDelayExponent)

	r := bytes.NewReader(data)
	initialLen := r.Len()

	var frames []wire.Frame

	for r.Len() > 0 {
		f, err := parser.ParseNext(r, encLevel)
		if err != nil {
			break
		}
		frames = append(frames, f)
	}
	parsedLen := initialLen - r.Len()

	if len(frames) == 0 {
		return 0
	}

	b := &bytes.Buffer{}
	for _, f := range frames {
		if f == nil { // PADDING frame
			b.WriteByte(0x0)
			continue
		}
		// We accept empty STREAM frames, but we don't write them.
		if sf, ok := f.(*wire.StreamFrame); ok {
			if sf.DataLen() == 0 {
				sf.PutBack()
				continue
			}
		}
		lenBefore := b.Len()
		if err := f.Write(b, version); err != nil {
			panic(fmt.Sprintf("Error writing frame %#v: %s", f, err))
		}
		frameLen := b.Len() - lenBefore
		if f.Length(version) != protocol.ByteCount(frameLen) {
			panic(fmt.Sprintf("Inconsistent frame length for %#v: expected %d, got %d", f, frameLen, f.Length(version)))
		}
		if sf, ok := f.(*wire.StreamFrame); ok {
			sf.PutBack()
		}
	}
	if b.Len() > parsedLen {
		panic(fmt.Sprintf("Serialized length (%d) is longer than parsed length (%d)", b.Len(), parsedLen))
	}
	return 1
}
