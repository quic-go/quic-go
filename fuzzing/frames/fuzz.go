package frames

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

const version = protocol.Version1

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

	var numFrames int
	var b []byte
	for len(data) > 0 {
		initialLen := len(data)
		l, f, err := parser.ParseNext(data, encLevel, version)
		if err != nil {
			break
		}
		data = data[l:]
		numFrames++
		if f == nil { // PADDING frame
			continue
		}
		wire.IsProbingFrame(f)
		ackhandler.IsFrameAckEliciting(f)
		// We accept empty STREAM frames, but we don't write them.
		if sf, ok := f.(*wire.StreamFrame); ok {
			if sf.DataLen() == 0 {
				sf.PutBack()
				continue
			}
		}
		validateFrame(f)

		startLen := len(b)
		parsedLen := initialLen - len(data)
		b, err = f.Append(b, version)
		if err != nil {
			panic(fmt.Sprintf("error writing frame %#v: %s", f, err))
		}
		frameLen := protocol.ByteCount(len(b) - startLen)
		if f.Length(version) != frameLen {
			panic(fmt.Sprintf("inconsistent frame length for %#v: expected %d, got %d", f, frameLen, f.Length(version)))
		}
		if sf, ok := f.(*wire.StreamFrame); ok {
			sf.PutBack()
		}
		if frameLen > protocol.ByteCount(parsedLen) {
			panic(fmt.Sprintf("serialized length (%d) is longer than parsed length (%d)", len(b), parsedLen))
		}
	}

	if numFrames == 0 {
		return 0
	}
	return 1
}

func validateFrame(frame wire.Frame) {
	switch f := frame.(type) {
	case *wire.StreamFrame:
		if protocol.ByteCount(len(f.Data)) != f.DataLen() {
			panic("STREAM frame: inconsistent data length")
		}
	case *wire.AckFrame:
		if f.DelayTime < 0 {
			panic(fmt.Sprintf("invalid ACK delay_time: %s", f.DelayTime))
		}
		if f.LargestAcked() < f.LowestAcked() {
			panic("ACK: largest acknowledged is smaller than lowest acknowledged")
		}
		for _, r := range f.AckRanges {
			if r.Largest < 0 || r.Smallest < 0 {
				panic("ACK range contains a negative packet number")
			}
		}
		if !f.AcksPacket(f.LargestAcked()) {
			panic("ACK frame claims that largest acknowledged is not acknowledged")
		}
		if !f.AcksPacket(f.LowestAcked()) {
			panic("ACK frame claims that lowest acknowledged is not acknowledged")
		}
		_ = f.AcksPacket(100)
		_ = f.AcksPacket((f.LargestAcked() + f.LowestAcked()) / 2)
	case *wire.NewConnectionIDFrame:
		if f.ConnectionID.Len() < 1 || f.ConnectionID.Len() > 20 {
			panic(fmt.Sprintf("invalid NEW_CONNECTION_ID frame length: %s", f.ConnectionID))
		}
	case *wire.NewTokenFrame:
		if len(f.Token) == 0 {
			panic("NEW_TOKEN frame with an empty token")
		}
	case *wire.MaxStreamsFrame:
		if f.MaxStreamNum > protocol.MaxStreamCount {
			panic("MAX_STREAMS frame with an invalid Maximum Streams value")
		}
	case *wire.StreamsBlockedFrame:
		if f.StreamLimit > protocol.MaxStreamCount {
			panic("STREAMS_BLOCKED frame with an invalid Maximum Streams value")
		}
	case *wire.ConnectionCloseFrame:
		if f.IsApplicationError && f.FrameType != 0 {
			panic("CONNECTION_CLOSE for an application error containing a frame type")
		}
	}
}
