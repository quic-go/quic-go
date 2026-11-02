//go:build !race

// The race detector allocates, so allocation counts are only meaningful without it.

package wire

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestFrameParserAllocs(t *testing.T) {
	t.Run("STREAM", func(t *testing.T) {
		var frames []Frame
		for i := range 10 {
			frames = append(frames, &StreamFrame{
				StreamID:       protocol.StreamID(1337 + i),
				Offset:         protocol.ByteCount(1e7 + i),
				Data:           make([]byte, 200+i),
				DataLenPresent: true,
			})
		}
		require.Zero(t, testFrameParserAllocs(t, frames))
	})

	t.Run("ACK", func(t *testing.T) {
		var frames []Frame
		for i := range 10 {
			frames = append(frames, &AckFrame{
				AckRanges: []AckRange{
					{Smallest: protocol.PacketNumber(5000 + i), Largest: protocol.PacketNumber(5200 + i)},
					{Smallest: protocol.PacketNumber(1 + i), Largest: protocol.PacketNumber(4200 + i)},
				},
				DelayTime: time.Duration(int64(time.Millisecond) * int64(i)),
				ECT0:      uint64(5000 + i),
				ECT1:      uint64(i),
				ECNCE:     uint64(10 + i),
			})
		}
		require.Zero(t, testFrameParserAllocs(t, frames))
	})
}

func testFrameParserAllocs(t *testing.T, frames []Frame) float64 {
	buf := writeFrames(t, frames...)
	parser := NewFrameParser(true, true, true)
	parser.SetAckDelayExponent(3)

	return testing.AllocsPerRun(100, func() {
		parseFrames(t, parser, buf, frames...)
	})
}
