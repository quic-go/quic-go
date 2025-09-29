package qlog

import (
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlogwriter"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

// BenchmarkConnectionTracing aims to benchmark a somewhat realistic connection that sends and receives packets.
func BenchmarkConnectionTracing(b *testing.B) {
	b.ReportAllocs()

	srcConnID := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})
	trace := qlogwriter.NewConnectionFileSeq(
		nopWriteCloser(io.Discard),
		false,
		protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
	)
	go trace.Run()
	tracer := trace.AddProducer()
	b.Cleanup(func() { tracer.Close() })

	var rttStats utils.RTTStats
	rttStats.UpdateRTT(1337*time.Millisecond, 0)
	rttStats.UpdateRTT(1000*time.Millisecond, 10*time.Millisecond)
	rttStats.UpdateRTT(800*time.Millisecond, 100*time.Millisecond)

	var i int
	for b.Loop() {
		i++
		tracer.RecordEvent(&PacketSent{
			Header: PacketHeader{
				PacketType:       PacketType1RTT,
				PacketNumber:     1234 + protocol.PacketNumber(i),
				KeyPhaseBit:      KeyPhaseZero,
				DestConnectionID: srcConnID,
			},
			Raw: RawInfo{Length: 1337},
			ECN: ECT0,
			Frames: []Frame{
				{Frame: &AckFrame{AckRanges: []wire.AckRange{{Largest: 12345 + protocol.PacketNumber(2*i), Smallest: 1234 + protocol.PacketNumber(i)}}}},
				{Frame: &MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987 + protocol.ByteCount(i)}},
			},
		})

		minRTT := rttStats.MinRTT()
		smoothedRTT := rttStats.SmoothedRTT()
		latestRTT := rttStats.LatestRTT()
		rttVariance := rttStats.MeanDeviation()
		cwndInt := int(12345 + protocol.ByteCount(2*i))
		bytesInt := int(12345 + protocol.ByteCount(i))
		tracer.RecordEvent(&MetricsUpdated{
			MinRTT:           &minRTT,
			SmoothedRTT:      &smoothedRTT,
			LatestRTT:        &latestRTT,
			RTTVariance:      &rttVariance,
			CongestionWindow: &cwndInt,
			BytesInFlight:    &bytesInt,
			PacketsInFlight:  &i,
		})

		if i%2 == 0 {
			tracer.RecordEvent(&PacketReceived{
				Header: PacketHeader{
					PacketType:       PacketType1RTT,
					PacketNumber:     1337 + protocol.PacketNumber(i),
					KeyPhaseBit:      KeyPhaseOne,
					DestConnectionID: srcConnID,
				},
				Raw: RawInfo{Length: 1337},
				ECN: ECT0,
				Frames: []Frame{
					{Frame: &StreamFrame{StreamID: 123, Offset: int64(1234 + protocol.ByteCount(100*i)), Length: 100, Fin: true}},
				},
			})
		}
	}
}
