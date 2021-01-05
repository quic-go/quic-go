package qlog

import (
	"strconv"

	"github.com/lucas-clemente/quic-go/logging"
)

type ackFrame struct {
	FrameType string      `json:"frame_type"`
	AckDelay  float64     `json:"ack_delay"`
	AckRanges [][2]uint64 `json:"acked_ranges"`
}

func toAckFrame(ack *logging.AckFrame) *ackFrame {
	ranges := make([][2]uint64, 0, len(ack.AckRanges))
	for _, r := range ack.AckRanges {
		ranges = append(ranges, [2]uint64{uint64(r.Smallest), uint64(r.Largest)})
	}
	return &ackFrame{
		FrameType: "ack",
		AckDelay:  float64(ack.DelayTime.Microseconds()) / 1000,
		AckRanges: ranges,
	}
}

type streamFrame struct {
	FrameType string `json:"frame_type"`
	StreamID  uint64 `json:"stream_id"`
	Offset    uint64 `json:"offset"`
	Length    uint64 `json:"length"`
}

func toStreamFrame(sf *logging.StreamFrame) *streamFrame {
	return &streamFrame{
		FrameType: "stream_frame",
		StreamID:  uint64(sf.StreamID),
		Offset:    uint64(sf.Offset),
		Length:    uint64(sf.Length),
	}
}

func encodeAckFrame(b []byte, ack *logging.AckFrame) []byte {
	b = append(b, []byte(`{"frame_type":"ack","ack_delay:"`)...)
	b = strconv.AppendFloat(b, float64(ack.DelayTime.Microseconds())/1000, 'f', -1, 64)
	b = append(b, []byte(`,"acked_ranges":[`)...)
	var hasOne bool
	for _, r := range ack.AckRanges {
		if hasOne {
			b = append(b, ',')
		}
		b = append(b, '[')
		b = strconv.AppendInt(b, int64(r.Smallest), 10)
		b = append(b, ',')
		b = strconv.AppendInt(b, int64(r.Largest), 10)
		b = append(b, ']')
		hasOne = true
	}
	b = append(b, []byte("]}")...)
	return b
}
