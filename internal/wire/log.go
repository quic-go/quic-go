package wire

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/quic-go/quic-go/internal/protocol"
)

// LogFrame logs a frame, either sent or received
func LogFrame(logger *slog.Logger, frame Frame, sent bool) {
	if !logger.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	dir := "<-"
	if sent {
		dir = "->"
	}
	switch f := frame.(type) {
	case *CryptoFrame:
		dataLen := protocol.ByteCount(len(f.Data))
		logger.Debug(dir+" CryptoFrame",
			"offset", f.Offset,
			"data_len", dataLen,
			"end_offset", f.Offset+dataLen,
		)
	case *StreamFrame:
		logger.Debug(dir+" StreamFrame",
			"stream_id", f.StreamID,
			"fin", f.Fin,
			"offset", f.Offset,
			"data_len", f.DataLen(),
			"end_offset", f.Offset+f.DataLen(),
		)
	case *ResetStreamFrame:
		logger.Debug(dir+" ResetStreamFrame",
			"stream_id", f.StreamID,
			"error_code", fmt.Sprintf("%#x", f.ErrorCode),
			"final_size", f.FinalSize,
		)
	case *AckFrame:
		hasECN := f.ECT0 > 0 || f.ECT1 > 0 || f.ECNCE > 0
		if len(f.AckRanges) > 1 {
			ackRanges := make([]string, len(f.AckRanges))
			for i, r := range f.AckRanges {
				ackRanges[i] = fmt.Sprintf("{Largest: %d, Smallest: %d}", r.Largest, r.Smallest)
			}
			if hasECN {
				logger.Debug(dir+" AckFrame",
					"largest_acked", f.LargestAcked(),
					"lowest_acked", f.LowestAcked(),
					"ack_ranges", strings.Join(ackRanges, ", "),
					"delay_time", f.DelayTime.String(),
					"ect0", f.ECT0,
					"ect1", f.ECT1,
					"ce", f.ECNCE,
				)
			} else {
				logger.Debug(dir+" AckFrame",
					"largest_acked", f.LargestAcked(),
					"lowest_acked", f.LowestAcked(),
					"ack_ranges", strings.Join(ackRanges, ", "),
					"delay_time", f.DelayTime.String(),
				)
			}
		} else {
			if hasECN {
				logger.Debug(dir+" AckFrame",
					"largest_acked", f.LargestAcked(),
					"lowest_acked", f.LowestAcked(),
					"delay_time", f.DelayTime.String(),
					"ect0", f.ECT0,
					"ect1", f.ECT1,
					"ce", f.ECNCE,
				)
			} else {
				logger.Debug(dir+" AckFrame",
					"largest_acked", f.LargestAcked(),
					"lowest_acked", f.LowestAcked(),
					"delay_time", f.DelayTime.String(),
				)
			}
		}
	case *MaxDataFrame:
		logger.Debug(dir+" MaxDataFrame", "max_data", f.MaximumData)
	case *MaxStreamDataFrame:
		logger.Debug(dir+" MaxStreamDataFrame",
			"stream_id", f.StreamID,
			"max_stream_data", f.MaximumStreamData,
		)
	case *DataBlockedFrame:
		logger.Debug(dir+" DataBlockedFrame", "max_data", f.MaximumData)
	case *StreamDataBlockedFrame:
		logger.Debug(dir+" StreamDataBlockedFrame",
			"stream_id", f.StreamID,
			"max_stream_data", f.MaximumStreamData,
		)
	case *MaxStreamsFrame:
		switch f.Type {
		case protocol.StreamTypeUni:
			logger.Debug(dir+" MaxStreamsFrame", "type", "uni", "max_stream_num", f.MaxStreamNum)
		case protocol.StreamTypeBidi:
			logger.Debug(dir+" MaxStreamsFrame", "type", "bidi", "max_stream_num", f.MaxStreamNum)
		}
	case *StreamsBlockedFrame:
		switch f.Type {
		case protocol.StreamTypeUni:
			logger.Debug(dir+" StreamsBlockedFrame", "type", "uni", "max_streams", f.StreamLimit)
		case protocol.StreamTypeBidi:
			logger.Debug(dir+" StreamsBlockedFrame", "type", "bidi", "max_streams", f.StreamLimit)
		}
	case *NewConnectionIDFrame:
		logger.Debug(dir+" NewConnectionIDFrame",
			"seq_num", f.SequenceNumber,
			"retire_prior_to", f.RetirePriorTo,
			"conn_id", f.ConnectionID,
			"stateless_reset_token", fmt.Sprintf("%#x", f.StatelessResetToken),
		)
	case *RetireConnectionIDFrame:
		logger.Debug(dir+" RetireConnectionIDFrame", "seq_num", f.SequenceNumber)
	case *NewTokenFrame:
		logger.Debug(dir+" NewTokenFrame", "token", fmt.Sprintf("%#x", f.Token))
	default:
		logger.Debug(dir+" Frame", "frame", fmt.Sprintf("%#v", frame))
	}
}
