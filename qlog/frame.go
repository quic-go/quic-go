package qlog

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/quic-go/json/jsontext"
)

type frame struct {
	Frame logging.Frame
}

func (f frame) Encode(enc *jsontext.Encoder) error {
	switch frame := f.Frame.(type) {
	case *logging.PingFrame:
		return encodePingFrame(enc, frame)
	case *logging.AckFrame:
		return encodeAckFrame(enc, frame)
	case *logging.ResetStreamFrame:
		return encodeResetStreamFrame(enc, frame)
	case *logging.StopSendingFrame:
		return encodeStopSendingFrame(enc, frame)
	case *logging.CryptoFrame:
		return encodeCryptoFrame(enc, frame)
	case *logging.NewTokenFrame:
		return encodeNewTokenFrame(enc, frame)
	case *logging.StreamFrame:
		return encodeStreamFrame(enc, frame)
	case *logging.MaxDataFrame:
		return encodeMaxDataFrame(enc, frame)
	case *logging.MaxStreamDataFrame:
		return encodeMaxStreamDataFrame(enc, frame)
	case *logging.MaxStreamsFrame:
		return encodeMaxStreamsFrame(enc, frame)
	case *logging.DataBlockedFrame:
		return encodeDataBlockedFrame(enc, frame)
	case *logging.StreamDataBlockedFrame:
		return encodeStreamDataBlockedFrame(enc, frame)
	case *logging.StreamsBlockedFrame:
		return encodeStreamsBlockedFrame(enc, frame)
	case *logging.NewConnectionIDFrame:
		return encodeNewConnectionIDFrame(enc, frame)
	case *logging.RetireConnectionIDFrame:
		return encodeRetireConnectionIDFrame(enc, frame)
	case *logging.PathChallengeFrame:
		return encodePathChallengeFrame(enc, frame)
	case *logging.PathResponseFrame:
		return encodePathResponseFrame(enc, frame)
	case *logging.ConnectionCloseFrame:
		return encodeConnectionCloseFrame(enc, frame)
	case *logging.HandshakeDoneFrame:
		return encodeHandshakeDoneFrame(enc, frame)
	case *logging.DatagramFrame:
		return encodeDatagramFrame(enc, frame)
	case *logging.AckFrequencyFrame:
		return encodeAckFrequencyFrame(enc, frame)
	case *logging.ImmediateAckFrame:
		return encodeImmediateAckFrame(enc, frame)
	default:
		panic("unknown frame type")
	}
}

type frames []frame

func (fs frames) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginArray); err != nil {
		return err
	}
	for _, f := range fs {
		if err := f.Encode(enc); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndArray)
}

func encodePingFrame(enc *jsontext.Encoder, _ *logging.PingFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("ping")); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type ackRanges []wire.AckRange

func (ars ackRanges) encodeArray(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginArray); err != nil {
		return err
	}
	for _, r := range ars {
		if err := ackRange(r).Encode(enc); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.EndArray); err != nil {
		return err
	}
	return nil
}

type ackRange wire.AckRange

func (ar ackRange) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginArray); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(ar.Smallest))); err != nil {
		return err
	}
	if ar.Smallest != ar.Largest {
		if err := enc.WriteToken(jsontext.Int(int64(ar.Largest))); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.EndArray); err != nil {
		return err
	}
	return nil
}

func encodeAckFrame(enc *jsontext.Encoder, f *logging.AckFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("ack")); err != nil {
		return err
	}
	if f.DelayTime != 0 {
		if err := enc.WriteToken(jsontext.String("ack_delay")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Float(milliseconds(f.DelayTime))); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("acked_ranges")); err != nil {
		return err
	}
	if err := ackRanges(f.AckRanges).encodeArray(enc); err != nil {
		return err
	}
	hasECN := f.ECT0 > 0 || f.ECT1 > 0 || f.ECNCE > 0
	if hasECN {
		if err := enc.WriteToken(jsontext.String("ect0")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(f.ECT0)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("ect1")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(f.ECT1)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("ce")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(f.ECNCE)); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeResetStreamFrame(enc *jsontext.Encoder, f *logging.ResetStreamFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if f.ReliableSize > 0 {
		if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("reset_stream_at")); err != nil {
			return err
		}
	} else {
		if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("reset_stream")); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("stream_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.StreamID))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("error_code")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.ErrorCode))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("final_size")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.FinalSize))); err != nil {
		return err
	}
	if f.ReliableSize > 0 {
		if err := enc.WriteToken(jsontext.String("reliable_size")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(f.ReliableSize))); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeStopSendingFrame(enc *jsontext.Encoder, f *logging.StopSendingFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stop_sending")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stream_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.StreamID))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("error_code")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.ErrorCode))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeCryptoFrame(enc *jsontext.Encoder, f *logging.CryptoFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("crypto")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("offset")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.Offset))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("length")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.Length))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeNewTokenFrame(enc *jsontext.Encoder, f *logging.NewTokenFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("new_token")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("token")); err != nil {
		return err
	}
	if err := (token{Raw: f.Token}).Encode(enc); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeStreamFrame(enc *jsontext.Encoder, f *logging.StreamFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stream")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stream_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.StreamID))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("offset")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.Offset))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("length")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.Length))); err != nil {
		return err
	}
	if f.Fin {
		if err := enc.WriteToken(jsontext.String("fin")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.True); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeMaxDataFrame(enc *jsontext.Encoder, f *logging.MaxDataFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("max_data")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("maximum")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.MaximumData))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeMaxStreamDataFrame(enc *jsontext.Encoder, f *logging.MaxStreamDataFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("max_stream_data")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stream_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.StreamID))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("maximum")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.MaximumStreamData))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeMaxStreamsFrame(enc *jsontext.Encoder, f *logging.MaxStreamsFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("max_streams")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stream_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(streamType(f.Type).String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("maximum")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.MaxStreamNum))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeDataBlockedFrame(enc *jsontext.Encoder, f *logging.DataBlockedFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("data_blocked")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("limit")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.MaximumData))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeStreamDataBlockedFrame(enc *jsontext.Encoder, f *logging.StreamDataBlockedFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stream_data_blocked")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stream_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.StreamID))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("limit")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.MaximumStreamData))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeStreamsBlockedFrame(enc *jsontext.Encoder, f *logging.StreamsBlockedFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("streams_blocked")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stream_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(streamType(f.Type).String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("limit")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.StreamLimit))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeNewConnectionIDFrame(enc *jsontext.Encoder, f *logging.NewConnectionIDFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("new_connection_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("sequence_number")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(f.SequenceNumber)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("retire_prior_to")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(f.RetirePriorTo)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("length")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(f.ConnectionID.Len()))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("connection_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(f.ConnectionID.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stateless_reset_token")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(fmt.Sprintf("%x", f.StatelessResetToken))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeRetireConnectionIDFrame(enc *jsontext.Encoder, f *logging.RetireConnectionIDFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("retire_connection_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("sequence_number")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(f.SequenceNumber)); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodePathChallengeFrame(enc *jsontext.Encoder, f *logging.PathChallengeFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("path_challenge")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("data")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(fmt.Sprintf("%x", f.Data[:]))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodePathResponseFrame(enc *jsontext.Encoder, f *logging.PathResponseFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("path_response")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("data")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(fmt.Sprintf("%x", f.Data[:]))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeConnectionCloseFrame(enc *jsontext.Encoder, f *logging.ConnectionCloseFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("connection_close")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("error_space")); err != nil {
		return err
	}
	errorSpace := "transport"
	if f.IsApplicationError {
		errorSpace = "application"
	}
	if err := enc.WriteToken(jsontext.String(errorSpace)); err != nil {
		return err
	}
	errName := transportError(f.ErrorCode).String()
	if len(errName) > 0 {
		if err := enc.WriteToken(jsontext.String("error_code")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(errName)); err != nil {
			return err
		}
	} else {
		if err := enc.WriteToken(jsontext.String("error_code")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(f.ErrorCode)); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("raw_error_code")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(f.ErrorCode)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("reason")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(f.ReasonPhrase)); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeHandshakeDoneFrame(enc *jsontext.Encoder, _ *logging.HandshakeDoneFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("handshake_done")); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeDatagramFrame(enc *jsontext.Encoder, f *logging.DatagramFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("datagram")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("length")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.Length))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeAckFrequencyFrame(enc *jsontext.Encoder, f *logging.AckFrequencyFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("ack_frequency")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("sequence_number")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(f.SequenceNumber)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("ack_eliciting_threshold")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(f.AckElicitingThreshold)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("request_max_ack_delay")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Float(milliseconds(f.RequestMaxAckDelay))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("reordering_threshold")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(f.ReorderingThreshold))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

func encodeImmediateAckFrame(enc *jsontext.Encoder, _ *logging.ImmediateAckFrame) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("frame_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("immediate_ack")); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}
