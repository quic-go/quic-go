package qlogevents

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog/jsontext"
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
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginArray)
	for _, f := range fs {
		if err := f.Encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndArray)
	return h.err
}

func encodePingFrame(enc *jsontext.Encoder, _ *logging.PingFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("ping"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ackRanges []wire.AckRange

func (ars ackRanges) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginArray)
	for _, r := range ars {
		if err := ackRange(r).Encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndArray)
	return h.err
}

type ackRange wire.AckRange

func (ar ackRange) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginArray)
	h.WriteToken(jsontext.Int(int64(ar.Smallest)))
	if ar.Smallest != ar.Largest {
		h.WriteToken(jsontext.Int(int64(ar.Largest)))
	}
	h.WriteToken(jsontext.EndArray)
	return h.err
}

func encodeAckFrame(enc *jsontext.Encoder, f *logging.AckFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("ack"))
	if f.DelayTime != 0 {
		h.WriteToken(jsontext.String("ack_delay"))
		h.WriteToken(jsontext.Float(milliseconds(f.DelayTime)))
	}
	h.WriteToken(jsontext.String("acked_ranges"))
	if err := ackRanges(f.AckRanges).Encode(enc); err != nil {
		return err
	}
	hasECN := f.ECT0 > 0 || f.ECT1 > 0 || f.ECNCE > 0
	if hasECN {
		h.WriteToken(jsontext.String("ect0"))
		h.WriteToken(jsontext.Uint(f.ECT0))
		h.WriteToken(jsontext.String("ect1"))
		h.WriteToken(jsontext.Uint(f.ECT1))
		h.WriteToken(jsontext.String("ce"))
		h.WriteToken(jsontext.Uint(f.ECNCE))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeResetStreamFrame(enc *jsontext.Encoder, f *logging.ResetStreamFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	if f.ReliableSize > 0 {
		h.WriteToken(jsontext.String("reset_stream_at"))
	} else {
		h.WriteToken(jsontext.String("reset_stream"))
	}
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamID)))
	h.WriteToken(jsontext.String("error_code"))
	h.WriteToken(jsontext.Uint(uint64(f.ErrorCode)))
	h.WriteToken(jsontext.String("final_size"))
	h.WriteToken(jsontext.Uint(uint64(f.FinalSize)))
	if f.ReliableSize > 0 {
		h.WriteToken(jsontext.String("reliable_size"))
		h.WriteToken(jsontext.Uint(uint64(f.ReliableSize)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeStopSendingFrame(enc *jsontext.Encoder, f *logging.StopSendingFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("stop_sending"))
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamID)))
	h.WriteToken(jsontext.String("error_code"))
	h.WriteToken(jsontext.Uint(uint64(f.ErrorCode)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeCryptoFrame(enc *jsontext.Encoder, f *logging.CryptoFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("crypto"))
	h.WriteToken(jsontext.String("offset"))
	h.WriteToken(jsontext.Uint(uint64(f.Offset)))
	h.WriteToken(jsontext.String("length"))
	h.WriteToken(jsontext.Uint(uint64(f.Length)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeNewTokenFrame(enc *jsontext.Encoder, f *logging.NewTokenFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("new_token"))
	h.WriteToken(jsontext.String("token"))
	if err := (token{Raw: f.Token}).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeStreamFrame(enc *jsontext.Encoder, f *logging.StreamFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("stream"))
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamID)))
	h.WriteToken(jsontext.String("offset"))
	h.WriteToken(jsontext.Uint(uint64(f.Offset)))
	h.WriteToken(jsontext.String("length"))
	h.WriteToken(jsontext.Uint(uint64(f.Length)))
	if f.Fin {
		h.WriteToken(jsontext.String("fin"))
		h.WriteToken(jsontext.True)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeMaxDataFrame(enc *jsontext.Encoder, f *logging.MaxDataFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("max_data"))
	h.WriteToken(jsontext.String("maximum"))
	h.WriteToken(jsontext.Uint(uint64(f.MaximumData)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeMaxStreamDataFrame(enc *jsontext.Encoder, f *logging.MaxStreamDataFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("max_stream_data"))
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamID)))
	h.WriteToken(jsontext.String("maximum"))
	h.WriteToken(jsontext.Uint(uint64(f.MaximumStreamData)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeMaxStreamsFrame(enc *jsontext.Encoder, f *logging.MaxStreamsFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("max_streams"))
	h.WriteToken(jsontext.String("stream_type"))
	h.WriteToken(jsontext.String(streamType(f.Type).String()))
	h.WriteToken(jsontext.String("maximum"))
	h.WriteToken(jsontext.Uint(uint64(f.MaxStreamNum)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeDataBlockedFrame(enc *jsontext.Encoder, f *logging.DataBlockedFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("data_blocked"))
	h.WriteToken(jsontext.String("limit"))
	h.WriteToken(jsontext.Uint(uint64(f.MaximumData)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeStreamDataBlockedFrame(enc *jsontext.Encoder, f *logging.StreamDataBlockedFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("stream_data_blocked"))
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamID)))
	h.WriteToken(jsontext.String("limit"))
	h.WriteToken(jsontext.Uint(uint64(f.MaximumStreamData)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeStreamsBlockedFrame(enc *jsontext.Encoder, f *logging.StreamsBlockedFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("streams_blocked"))
	h.WriteToken(jsontext.String("stream_type"))
	h.WriteToken(jsontext.String(streamType(f.Type).String()))
	h.WriteToken(jsontext.String("limit"))
	h.WriteToken(jsontext.Uint(uint64(f.StreamLimit)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeNewConnectionIDFrame(enc *jsontext.Encoder, f *logging.NewConnectionIDFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("new_connection_id"))
	h.WriteToken(jsontext.String("sequence_number"))
	h.WriteToken(jsontext.Uint(f.SequenceNumber))
	h.WriteToken(jsontext.String("retire_prior_to"))
	h.WriteToken(jsontext.Uint(f.RetirePriorTo))
	h.WriteToken(jsontext.String("length"))
	h.WriteToken(jsontext.Int(int64(f.ConnectionID.Len())))
	h.WriteToken(jsontext.String("connection_id"))
	h.WriteToken(jsontext.String(f.ConnectionID.String()))
	h.WriteToken(jsontext.String("stateless_reset_token"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", f.StatelessResetToken)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeRetireConnectionIDFrame(enc *jsontext.Encoder, f *logging.RetireConnectionIDFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("retire_connection_id"))
	h.WriteToken(jsontext.String("sequence_number"))
	h.WriteToken(jsontext.Uint(f.SequenceNumber))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodePathChallengeFrame(enc *jsontext.Encoder, f *logging.PathChallengeFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("path_challenge"))
	h.WriteToken(jsontext.String("data"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", f.Data[:])))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodePathResponseFrame(enc *jsontext.Encoder, f *logging.PathResponseFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("path_response"))
	h.WriteToken(jsontext.String("data"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", f.Data[:])))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeConnectionCloseFrame(enc *jsontext.Encoder, f *logging.ConnectionCloseFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("connection_close"))
	h.WriteToken(jsontext.String("error_space"))
	errorSpace := "transport"
	if f.IsApplicationError {
		errorSpace = "application"
	}
	h.WriteToken(jsontext.String(errorSpace))
	errName := transportError(f.ErrorCode).String()
	if len(errName) > 0 {
		h.WriteToken(jsontext.String("error_code"))
		h.WriteToken(jsontext.String(errName))
	} else {
		h.WriteToken(jsontext.String("error_code"))
		h.WriteToken(jsontext.Uint(f.ErrorCode))
	}
	h.WriteToken(jsontext.String("raw_error_code"))
	h.WriteToken(jsontext.Uint(f.ErrorCode))
	h.WriteToken(jsontext.String("reason"))
	h.WriteToken(jsontext.String(f.ReasonPhrase))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeHandshakeDoneFrame(enc *jsontext.Encoder, _ *logging.HandshakeDoneFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("handshake_done"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeDatagramFrame(enc *jsontext.Encoder, f *logging.DatagramFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("datagram"))
	h.WriteToken(jsontext.String("length"))
	h.WriteToken(jsontext.Uint(uint64(f.Length)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeAckFrequencyFrame(enc *jsontext.Encoder, f *logging.AckFrequencyFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("ack_frequency"))
	h.WriteToken(jsontext.String("sequence_number"))
	h.WriteToken(jsontext.Uint(f.SequenceNumber))
	h.WriteToken(jsontext.String("ack_eliciting_threshold"))
	h.WriteToken(jsontext.Uint(f.AckElicitingThreshold))
	h.WriteToken(jsontext.String("request_max_ack_delay"))
	h.WriteToken(jsontext.Float(milliseconds(f.RequestMaxAckDelay)))
	h.WriteToken(jsontext.String("reordering_threshold"))
	h.WriteToken(jsontext.Uint(uint64(f.ReorderingThreshold)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func encodeImmediateAckFrame(enc *jsontext.Encoder, _ *logging.ImmediateAckFrame) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("frame_type"))
	h.WriteToken(jsontext.String("immediate_ack"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}
