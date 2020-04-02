package qlog

import (
	"fmt"

	"github.com/francoispqt/gojay"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type frame struct {
	Frame interface{}
}

var _ gojay.MarshalerJSONObject = frame{}

type frames []frame

func (fs frames) IsNil() bool { return fs == nil }
func (fs frames) MarshalJSONArray(enc *gojay.Encoder) {
	for _, f := range fs {
		enc.Object(f)
	}
}

var _ gojay.MarshalerJSONArray = frames{}

type cryptoFrame struct {
	Offset protocol.ByteCount
	Length protocol.ByteCount
}

type streamFrame struct {
	StreamID protocol.StreamID
	Offset   protocol.ByteCount
	Length   protocol.ByteCount
	FinBit   bool
}

func transformFrame(wf wire.Frame) *frame {
	// We don't want to store CRYPTO and STREAM frames, for multiple reasons:
	// * They both contain data, and we want to make this byte slice GC'able as soon as possible.
	// * STREAM frames use a slice from the buffer pool, which is released as soon as the frame is processed.
	switch f := wf.(type) {
	case *wire.CryptoFrame:
		return &frame{Frame: &cryptoFrame{
			Offset: f.Offset,
			Length: protocol.ByteCount(len(f.Data)),
		}}
	case *wire.StreamFrame:
		return &frame{Frame: &streamFrame{
			StreamID: f.StreamID,
			Offset:   f.Offset,
			Length:   f.DataLen(),
			FinBit:   f.FinBit,
		}}
	default:
		return &frame{Frame: wf}
	}
}

func (f frame) MarshalJSONObject(enc *gojay.Encoder) {
	switch frame := f.Frame.(type) {
	case *wire.PingFrame:
		marshalPingFrame(enc, frame)
	case *wire.AckFrame:
		marshalAckFrame(enc, frame)
	case *wire.ResetStreamFrame:
		marshalResetStreamFrame(enc, frame)
	case *wire.StopSendingFrame:
		marshalStopSendingFrame(enc, frame)
	case *cryptoFrame:
		marshalCryptoFrame(enc, frame)
	case *wire.NewTokenFrame:
		marshalNewTokenFrame(enc, frame)
	case *streamFrame:
		marshalStreamFrame(enc, frame)
	case *wire.MaxDataFrame:
		marshalMaxDataFrame(enc, frame)
	case *wire.MaxStreamDataFrame:
		marshalMaxStreamDataFrame(enc, frame)
	case *wire.MaxStreamsFrame:
		marshalMaxStreamsFrame(enc, frame)
	case *wire.DataBlockedFrame:
		marshalDataBlockedFrame(enc, frame)
	case *wire.StreamDataBlockedFrame:
		marshalStreamDataBlockedFrame(enc, frame)
	case *wire.StreamsBlockedFrame:
		marshalStreamsBlockedFrame(enc, frame)
	case *wire.NewConnectionIDFrame:
		marshalNewConnectionIDFrame(enc, frame)
	case *wire.RetireConnectionIDFrame:
		marshalRetireConnectionIDFrame(enc, frame)
	case *wire.PathChallengeFrame:
		marshalPathChallengeFrame(enc, frame)
	case *wire.PathResponseFrame:
		marshalPathResponseFrame(enc, frame)
	case *wire.ConnectionCloseFrame:
		marshalConnectionCloseFrame(enc, frame)
	case *wire.HandshakeDoneFrame:
		marshalHandshakeDoneFrame(enc, frame)
	default:
		panic("unknown frame type")
	}
}

func (f frame) IsNil() bool { return false }

func marshalPingFrame(enc *gojay.Encoder, _ *wire.PingFrame) {
	enc.StringKey("frame_type", "ping")
}

type ackRanges []wire.AckRange

func (ars ackRanges) MarshalJSONArray(enc *gojay.Encoder) {
	for _, r := range ars {
		enc.Array(ackRange(r))
	}
}

func (ars ackRanges) IsNil() bool { return false }

type ackRange wire.AckRange

func (ar ackRange) MarshalJSONArray(enc *gojay.Encoder) {
	enc.AddInt64(int64(ar.Smallest))
	if ar.Smallest != ar.Largest {
		enc.AddInt64(int64(ar.Largest))
	}
}

func (ar ackRange) IsNil() bool { return false }

func marshalAckFrame(enc *gojay.Encoder, f *wire.AckFrame) {
	enc.StringKey("frame_type", "ack")
	enc.FloatKeyOmitEmpty("ack_delay", milliseconds(f.DelayTime))
	enc.ArrayKey("acked_ranges", ackRanges(f.AckRanges))
}

func marshalResetStreamFrame(enc *gojay.Encoder, f *wire.ResetStreamFrame) {
	enc.StringKey("frame_type", "reset_stream")
	enc.Int64Key("stream_id", int64(f.StreamID))
	enc.Int64Key("error_code", int64(f.ErrorCode))
	enc.Int64Key("final_size", int64(f.ByteOffset))
}

func marshalStopSendingFrame(enc *gojay.Encoder, f *wire.StopSendingFrame) {
	enc.StringKey("frame_type", "stop_sending")
	enc.Int64Key("stream_id", int64(f.StreamID))
	enc.Int64Key("error_code", int64(f.ErrorCode))
}

func marshalCryptoFrame(enc *gojay.Encoder, f *cryptoFrame) {
	enc.StringKey("frame_type", "crypto")
	enc.Int64Key("offset", int64(f.Offset))
	enc.Int64Key("length", int64(f.Length))
}

func marshalNewTokenFrame(enc *gojay.Encoder, f *wire.NewTokenFrame) {
	enc.StringKey("frame_type", "new_token")
	enc.IntKey("length", len(f.Token))
	enc.StringKey("token", fmt.Sprintf("%x", f.Token))
}

func marshalStreamFrame(enc *gojay.Encoder, f *streamFrame) {
	enc.StringKey("frame_type", "stream")
	enc.Int64Key("stream_id", int64(f.StreamID))
	enc.Int64Key("offset", int64(f.Offset))
	enc.IntKey("length", int(f.Length))
	enc.BoolKeyOmitEmpty("fin", f.FinBit)
}

func marshalMaxDataFrame(enc *gojay.Encoder, f *wire.MaxDataFrame) {
	enc.StringKey("frame_type", "max_data")
	enc.Int64Key("maximum", int64(f.ByteOffset))
}

func marshalMaxStreamDataFrame(enc *gojay.Encoder, f *wire.MaxStreamDataFrame) {
	enc.StringKey("frame_type", "max_stream_data")
	enc.Int64Key("stream_id", int64(f.StreamID))
	enc.Int64Key("maximum", int64(f.ByteOffset))
}

func marshalMaxStreamsFrame(enc *gojay.Encoder, f *wire.MaxStreamsFrame) {
	enc.StringKey("frame_type", "max_streams")
	enc.StringKey("stream_type", streamType(f.Type).String())
	enc.Int64Key("maximum", int64(f.MaxStreamNum))
}

func marshalDataBlockedFrame(enc *gojay.Encoder, f *wire.DataBlockedFrame) {
	enc.StringKey("frame_type", "data_blocked")
	enc.Int64Key("limit", int64(f.DataLimit))
}

func marshalStreamDataBlockedFrame(enc *gojay.Encoder, f *wire.StreamDataBlockedFrame) {
	enc.StringKey("frame_type", "stream_data_blocked")
	enc.Int64Key("stream_id", int64(f.StreamID))
	enc.Int64Key("limit", int64(f.DataLimit))
}

func marshalStreamsBlockedFrame(enc *gojay.Encoder, f *wire.StreamsBlockedFrame) {
	enc.StringKey("frame_type", "streams_blocked")
	enc.StringKey("stream_type", streamType(f.Type).String())
	enc.Int64Key("limit", int64(f.StreamLimit))
}

func marshalNewConnectionIDFrame(enc *gojay.Encoder, f *wire.NewConnectionIDFrame) {
	enc.StringKey("frame_type", "new_connection_id")
	enc.Int64Key("sequence_number", int64(f.SequenceNumber))
	enc.Int64Key("retire_prior_to", int64(f.RetirePriorTo))
	enc.IntKey("length", f.ConnectionID.Len())
	enc.StringKey("connection_id", connectionID(f.ConnectionID).String())
	enc.StringKey("stateless_reset_token", fmt.Sprintf("%x", f.StatelessResetToken))
}

func marshalRetireConnectionIDFrame(enc *gojay.Encoder, f *wire.RetireConnectionIDFrame) {
	enc.StringKey("frame_type", "retire_connection_id")
	enc.Int64Key("sequence_number", int64(f.SequenceNumber))
}

func marshalPathChallengeFrame(enc *gojay.Encoder, f *wire.PathChallengeFrame) {
	enc.StringKey("frame_type", "path_challenge")
	enc.StringKey("data", fmt.Sprintf("%x", f.Data[:]))
}

func marshalPathResponseFrame(enc *gojay.Encoder, f *wire.PathResponseFrame) {
	enc.StringKey("frame_type", "path_response")
	enc.StringKey("data", fmt.Sprintf("%x", f.Data[:]))
}

func marshalConnectionCloseFrame(enc *gojay.Encoder, f *wire.ConnectionCloseFrame) {
	errorSpace := "transport"
	if f.IsApplicationError {
		errorSpace = "application"
	}
	enc.StringKey("frame_type", "connection_close")
	enc.StringKey("error_space", errorSpace)
	if errName := transportError(f.ErrorCode).String(); len(errName) > 0 {
		enc.StringKey("error_code", errName)
	} else {
		enc.Uint64Key("error_code", uint64(f.ErrorCode))
	}
	enc.Uint64Key("raw_error_code", uint64(f.ErrorCode))
	enc.StringKey("reason", f.ReasonPhrase)
}

func marshalHandshakeDoneFrame(enc *gojay.Encoder, _ *wire.HandshakeDoneFrame) {
	enc.StringKey("frame_type", "handshake_done")
}
