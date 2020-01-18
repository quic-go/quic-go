package qlog

import (
	"encoding/json"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type frame struct {
	Frame interface{}
}

type streamType protocol.StreamType

func (s streamType) String() string {
	switch protocol.StreamType(s) {
	case protocol.StreamTypeUni:
		return "unidirectional"
	case protocol.StreamTypeBidi:
		return "bidirectional"
	default:
		panic("unknown stream type")
	}
}

func escapeStr(str string) []byte { return []byte("\"" + str + "\"") }

type connectionID protocol.ConnectionID

func (c connectionID) MarshalJSON() ([]byte, error) {
	return escapeStr(fmt.Sprintf("%x", c)), nil
}

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

// MarshalJSON marshals to JSON
func (f frame) MarshalJSON() ([]byte, error) {
	switch frame := f.Frame.(type) {
	case *wire.PingFrame:
		return marshalPingFrame(frame)
	case *wire.AckFrame:
		return marshalAckFrame(frame)
	case *wire.ResetStreamFrame:
		return marshalResetStreamFrame(frame)
	case *wire.StopSendingFrame:
		return marshalStopSendingFrame(frame)
	case *cryptoFrame:
		return marshalCryptoFrame(frame)
	case *wire.NewTokenFrame:
		return marshalNewTokenFrame(frame)
	case *streamFrame:
		return marshalStreamFrame(frame)
	case *wire.MaxDataFrame:
		return marshalMaxDataFrame(frame)
	case *wire.MaxStreamDataFrame:
		return marshalMaxStreamDataFrame(frame)
	case *wire.MaxStreamsFrame:
		return marshalMaxStreamsFrame(frame)
	case *wire.DataBlockedFrame:
		return marshalDataBlockedFrame(frame)
	case *wire.StreamDataBlockedFrame:
		return marshalStreamDataBlockedFrame(frame)
	case *wire.StreamsBlockedFrame:
		return marshalStreamsBlockedFrame(frame)
	case *wire.NewConnectionIDFrame:
		return marshalNewConnectionIDFrame(frame)
	case *wire.RetireConnectionIDFrame:
		return marshalRetireConnectionIDFrame(frame)
	case *wire.PathChallengeFrame:
		return marshalPathChallengeFrame(frame)
	case *wire.PathResponseFrame:
		return marshalPathResponseFrame(frame)
	case *wire.ConnectionCloseFrame:
		return marshalConnectionCloseFrame(frame)
	case *wire.HandshakeDoneFrame:
		return marshalHandshakeDoneFrame(frame)
	default:
		panic("unknown frame type")
	}
}

func marshalPingFrame(_ *wire.PingFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string `json:"frame_type"`
	}{
		FrameType: "ping",
	})
}

type ackRange struct {
	Smallest protocol.PacketNumber
	Largest  protocol.PacketNumber
}

func (ar ackRange) MarshalJSON() ([]byte, error) {
	if ar.Smallest == ar.Largest {
		return json.Marshal([]string{fmt.Sprintf("%d", ar.Smallest)})
	}
	return json.Marshal([]string{fmt.Sprintf("%d", ar.Smallest), fmt.Sprintf("%d", ar.Largest)})
}

func marshalAckFrame(f *wire.AckFrame) ([]byte, error) {
	ranges := make([]ackRange, len(f.AckRanges))
	for i, r := range f.AckRanges {
		ranges[i] = ackRange{Smallest: r.Smallest, Largest: r.Largest}
	}
	return json.Marshal(struct {
		FrameType string     `json:"frame_type"`
		AckDelay  int64      `json:"ack_delay,string,omitempty"`
		AckRanges []ackRange `json:"acked_ranges"`
	}{
		FrameType: "ack",
		AckDelay:  f.DelayTime.Milliseconds(),
		AckRanges: ranges,
	})
}

func marshalResetStreamFrame(f *wire.ResetStreamFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string                        `json:"frame_type"`
		StreamID  protocol.StreamID             `json:"stream_id,string"`
		ErrorCode protocol.ApplicationErrorCode `json:"error_code"`
		FinalSize protocol.ByteCount            `json:"final_size,string"`
	}{
		FrameType: "reset_stream",
		StreamID:  f.StreamID,
		ErrorCode: f.ErrorCode,
		FinalSize: f.ByteOffset,
	})
}

func marshalStopSendingFrame(f *wire.StopSendingFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string                        `json:"frame_type"`
		StreamID  protocol.StreamID             `json:"stream_id,string"`
		ErrorCode protocol.ApplicationErrorCode `json:"error_code"`
	}{
		FrameType: "stop_sending",
		StreamID:  f.StreamID,
		ErrorCode: f.ErrorCode,
	})
}

func marshalCryptoFrame(f *cryptoFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string             `json:"frame_type"`
		Offset    protocol.ByteCount `json:"offset,string"`
		Length    protocol.ByteCount `json:"length"`
	}{
		FrameType: "crypto",
		Offset:    f.Offset,
		Length:    f.Length,
	})
}

func marshalNewTokenFrame(f *wire.NewTokenFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string `json:"frame_type"`
		Length    int    `json:"length"`
		Token     string `json:"token"`
	}{
		FrameType: "new_token",
		Length:    len(f.Token),
		Token:     fmt.Sprintf("%x", f.Token),
	})
}

func marshalStreamFrame(f *streamFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string             `json:"frame_type"`
		StreamID  protocol.StreamID  `json:"stream_id,string"`
		Offset    protocol.ByteCount `json:"offset,string"`
		Length    protocol.ByteCount `json:"length"`
		Fin       bool               `json:"fin,omitempty"`
	}{
		FrameType: "stream",
		StreamID:  f.StreamID,
		Offset:    f.Offset,
		Length:    f.Length,
		Fin:       f.FinBit,
	})
}

func marshalMaxDataFrame(f *wire.MaxDataFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string             `json:"frame_type"`
		Maximum   protocol.ByteCount `json:"maximum,string"`
	}{
		FrameType: "max_data",
		Maximum:   f.ByteOffset,
	})
}

func marshalMaxStreamDataFrame(f *wire.MaxStreamDataFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string             `json:"frame_type"`
		StreamID  protocol.StreamID  `json:"stream_id,string"`
		Maximum   protocol.ByteCount `json:"maximum,string"`
	}{
		FrameType: "max_stream_data",
		StreamID:  f.StreamID,
		Maximum:   f.ByteOffset,
	})
}

func marshalMaxStreamsFrame(f *wire.MaxStreamsFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType  string             `json:"frame_type"`
		StreamType string             `json:"stream_type"`
		Maximum    protocol.StreamNum `json:"maximum,string"`
	}{
		FrameType:  "max_streams",
		StreamType: streamType(f.Type).String(),
		Maximum:    f.MaxStreamNum,
	})
}

func marshalDataBlockedFrame(f *wire.DataBlockedFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string             `json:"frame_type"`
		Limit     protocol.ByteCount `json:"limit,string"`
	}{
		FrameType: "data_blocked",
		Limit:     f.DataLimit,
	})
}

func marshalStreamDataBlockedFrame(f *wire.StreamDataBlockedFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string             `json:"frame_type"`
		StreamID  protocol.StreamID  `json:"stream_id,string"`
		Limit     protocol.ByteCount `json:"limit,string"`
	}{
		FrameType: "stream_data_blocked",
		StreamID:  f.StreamID,
		Limit:     f.DataLimit,
	})
}

func marshalStreamsBlockedFrame(f *wire.StreamsBlockedFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType  string             `json:"frame_type"`
		StreamType string             `json:"stream_type"`
		Limit      protocol.StreamNum `json:"limit,string"`
	}{
		FrameType:  "streams_blocked",
		StreamType: streamType(f.Type).String(),
		Limit:      f.StreamLimit,
	})
}

func marshalNewConnectionIDFrame(f *wire.NewConnectionIDFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType      string       `json:"frame_type"`
		SequenceNumber uint64       `json:"sequence_number,string"`
		RetirePriorTo  uint64       `json:"retire_prior_to,string"`
		Length         int          `json:"length"`
		ConnectionID   connectionID `json:"connection_id"`
		ResetToken     string       `json:"reset_token"`
	}{
		FrameType:      "new_connection_id",
		SequenceNumber: f.SequenceNumber,
		RetirePriorTo:  f.RetirePriorTo,
		Length:         f.ConnectionID.Len(),
		ConnectionID:   connectionID(f.ConnectionID),
		ResetToken:     fmt.Sprintf("%x", f.StatelessResetToken),
	})
}

func marshalRetireConnectionIDFrame(f *wire.RetireConnectionIDFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType      string `json:"frame_type"`
		SequenceNumber uint64 `json:"sequence_number,string"`
	}{
		FrameType:      "retire_connection_id",
		SequenceNumber: f.SequenceNumber,
	})
}

func marshalPathChallengeFrame(f *wire.PathChallengeFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string `json:"frame_type"`
		Data      string `json:"data"`
	}{
		FrameType: "path_challenge",
		Data:      fmt.Sprintf("%x", f.Data[:]),
	})
}

func marshalPathResponseFrame(f *wire.PathResponseFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string `json:"frame_type"`
		Data      string `json:"data"`
	}{
		FrameType: "path_response",
		Data:      fmt.Sprintf("%x", f.Data[:]),
	})
}

func marshalConnectionCloseFrame(f *wire.ConnectionCloseFrame) ([]byte, error) {
	errorSpace := "transport"
	if f.IsApplicationError {
		errorSpace = "application"
	}
	return json.Marshal(struct {
		FrameType    string `json:"frame_type"`
		ErrorSpace   string `json:"error_space"`
		ErrorCode    uint64 `json:"error_code"`
		RawErrorCode uint64 `json:"raw_error_code"`
		Reason       string `json:"reason"`
	}{
		FrameType:    "connection_close",
		ErrorSpace:   errorSpace,
		ErrorCode:    uint64(f.ErrorCode),
		RawErrorCode: uint64(f.ErrorCode),
		Reason:       f.ReasonPhrase,
	})
}

func marshalHandshakeDoneFrame(_ *wire.HandshakeDoneFrame) ([]byte, error) {
	return json.Marshal(struct {
		FrameType string `json:"frame_type"`
	}{
		FrameType: "handshake_done",
	})
}
