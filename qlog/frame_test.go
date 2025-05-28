package qlog

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Noooste/quic-go/internal/protocol"
	"github.com/Noooste/quic-go/internal/qerr"
	"github.com/Noooste/quic-go/logging"
	"github.com/francoispqt/gojay"
	"github.com/stretchr/testify/require"
)

func check(t *testing.T, f logging.Frame, expected map[string]interface{}) {
	buf := &bytes.Buffer{}
	enc := gojay.NewEncoder(buf)
	err := enc.Encode(frame{Frame: f})
	require.NoError(t, err)
	data := buf.Bytes()
	require.True(t, json.Valid(data))
	checkEncoding(t, data, expected)
}

func TestPingFrame(t *testing.T) {
	check(t,
		&logging.PingFrame{},
		map[string]interface{}{
			"frame_type": "ping",
		},
	)
}

func TestAckFrame(t *testing.T) {
	tests := []struct {
		name     string
		frame    *logging.AckFrame
		expected map[string]interface{}
	}{
		{
			name: "with delay and single packet range",
			frame: &logging.AckFrame{
				DelayTime: 86 * time.Millisecond,
				AckRanges: []logging.AckRange{{Smallest: 120, Largest: 120}},
			},
			expected: map[string]interface{}{
				"frame_type":   "ack",
				"ack_delay":    86,
				"acked_ranges": [][]float64{{120}},
			},
		},
		{
			name: "without delay",
			frame: &logging.AckFrame{
				AckRanges: []logging.AckRange{{Smallest: 120, Largest: 120}},
			},
			expected: map[string]interface{}{
				"frame_type":   "ack",
				"acked_ranges": [][]float64{{120}},
			},
		},
		{
			name: "with ECN counts",
			frame: &logging.AckFrame{
				AckRanges: []logging.AckRange{{Smallest: 120, Largest: 120}},
				ECT0:      10,
				ECT1:      100,
				ECNCE:     1000,
			},
			expected: map[string]interface{}{
				"frame_type":   "ack",
				"acked_ranges": [][]float64{{120}},
				"ect0":         10,
				"ect1":         100,
				"ce":           1000,
			},
		},
		{
			name: "with multiple ranges",
			frame: &logging.AckFrame{
				DelayTime: 86 * time.Millisecond,
				AckRanges: []logging.AckRange{
					{Smallest: 5, Largest: 50},
					{Smallest: 100, Largest: 120},
				},
			},
			expected: map[string]interface{}{
				"frame_type": "ack",
				"ack_delay":  86,
				"acked_ranges": [][]float64{
					{5, 50},
					{100, 120},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, tt.frame, tt.expected)
		})
	}
}

func TestResetStreamFrame(t *testing.T) {
	check(t,
		&logging.ResetStreamFrame{
			StreamID:  987,
			FinalSize: 1234,
			ErrorCode: 42,
		},
		map[string]interface{}{
			"frame_type": "reset_stream",
			"stream_id":  987,
			"error_code": 42,
			"final_size": 1234,
		},
	)
}

func TestResetStreamAtFrame(t *testing.T) {
	check(t,
		&logging.ResetStreamFrame{
			StreamID:     987,
			FinalSize:    1234,
			ErrorCode:    42,
			ReliableSize: 999,
		},
		map[string]interface{}{
			"frame_type":    "reset_stream_at",
			"stream_id":     987,
			"error_code":    42,
			"final_size":    1234,
			"reliable_size": 999,
		},
	)
}

func TestStopSendingFrame(t *testing.T) {
	check(t,
		&logging.StopSendingFrame{
			StreamID:  987,
			ErrorCode: 42,
		},
		map[string]interface{}{
			"frame_type": "stop_sending",
			"stream_id":  987,
			"error_code": 42,
		},
	)
}

func TestCryptoFrame(t *testing.T) {
	check(t,
		&logging.CryptoFrame{
			Offset: 1337,
			Length: 6,
		},
		map[string]interface{}{
			"frame_type": "crypto",
			"offset":     1337,
			"length":     6,
		},
	)
}

func TestNewTokenFrame(t *testing.T) {
	check(t,
		&logging.NewTokenFrame{
			Token: []byte{0xde, 0xad, 0xbe, 0xef},
		},
		map[string]interface{}{
			"frame_type": "new_token",
			"token":      map[string]interface{}{"data": "deadbeef"},
		},
	)
}

func TestStreamFrame(t *testing.T) {
	tests := []struct {
		name     string
		frame    *logging.StreamFrame
		expected map[string]interface{}
	}{
		{
			name: "with FIN",
			frame: &logging.StreamFrame{
				StreamID: 42,
				Offset:   1337,
				Fin:      true,
				Length:   9876,
			},
			expected: map[string]interface{}{
				"frame_type": "stream",
				"stream_id":  42,
				"offset":     1337,
				"fin":        true,
				"length":     9876,
			},
		},
		{
			name: "without FIN",
			frame: &logging.StreamFrame{
				StreamID: 42,
				Offset:   1337,
				Length:   3,
			},
			expected: map[string]interface{}{
				"frame_type": "stream",
				"stream_id":  42,
				"offset":     1337,
				"length":     3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, tt.frame, tt.expected)
		})
	}
}

func TestMaxDataFrame(t *testing.T) {
	check(t,
		&logging.MaxDataFrame{
			MaximumData: 1337,
		},
		map[string]interface{}{
			"frame_type": "max_data",
			"maximum":    1337,
		},
	)
}

func TestMaxStreamDataFrame(t *testing.T) {
	check(t,
		&logging.MaxStreamDataFrame{
			StreamID:          1234,
			MaximumStreamData: 1337,
		},
		map[string]interface{}{
			"frame_type": "max_stream_data",
			"stream_id":  1234,
			"maximum":    1337,
		},
	)
}

func TestMaxStreamsFrame(t *testing.T) {
	check(t,
		&logging.MaxStreamsFrame{
			Type:         protocol.StreamTypeBidi,
			MaxStreamNum: 42,
		},
		map[string]interface{}{
			"frame_type":  "max_streams",
			"stream_type": "bidirectional",
			"maximum":     42,
		},
	)
}

func TestDataBlockedFrame(t *testing.T) {
	check(t,
		&logging.DataBlockedFrame{
			MaximumData: 1337,
		},
		map[string]interface{}{
			"frame_type": "data_blocked",
			"limit":      1337,
		},
	)
}

func TestStreamDataBlockedFrame(t *testing.T) {
	check(t,
		&logging.StreamDataBlockedFrame{
			StreamID:          42,
			MaximumStreamData: 1337,
		},
		map[string]interface{}{
			"frame_type": "stream_data_blocked",
			"stream_id":  42,
			"limit":      1337,
		},
	)
}

func TestStreamsBlockedFrame(t *testing.T) {
	check(t,
		&logging.StreamsBlockedFrame{
			Type:        protocol.StreamTypeUni,
			StreamLimit: 123,
		},
		map[string]interface{}{
			"frame_type":  "streams_blocked",
			"stream_type": "unidirectional",
			"limit":       123,
		},
	)
}

func TestNewConnectionIDFrame(t *testing.T) {
	check(t,
		&logging.NewConnectionIDFrame{
			SequenceNumber:      42,
			RetirePriorTo:       24,
			ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
		},
		map[string]interface{}{
			"frame_type":            "new_connection_id",
			"sequence_number":       42,
			"retire_prior_to":       24,
			"length":                4,
			"connection_id":         "deadbeef",
			"stateless_reset_token": "000102030405060708090a0b0c0d0e0f",
		},
	)
}

func TestRetireConnectionIDFrame(t *testing.T) {
	check(t,
		&logging.RetireConnectionIDFrame{
			SequenceNumber: 1337,
		},
		map[string]interface{}{
			"frame_type":      "retire_connection_id",
			"sequence_number": 1337,
		},
	)
}

func TestPathChallengeFrame(t *testing.T) {
	check(t,
		&logging.PathChallengeFrame{
			Data: [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xc0, 0x01},
		},
		map[string]interface{}{
			"frame_type": "path_challenge",
			"data":       "deadbeefcafec001",
		},
	)
}

func TestPathResponseFrame(t *testing.T) {
	check(t,
		&logging.PathResponseFrame{
			Data: [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xc0, 0x01},
		},
		map[string]interface{}{
			"frame_type": "path_response",
			"data":       "deadbeefcafec001",
		},
	)
}

func TestConnectionCloseFrame(t *testing.T) {
	tests := []struct {
		name     string
		frame    *logging.ConnectionCloseFrame
		expected map[string]interface{}
	}{
		{
			name: "application error code",
			frame: &logging.ConnectionCloseFrame{
				IsApplicationError: true,
				ErrorCode:          1337,
				ReasonPhrase:       "lorem ipsum",
			},
			expected: map[string]interface{}{
				"frame_type":     "connection_close",
				"error_space":    "application",
				"error_code":     1337,
				"raw_error_code": 1337,
				"reason":         "lorem ipsum",
			},
		},
		{
			name: "transport error code",
			frame: &logging.ConnectionCloseFrame{
				ErrorCode:    uint64(qerr.FlowControlError),
				ReasonPhrase: "lorem ipsum",
			},
			expected: map[string]interface{}{
				"frame_type":     "connection_close",
				"error_space":    "transport",
				"error_code":     "flow_control_error",
				"raw_error_code": int(qerr.FlowControlError),
				"reason":         "lorem ipsum",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, tt.frame, tt.expected)
		})
	}
}

func TestHandshakeDoneFrame(t *testing.T) {
	check(t,
		&logging.HandshakeDoneFrame{},
		map[string]interface{}{
			"frame_type": "handshake_done",
		},
	)
}

func TestDatagramFrame(t *testing.T) {
	check(t,
		&logging.DatagramFrame{Length: 1337},
		map[string]interface{}{
			"frame_type": "datagram",
			"length":     1337,
		},
	)
}
