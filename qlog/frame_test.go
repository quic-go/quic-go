package qlog

import (
	"bytes"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

func check(t *testing.T, f any, expected string) {
	t.Helper()

	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	require.NoError(t, (Frame{Frame: f}).Encode(enc))
	require.JSONEq(t, expected, buf.String())
}

func TestPingFrame(t *testing.T) {
	check(t, &PingFrame{}, `{"frame_type": "ping"}`)
}

func TestAckFrame(t *testing.T) {
	tests := []struct {
		name     string
		frame    *AckFrame
		expected string
	}{
		{
			name: "with delay and single packet range",
			frame: &AckFrame{
				DelayTime: 86 * time.Millisecond,
				AckRanges: []AckRange{{Smallest: 120, Largest: 120}},
			},
			expected: `{
				"frame_type": "ack",
				"ack_delay": 86,
				"acked_ranges": [[120]]
			}`,
		},
		{
			name: "without delay",
			frame: &AckFrame{
				AckRanges: []AckRange{{Smallest: 120, Largest: 120}},
			},
			expected: `{
				"frame_type": "ack",
				"acked_ranges": [[120]]
			}`,
		},
		{
			name: "with ECN counts",
			frame: &AckFrame{
				AckRanges: []AckRange{{Smallest: 120, Largest: 120}},
				ECT0:      10,
				ECT1:      100,
				ECNCE:     1000,
			},
			expected: `{
				"frame_type": "ack",
				"acked_ranges": [[120]],
				"ect0": 10,
				"ect1": 100,
				"ce": 1000
			}`,
		},
		{
			name: "with multiple ranges",
			frame: &AckFrame{
				DelayTime: 86 * time.Millisecond,
				AckRanges: []AckRange{
					{Smallest: 5, Largest: 50},
					{Smallest: 100, Largest: 120},
				},
			},
			expected: `{
				"frame_type": "ack",
				"ack_delay": 86,
				"acked_ranges": [
					[5, 50],
					[100, 120]
				]
			}`,
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
		&ResetStreamFrame{
			StreamID:  987,
			FinalSize: 1234,
			ErrorCode: 42,
		},
		`{
			"frame_type": "reset_stream",
			"stream_id": 987,
			"error_code": 42,
			"final_size": 1234
		}`,
	)
}

func TestResetStreamAtFrame(t *testing.T) {
	check(t,
		&ResetStreamFrame{
			StreamID:     987,
			FinalSize:    1234,
			ErrorCode:    42,
			ReliableSize: 999,
		},
		`{
			"frame_type": "reset_stream_at",
			"stream_id": 987,
			"error_code": 42,
			"final_size": 1234,
			"reliable_size": 999
		}`,
	)
}

func TestAckFrequencyFrame(t *testing.T) {
	check(t,
		&AckFrequencyFrame{
			SequenceNumber:        1337,
			AckElicitingThreshold: 123,
			RequestMaxAckDelay:    42 * time.Millisecond,
			ReorderingThreshold:   1234,
		},
		`{
			"frame_type": "ack_frequency",
			"sequence_number": 1337,
			"ack_eliciting_threshold": 123,
			"request_max_ack_delay": 42,
			"reordering_threshold": 1234
		}`,
	)
}

func TestImmediateAckFrame(t *testing.T) {
	check(t,
		&ImmediateAckFrame{},
		`{
			"frame_type": "immediate_ack"
		}`,
	)
}

func TestStopSendingFrame(t *testing.T) {
	check(t,
		&StopSendingFrame{StreamID: 987, ErrorCode: 42},
		`{
			"frame_type": "stop_sending",
			"stream_id": 987,
			"error_code": 42
		}`,
	)
}

func TestCryptoFrame(t *testing.T) {
	check(t,
		&CryptoFrame{Offset: 1337, Length: 6},
		`{
			"frame_type": "crypto",
			"offset": 1337,
			"length": 6
		}`,
	)
}

func TestNewTokenFrame(t *testing.T) {
	check(t,
		&NewTokenFrame{Token: []byte{0xde, 0xad, 0xbe, 0xef}},
		`{
			"frame_type": "new_token",
			"token": {"data": "deadbeef"}
		}`,
	)
}

func TestStreamFrame(t *testing.T) {
	tests := []struct {
		name     string
		frame    *StreamFrame
		expected string
	}{
		{
			name: "with FIN",
			frame: &StreamFrame{
				StreamID: 42,
				Offset:   1337,
				Fin:      true,
				Length:   9876,
			},
			expected: `{
				"frame_type": "stream",
				"stream_id": 42,
				"offset": 1337,
				"fin": true,
				"length": 9876
			}`,
		},
		{
			name: "without FIN",
			frame: &StreamFrame{
				StreamID: 42,
				Offset:   1337,
				Length:   3,
			},
			expected: `{
				"frame_type": "stream",
				"stream_id": 42,
				"offset": 1337,
				"length": 3
			}`,
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
		&MaxDataFrame{MaximumData: 1337},
		`{
			"frame_type": "max_data",
			"maximum": 1337
		}`,
	)
}

func TestMaxStreamDataFrame(t *testing.T) {
	check(t,
		&MaxStreamDataFrame{StreamID: 1234, MaximumStreamData: 1337},
		`{
			"frame_type": "max_stream_data",
			"stream_id": 1234,
			"maximum": 1337
		}`,
	)
}

func TestMaxStreamsFrame(t *testing.T) {
	check(t,
		&MaxStreamsFrame{
			Type:         protocol.StreamTypeBidi,
			MaxStreamNum: 42,
		},
		`{
			"frame_type": "max_streams",
			"stream_type": "bidirectional",
			"maximum": 42
		}`,
	)
}

func TestDataBlockedFrame(t *testing.T) {
	check(t,
		&DataBlockedFrame{MaximumData: 1337},
		`{
			"frame_type": "data_blocked",
			"limit": 1337
		}`,
	)
}

func TestStreamDataBlockedFrame(t *testing.T) {
	check(t,
		&StreamDataBlockedFrame{
			StreamID:          42,
			MaximumStreamData: 1337,
		},
		`{
			"frame_type": "stream_data_blocked",
			"stream_id": 42,
			"limit": 1337
		}`,
	)
}

func TestStreamsBlockedFrame(t *testing.T) {
	check(t,
		&StreamsBlockedFrame{
			Type:        protocol.StreamTypeUni,
			StreamLimit: 123,
		},
		`{
			"frame_type": "streams_blocked",
			"stream_type": "unidirectional",
			"limit": 123
		}`,
	)
}

func TestNewConnectionIDFrame(t *testing.T) {
	check(t,
		&NewConnectionIDFrame{
			SequenceNumber:      42,
			RetirePriorTo:       24,
			ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
		},
		`{
			"frame_type": "new_connection_id",
			"sequence_number": 42,
			"retire_prior_to": 24,
			"length": 4,
			"connection_id": "deadbeef",
			"stateless_reset_token": "000102030405060708090a0b0c0d0e0f"
		}`,
	)
}

func TestRetireConnectionIDFrame(t *testing.T) {
	check(t,
		&RetireConnectionIDFrame{SequenceNumber: 1337},
		`{
			"frame_type": "retire_connection_id",
			"sequence_number": 1337
		}`,
	)
}

func TestPathChallengeFrame(t *testing.T) {
	check(t,
		&PathChallengeFrame{Data: [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xc0, 0x01}},
		`{
			"frame_type": "path_challenge",
			"data": "deadbeefcafec001"
		}`,
	)
}

func TestPathResponseFrame(t *testing.T) {
	check(t,
		&PathResponseFrame{Data: [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xc0, 0x01}},
		`{
			"frame_type": "path_response",
			"data": "deadbeefcafec001"
		}`,
	)
}

func TestConnectionCloseFrame(t *testing.T) {
	tests := []struct {
		name     string
		frame    *ConnectionCloseFrame
		expected string
	}{
		{
			name: "application error code",
			frame: &ConnectionCloseFrame{
				IsApplicationError: true,
				ErrorCode:          1337,
				ReasonPhrase:       "lorem ipsum",
			},
			expected: `{
				"frame_type": "connection_close",
				"error_space": "application",
				"error_code": 1337,
				"raw_error_code": 1337,
				"reason": "lorem ipsum"
			}`,
		},
		{
			name: "transport error code",
			frame: &ConnectionCloseFrame{
				ErrorCode:    uint64(qerr.FlowControlError),
				ReasonPhrase: "lorem ipsum",
			},
			expected: `{
				"frame_type": "connection_close",
				"error_space": "transport",
				"error_code": "flow_control_error",
				"raw_error_code": 3,
				"reason": "lorem ipsum"
			}`,
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
		&HandshakeDoneFrame{},
		`{
			"frame_type": "handshake_done"
		}`,
	)
}

func TestDatagramFrame(t *testing.T) {
	check(t,
		&DatagramFrame{Length: 1337},
		`{
			"frame_type": "datagram",
			"length": 1337
		}`,
	)
}
