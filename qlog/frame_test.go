package qlog

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/lucas-clemente/quic-go/internal/qerr"

	"github.com/francoispqt/gojay"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frames", func() {
	check := func(f wire.Frame, expected map[string]interface{}) {
		buf := &bytes.Buffer{}
		enc := gojay.NewEncoder(buf)
		ExpectWithOffset(1, enc.Encode(transformFrame(f))).To(Succeed())
		data := buf.Bytes()
		ExpectWithOffset(1, json.Valid(data)).To(BeTrue())
		checkEncoding(data, expected)
	}

	It("marshals PING frames", func() {
		check(
			&wire.PingFrame{},
			map[string]interface{}{
				"frame_type": "ping",
			},
		)
	})

	It("marshals ACK frames with a range acknowledging a single packet", func() {
		check(
			&wire.AckFrame{
				DelayTime: 86 * time.Millisecond,
				AckRanges: []wire.AckRange{{Smallest: 120, Largest: 120}},
			},
			map[string]interface{}{
				"frame_type":   "ack",
				"ack_delay":    86,
				"acked_ranges": [][]float64{{120}},
			},
		)
	})

	It("marshals ACK frames without a delay", func() {
		check(
			&wire.AckFrame{
				AckRanges: []wire.AckRange{{Smallest: 120, Largest: 120}},
			},
			map[string]interface{}{
				"frame_type":   "ack",
				"acked_ranges": [][]float64{{120}},
			},
		)
	})

	It("marshals ACK frames with a range acknowledging ranges of packets", func() {
		check(
			&wire.AckFrame{
				DelayTime: 86 * time.Millisecond,
				AckRanges: []wire.AckRange{
					{Smallest: 5, Largest: 50},
					{Smallest: 100, Largest: 120},
				},
			},
			map[string]interface{}{
				"frame_type": "ack",
				"ack_delay":  86,
				"acked_ranges": [][]float64{
					{5, 50},
					{100, 120},
				},
			},
		)
	})

	It("marshals RESET_STREAM frames", func() {
		check(
			&wire.ResetStreamFrame{
				StreamID:   987,
				ByteOffset: 1234,
				ErrorCode:  42,
			},
			map[string]interface{}{
				"frame_type": "reset_stream",
				"stream_id":  987,
				"error_code": 42,
				"final_size": 1234,
			},
		)
	})

	It("marshals STOP_SENDING frames", func() {
		check(
			&wire.StopSendingFrame{
				StreamID:  987,
				ErrorCode: 42,
			},
			map[string]interface{}{
				"frame_type": "stop_sending",
				"stream_id":  987,
				"error_code": 42,
			},
		)
	})

	It("marshals CRYPTO frames", func() {
		check(
			&wire.CryptoFrame{
				Offset: 1337,
				Data:   []byte("foobar"),
			},
			map[string]interface{}{
				"frame_type": "crypto",
				"offset":     1337,
				"length":     6,
			},
		)
	})

	It("marshals NEW_TOKEN frames", func() {
		check(
			&wire.NewTokenFrame{
				Token: []byte{0xde, 0xad, 0xbe, 0xef},
			},
			map[string]interface{}{
				"frame_type": "new_token",
				"length":     4,
				"token":      "deadbeef",
			},
		)
	})

	It("marshals STREAM frames with FIN", func() {
		check(
			&wire.StreamFrame{
				StreamID: 42,
				Offset:   1337,
				FinBit:   true,
				Data:     []byte("foobar"),
			},
			map[string]interface{}{
				"frame_type": "stream",
				"stream_id":  42,
				"offset":     1337,
				"fin":        true,
				"length":     6,
			},
		)
	})

	It("marshals STREAM frames without FIN", func() {
		check(
			&wire.StreamFrame{
				StreamID: 42,
				Offset:   1337,
				Data:     []byte("foo"),
			},
			map[string]interface{}{
				"frame_type": "stream",
				"stream_id":  42,
				"offset":     1337,
				"length":     3,
			},
		)
	})

	It("marshals MAX_DATA frames", func() {
		check(
			&wire.MaxDataFrame{
				ByteOffset: 1337,
			},
			map[string]interface{}{
				"frame_type": "max_data",
				"maximum":    1337,
			},
		)
	})

	It("marshals MAX_STREAM_DATA frames", func() {
		check(
			&wire.MaxStreamDataFrame{
				StreamID:   1234,
				ByteOffset: 1337,
			},
			map[string]interface{}{
				"frame_type": "max_stream_data",
				"stream_id":  1234,
				"maximum":    1337,
			},
		)
	})

	It("marshals MAX_STREAMS frames", func() {
		check(
			&wire.MaxStreamsFrame{
				Type:         protocol.StreamTypeBidi,
				MaxStreamNum: 42,
			},
			map[string]interface{}{
				"frame_type":  "max_streams",
				"stream_type": "bidirectional",
				"maximum":     42,
			},
		)
	})

	It("marshals DATA_BLOCKED frames", func() {
		check(
			&wire.DataBlockedFrame{
				DataLimit: 1337,
			},
			map[string]interface{}{
				"frame_type": "data_blocked",
				"limit":      1337,
			},
		)
	})

	It("marshals STREAM_DATA_BLOCKED frames", func() {
		check(
			&wire.StreamDataBlockedFrame{
				StreamID:  42,
				DataLimit: 1337,
			},
			map[string]interface{}{
				"frame_type": "stream_data_blocked",
				"stream_id":  42,
				"limit":      1337,
			},
		)
	})

	It("marshals STREAMS_BLOCKED frames", func() {
		check(
			&wire.StreamsBlockedFrame{
				Type:        protocol.StreamTypeUni,
				StreamLimit: 123,
			},
			map[string]interface{}{
				"frame_type":  "streams_blocked",
				"stream_type": "unidirectional",
				"limit":       123,
			},
		)
	})

	It("marshals NEW_CONNECTION_ID frames", func() {
		check(
			&wire.NewConnectionIDFrame{
				SequenceNumber:      42,
				RetirePriorTo:       24,
				ConnectionID:        protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
				StatelessResetToken: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
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
	})

	It("marshals RETIRE_CONNECTION_ID frames", func() {
		check(
			&wire.RetireConnectionIDFrame{
				SequenceNumber: 1337,
			},
			map[string]interface{}{
				"frame_type":      "retire_connection_id",
				"sequence_number": 1337,
			},
		)
	})

	It("marshals PATH_CHALLENGE frames", func() {
		check(
			&wire.PathChallengeFrame{
				Data: [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xc0, 0x01},
			},
			map[string]interface{}{
				"frame_type": "path_challenge",
				"data":       "deadbeefcafec001",
			},
		)
	})

	It("marshals PATH_RESPONSE frames", func() {
		check(
			&wire.PathResponseFrame{
				Data: [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xc0, 0x01},
			},
			map[string]interface{}{
				"frame_type": "path_response",
				"data":       "deadbeefcafec001",
			},
		)
	})

	It("marshals CONNECTION_CLOSE frames, for application error codes", func() {
		check(
			&wire.ConnectionCloseFrame{
				IsApplicationError: true,
				ErrorCode:          1337,
				ReasonPhrase:       "lorem ipsum",
			},
			map[string]interface{}{
				"frame_type":     "connection_close",
				"error_space":    "application",
				"error_code":     1337,
				"raw_error_code": 1337,
				"reason":         "lorem ipsum",
			},
		)
	})

	It("marshals CONNECTION_CLOSE frames, for transport error codes", func() {
		check(
			&wire.ConnectionCloseFrame{
				ErrorCode:    qerr.FlowControlError,
				ReasonPhrase: "lorem ipsum",
			},
			map[string]interface{}{
				"frame_type":     "connection_close",
				"error_space":    "transport",
				"error_code":     "flow_control_error",
				"raw_error_code": int(qerr.FlowControlError),
				"reason":         "lorem ipsum",
			},
		)
	})

	It("marshals HANDSHAKE_DONE frames", func() {
		check(
			&wire.HandshakeDoneFrame{},
			map[string]interface{}{
				"frame_type": "handshake_done",
			},
		)
	})
})
