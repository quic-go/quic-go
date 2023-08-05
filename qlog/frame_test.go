package qlog

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/logging"

	"github.com/francoispqt/gojay"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frames", func() {
	check := func(f logging.Frame, expected map[string]interface{}) {
		buf := &bytes.Buffer{}
		enc := gojay.NewEncoder(buf)
		ExpectWithOffset(1, enc.Encode(frame{Frame: f})).To(Succeed())
		data := buf.Bytes()
		ExpectWithOffset(1, json.Valid(data)).To(BeTrue())
		checkEncoding(data, expected)
	}

	It("marshals PING frames", func() {
		check(
			&logging.PingFrame{},
			map[string]interface{}{
				"frame_type": "ping",
			},
		)
	})

	It("marshals ACK frames with a range acknowledging a single packet", func() {
		check(
			&logging.AckFrame{
				DelayTime: 86 * time.Millisecond,
				AckRanges: []logging.AckRange{{Smallest: 120, Largest: 120}},
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
			&logging.AckFrame{
				AckRanges: []logging.AckRange{{Smallest: 120, Largest: 120}},
			},
			map[string]interface{}{
				"frame_type":   "ack",
				"acked_ranges": [][]float64{{120}},
			},
		)
	})

	It("marshals ACK frames with ECN counts", func() {
		check(
			&logging.AckFrame{
				AckRanges: []logging.AckRange{{Smallest: 120, Largest: 120}},
				ECT0:      10,
				ECT1:      100,
				ECNCE:     1000,
			},
			map[string]interface{}{
				"frame_type":   "ack",
				"acked_ranges": [][]float64{{120}},
				"ect0":         10,
				"ect1":         100,
				"ce":           1000,
			},
		)
	})

	It("marshals ACK frames with a range acknowledging ranges of packets", func() {
		check(
			&logging.AckFrame{
				DelayTime: 86 * time.Millisecond,
				AckRanges: []logging.AckRange{
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
	})

	It("marshals STOP_SENDING frames", func() {
		check(
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
	})

	It("marshals CRYPTO frames", func() {
		check(
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
	})

	It("marshals NEW_TOKEN frames", func() {
		check(
			&logging.NewTokenFrame{
				Token: []byte{0xde, 0xad, 0xbe, 0xef},
			},
			map[string]interface{}{
				"frame_type": "new_token",
				"token":      map[string]interface{}{"data": "deadbeef"},
			},
		)
	})

	It("marshals STREAM frames with FIN", func() {
		check(
			&logging.StreamFrame{
				StreamID: 42,
				Offset:   1337,
				Fin:      true,
				Length:   9876,
			},
			map[string]interface{}{
				"frame_type": "stream",
				"stream_id":  42,
				"offset":     1337,
				"fin":        true,
				"length":     9876,
			},
		)
	})

	It("marshals STREAM frames without FIN", func() {
		check(
			&logging.StreamFrame{
				StreamID: 42,
				Offset:   1337,
				Length:   3,
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
			&logging.MaxDataFrame{
				MaximumData: 1337,
			},
			map[string]interface{}{
				"frame_type": "max_data",
				"maximum":    1337,
			},
		)
	})

	It("marshals MAX_STREAM_DATA frames", func() {
		check(
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
	})

	It("marshals MAX_STREAMS frames", func() {
		check(
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
	})

	It("marshals DATA_BLOCKED frames", func() {
		check(
			&logging.DataBlockedFrame{
				MaximumData: 1337,
			},
			map[string]interface{}{
				"frame_type": "data_blocked",
				"limit":      1337,
			},
		)
	})

	It("marshals STREAM_DATA_BLOCKED frames", func() {
		check(
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
	})

	It("marshals STREAMS_BLOCKED frames", func() {
		check(
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
	})

	It("marshals NEW_CONNECTION_ID frames", func() {
		check(
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
	})

	It("marshals RETIRE_CONNECTION_ID frames", func() {
		check(
			&logging.RetireConnectionIDFrame{
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
			&logging.PathChallengeFrame{
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
			&logging.PathResponseFrame{
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
			&logging.ConnectionCloseFrame{
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
			&logging.ConnectionCloseFrame{
				ErrorCode:    uint64(qerr.FlowControlError),
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
			&logging.HandshakeDoneFrame{},
			map[string]interface{}{
				"frame_type": "handshake_done",
			},
		)
	})

	It("marshals DATAGRAM frames", func() {
		check(
			&logging.DatagramFrame{Length: 1337},
			map[string]interface{}{
				"frame_type": "datagram",
				"length":     1337,
			},
		)
	})
})
