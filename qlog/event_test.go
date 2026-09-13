package qlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/stretchr/testify/require"
)

func testEventEncoding(t *testing.T, ev qlogwriter.Event) (string, string) {
	t.Helper()
	var buf bytes.Buffer

	synctest.Test(t, func(t *testing.T) {
		tr := qlogwriter.NewConnectionFileSeq(
			nopWriteCloser(&buf),
			true,
			protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			[]string{EventSchema},
		)
		go tr.Run()
		producer := tr.AddProducer()

		synctest.Wait()
		time.Sleep(42 * time.Second)

		producer.RecordEvent(ev)
		producer.Close()
	})

	return decode(t, buf.String())
}

func decode(t *testing.T, data string) (string, string) {
	t.Helper()

	var result struct {
		Time float64
		Name string
		Data json.RawMessage
	}

	lines := bytes.Split([]byte(data), []byte{'\n'})
	require.Len(t, lines, 3) // the first line is the trace header, the second line is the event, the third line is empty
	require.Empty(t, lines[2])
	require.NotEmpty(t, lines[1])
	require.Equal(t, qlogwriter.RecordSeparator, lines[1][0], "expected record separator at start of line")
	require.NoError(t, json.Unmarshal(lines[1][1:], &result))
	require.Equal(t, 42*time.Second, time.Duration(result.Time*1e6)*time.Nanosecond)

	return result.Name, string(result.Data)
}

func TestStartedConnection(t *testing.T) {
	var localInfo, remoteInfo PathEndpointInfo
	localInfo.IPv4 = netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 13, 37}), 42)
	ip, err := netip.ParseAddr("2001:db8::1")
	require.NoError(t, err)
	remoteInfo.IPv6 = netip.AddrPortFrom(ip, 24)

	name, ev := testEventEncoding(t, &StartedConnection{
		Local:  localInfo,
		Remote: remoteInfo,
	})

	require.Equal(t, "transport:connection_started", name)
	require.JSONEq(t, `{
		"local": {"ip_v4": "192.168.13.37", "port_v4": 42},
		"remote": {"ip_v6": "2001:db8::1", "port_v6": 24}
	}`, ev)
}

func TestVersionInformation(t *testing.T) {
	name, ev := testEventEncoding(t, &VersionInformation{ChosenVersion: 0x1337})

	require.Equal(t, "transport:version_information", name)
	require.JSONEq(t, `{"chosen_version": "1337"}`, ev)
}

func TestVersionInformationWithNegotiation(t *testing.T) {
	name, ev := testEventEncoding(t, &VersionInformation{
		ChosenVersion:  0x1337,
		ClientVersions: []Version{1, 2, 3},
		ServerVersions: []Version{4, 5, 6},
	})

	require.Equal(t, "transport:version_information", name)
	require.JSONEq(t, `{
		"chosen_version": "1337",
		"client_versions": ["1", "2", "3"],
		"server_versions": ["4", "5", "6"]
	}`, ev)
}

func TestStreamPriorityUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &StreamPriorityUpdated{
		StreamID:    42,
		Urgency:     2,
		Incremental: true,
	})

	require.Equal(t, "transport:priority_updated", name)
	require.JSONEq(t, `{
		"stream_id": 42,
		"new": "u=2, i"
	}`, ev)
}

func TestIdleTimeouts(t *testing.T) {
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator: InitiatorLocal,
		Trigger:   ConnectionCloseTriggerIdleTimeout,
	})

	require.Equal(t, "transport:connection_closed", name)
	require.JSONEq(t, `{
		"initiator": "local",
		"trigger": "idle_timeout"
	}`, ev)
}

func TestReceivedStatelessResetPacket(t *testing.T) {
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator: InitiatorRemote,
		Trigger:   ConnectionCloseTriggerStatelessReset,
	})

	require.Equal(t, "transport:connection_closed", name)
	require.JSONEq(t, `{
		"initiator": "remote",
		"trigger": "stateless_reset"
	}`, ev)
}

func TestVersionNegotiationFailure(t *testing.T) {
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator: InitiatorLocal,
		Trigger:   ConnectionCloseTriggerVersionMismatch,
	})

	require.Equal(t, "transport:connection_closed", name)
	require.JSONEq(t, `{
		"initiator": "local",
		"trigger": "version_mismatch"
	}`, ev)
}

func TestApplicationErrors(t *testing.T) {
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator:        InitiatorRemote,
		ApplicationError: new(qerr.ApplicationErrorCode(1337)),
		Reason:           "foobar",
	})

	require.Equal(t, "transport:connection_closed", name)
	require.JSONEq(t, `{
		"initiator": "remote",
		"application_error": "unknown",
		"error_code": 1337,
		"reason": "foobar"
	}`, ev)
}

func TestTransportErrors(t *testing.T) {
	tests := []struct {
		code qerr.TransportErrorCode
		want string
	}{
		{qerr.NoError, "no_error"},
		{qerr.InternalError, "internal_error"},
		{qerr.ConnectionRefused, "connection_refused"},
		{qerr.FlowControlError, "flow_control_error"},
		{qerr.StreamLimitError, "stream_limit_error"},
		{qerr.StreamStateError, "stream_state_error"},
		{qerr.FinalSizeError, "final_size_error"},
		{qerr.FrameEncodingError, "frame_encoding_error"},
		{qerr.TransportParameterError, "transport_parameter_error"},
		{qerr.ConnectionIDLimitError, "connection_id_limit_error"},
		{qerr.ProtocolViolation, "protocol_violation"},
		{qerr.InvalidToken, "invalid_token"},
		{qerr.ApplicationErrorErrorCode, "application_error"},
		{qerr.CryptoBufferExceeded, "crypto_buffer_exceeded"},
		{qerr.KeyUpdateError, "key_update_error"},
		{qerr.AEADLimitReached, "aead_limit_reached"},
		{qerr.NoViablePathError, "no_viable_path"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			name, ev := testEventEncoding(t, &ConnectionClosed{
				Initiator:       InitiatorLocal,
				ConnectionError: new(tt.code),
				Reason:          "foobar",
			})

			require.Equal(t, "transport:connection_closed", name)
			require.JSONEq(t, fmt.Sprintf(`{
				"initiator": "local",
				"connection_error": %q,
				"reason": "foobar"
			}`, tt.want), ev)
		})
	}
}

func TestTransportCryptoError(t *testing.T) {
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator:       InitiatorLocal,
		ConnectionError: new(qerr.TransportErrorCode(0x100 + 0x2a)),
		Reason:          "foobar",
	})

	require.Equal(t, "transport:connection_closed", name)
	require.JSONEq(t, `{
		"initiator": "local",
		"connection_error": "crypto_error_0x12a",
		"reason": "foobar"
	}`, ev)
}

func TestSentTransportParameters(t *testing.T) {
	rcid := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator:                       InitiatorLocal,
		SentBy:                          protocol.PerspectiveServer,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		RetrySourceConnectionID:         &rcid,
		StatelessResetToken:             &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
		DisableActiveMigration:          true,
		MaxIdleTimeout:                  321 * time.Millisecond,
		MaxUDPPayloadSize:               1234,
		AckDelayExponent:                12,
		MaxAckDelay:                     123 * time.Millisecond,
		ActiveConnectionIDLimit:         7,
		InitialMaxData:                  4000,
		InitialMaxStreamDataBidiLocal:   1000,
		InitialMaxStreamDataBidiRemote:  2000,
		InitialMaxStreamDataUni:         3000,
		InitialMaxStreamsBidi:           10,
		InitialMaxStreamsUni:            20,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
		EnableResetStreamAt:             true,
	})

	require.Equal(t, "transport:parameters_set", name)
	require.JSONEq(t, `{
		"initiator": "local",
		"original_destination_connection_id": "deadc0de",
		"initial_source_connection_id": "deadbeef",
		"retry_source_connection_id": "decafbad",
		"stateless_reset_token": "112233445566778899aabbccddeeff00",
		"disable_active_migration": true,
		"max_idle_timeout": 321,
		"max_udp_payload_size": 1234,
		"ack_delay_exponent": 12,
		"max_ack_delay": 123,
		"active_connection_id_limit": 7,
		"initial_max_data": 4000,
		"initial_max_stream_data_bidi_local": 1000,
		"initial_max_stream_data_bidi_remote": 2000,
		"initial_max_stream_data_uni": 3000,
		"initial_max_streams_bidi": 10,
		"initial_max_streams_uni": 20,
		"reset_stream_at": true
	}`, ev)
}

func TestServerTransportParametersWithoutStatelessResetToken(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator:                       InitiatorLocal,
		SentBy:                          protocol.PerspectiveServer,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}),
		ActiveConnectionIDLimit:         7,
	})

	require.Equal(t, "transport:parameters_set", name)
	require.JSONEq(t, `{
		"initiator": "local",
		"original_destination_connection_id": "deadc0de",
		"initial_source_connection_id": "(empty)",
		"disable_active_migration": false,
		"active_connection_id_limit": 7,
		"max_datagram_frame_size": 0
	}`, ev)
}

func TestTransportParametersWithoutRetrySourceConnectionID(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator:           InitiatorLocal,
		SentBy:              protocol.PerspectiveServer,
		StatelessResetToken: &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
	})

	require.Equal(t, "transport:parameters_set", name)
	require.JSONEq(t, `{
		"initiator": "local",
		"original_destination_connection_id": "(empty)",
		"initial_source_connection_id": "(empty)",
		"stateless_reset_token": "112233445566778899aabbccddeeff00",
		"disable_active_migration": false,
		"max_datagram_frame_size": 0
	}`, ev)
}

func TestTransportParametersWithPreferredAddress(t *testing.T) {
	t.Run("IPv4 and IPv6", func(t *testing.T) {
		testTransportParametersWithPreferredAddress(t, true, true)
	})
	t.Run("IPv4 only", func(t *testing.T) {
		testTransportParametersWithPreferredAddress(t, true, false)
	})
	t.Run("IPv6 only", func(t *testing.T) {
		testTransportParametersWithPreferredAddress(t, false, true)
	})
}

func testTransportParametersWithPreferredAddress(t *testing.T, hasIPv4, hasIPv6 bool) {
	addr4 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{12, 34, 56, 78}), 123)
	addr6 := netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 456)
	preferredAddress := &PreferredAddress{
		ConnectionID:        protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
		StatelessResetToken: protocol.StatelessResetToken{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	if hasIPv4 {
		preferredAddress.IPv4 = addr4
	}
	if hasIPv6 {
		preferredAddress.IPv6 = addr6
	}
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator:        InitiatorLocal,
		SentBy:           protocol.PerspectiveServer,
		PreferredAddress: preferredAddress,
	})

	require.Equal(t, "transport:parameters_set", name)
	var addresses string
	if hasIPv4 {
		addresses += `"ip_v4": "12.34.56.78", "port_v4": 123,`
	}
	if hasIPv6 {
		addresses += `"ip_v6": "102:304:506:708:90a:b0c:d0e:f10", "port_v6": 456,`
	}
	require.JSONEq(t, fmt.Sprintf(`{
		"initiator": "local",
		"original_destination_connection_id": "(empty)",
		"initial_source_connection_id": "(empty)",
		"disable_active_migration": false,
		"max_datagram_frame_size": 0,
		"preferred_address": {
			%s
			"connection_id": "0807060504030201",
			"stateless_reset_token": "0f0e0d0c0b0a09080706050403020100"
		}
	}`, addresses), ev)
}

func TestTransportParametersWithDatagramExtension(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator:            InitiatorLocal,
		SentBy:               protocol.PerspectiveServer,
		MaxDatagramFrameSize: 1337,
	})

	require.Equal(t, "transport:parameters_set", name)
	require.JSONEq(t, `{
		"initiator": "local",
		"original_destination_connection_id": "(empty)",
		"initial_source_connection_id": "(empty)",
		"disable_active_migration": false,
		"max_datagram_frame_size": 1337
	}`, ev)
}

func TestReceivedTransportParameters(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator: InitiatorRemote,
		SentBy:    protocol.PerspectiveClient,
	})

	require.Equal(t, "transport:parameters_set", name)
	require.JSONEq(t, `{
		"initiator": "remote",
		"initial_source_connection_id": "(empty)",
		"disable_active_migration": false,
		"max_datagram_frame_size": 0
	}`, ev)
}

func TestRestoredTransportParameters(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Restore:                        true,
		InitialMaxStreamDataBidiLocal:  100,
		InitialMaxStreamDataBidiRemote: 200,
		InitialMaxStreamDataUni:        300,
		InitialMaxData:                 400,
		MaxIdleTimeout:                 123 * time.Millisecond,
	})

	require.Equal(t, "transport:parameters_restored", name)
	require.JSONEq(t, `{
		"disable_active_migration": false,
		"max_idle_timeout": 123,
		"initial_max_data": 400,
		"initial_max_stream_data_bidi_local": 100,
		"initial_max_stream_data_bidi_remote": 200,
		"initial_max_stream_data_uni": 300,
		"max_datagram_frame_size": 0
	}`, ev)
}

func TestPacketSent(t *testing.T) {
	name, ev := testEventEncoding(t, &PacketSent{
		Header: PacketHeader{
			PacketType:       PacketTypeHandshake,
			PacketNumber:     1337,
			Version:          protocol.Version1,
			SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		},
		Raw: RawInfo{Length: 987, PayloadLength: 1337},
		Frames: []Frame{
			{Frame: &MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987}},
			{Frame: &StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true}},
		},
		ECN: ECNCE,
	})

	require.Equal(t, "transport:packet_sent", name)
	require.JSONEq(t, `{
		"header": {
			"packet_type": "handshake",
			"packet_number": 1337,
			"version": "1",
			"scil": 4,
			"scid": "04030201",
			"dcil": 8,
			"dcid": "0102030405060708"
		},
		"raw": {"length": 987, "payload_length": 1337},
		"frames": [
			{"frame_type": "max_stream_data", "stream_id": 42, "maximum": 987},
			{"frame_type": "stream", "stream_id": 123, "offset": 1234, "length": 6, "fin": true}
		],
		"ecn": "CE"
	}`, ev)
}

func TestPacketSent1RTT(t *testing.T) {
	t.Run("with datagram payload checksum", func(t *testing.T) {
		testPacketSent1RTT(t, 1337)
	})

	t.Run("without datagram payload checksum", func(t *testing.T) {
		testPacketSent1RTT(t, 0)
	})
}

func testPacketSent1RTT(t *testing.T, datagramPayloadChecksum DatagramPayloadChecksum) {
	name, ev := testEventEncoding(t, &PacketSent{
		Header: PacketHeader{
			PacketType:       PacketType1RTT,
			PacketNumber:     1337,
			KeyPhaseBit:      KeyPhaseZero,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		},
		Raw: RawInfo{Length: 123},
		Frames: []Frame{
			{Frame: &AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}}},
			{Frame: &MaxDataFrame{MaximumData: 987}},
		},
		ECN:                     ECNUnsupported,
		DatagramPayloadChecksum: datagramPayloadChecksum,
	})

	require.Equal(t, "transport:packet_sent", name)
	var checksum string
	if datagramPayloadChecksum != 0 {
		checksum = fmt.Sprintf(`"datagram_payload_checksum": %d,`, datagramPayloadChecksum)
	}
	require.JSONEq(t, fmt.Sprintf(`{
		%s
		"header": {"packet_type": "1RTT", "packet_number": 1337, "dcil": 4, "dcid": "01020304", "key_phase_bit": "0"},
		"raw": {"length": 123},
		"frames": [{"frame_type": "ack", "acked_ranges": [[1, 10]]}, {"frame_type": "max_data", "maximum": 987}]
	}`, checksum), ev)
}

func TestPacketReceived(t *testing.T) {
	name, ev := testEventEncoding(t, &PacketReceived{
		Header: PacketHeader{
			PacketType:       PacketTypeInitial,
			PacketNumber:     1337,
			Version:          protocol.Version1,
			SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			Token:            &Token{Raw: []byte{0xde, 0xad, 0xbe, 0xef}},
		},
		Raw: RawInfo{
			Length:        789,
			PayloadLength: 1234,
		},
		Frames: []Frame{
			{Frame: &MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987}},
			{Frame: &StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true}},
		},
		ECN:                     ECT0,
		DatagramPayloadChecksum: 42,
	})

	require.Equal(t, "transport:packet_received", name)
	require.JSONEq(t, `{
		"header": {
			"packet_type": "initial",
			"packet_number": 1337,
			"version": "1",
			"scil": 4,
			"scid": "04030201",
			"dcil": 8,
			"dcid": "0102030405060708",
			"token": {"data": "deadbeef"}
		},
		"raw": {"length": 789, "payload_length": 1234},
		"frames": [
			{"frame_type": "max_stream_data", "stream_id": 42, "maximum": 987},
			{"frame_type": "stream", "stream_id": 123, "offset": 1234, "length": 6, "fin": true}
		],
		"ecn": "ECT(0)",
		"datagram_payload_checksum": 42
	}`, ev)
}

func TestPacketReceived1RTT(t *testing.T) {
	t.Run("with datagram payload checksum", func(t *testing.T) {
		testPacketReceived1RTT(t, 1337)
	})

	t.Run("without datagram payload checksum", func(t *testing.T) {
		testPacketReceived1RTT(t, 0)
	})
}

func testPacketReceived1RTT(t *testing.T, datagramPayloadChecksum DatagramPayloadChecksum) {
	name, ev := testEventEncoding(t, &PacketReceived{
		Header: PacketHeader{
			PacketType:       PacketType1RTT,
			PacketNumber:     1337,
			KeyPhaseBit:      KeyPhaseZero,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		},
		Raw: RawInfo{Length: 789, PayloadLength: 1234},
		Frames: []Frame{
			{Frame: &MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987}},
			{Frame: &StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true}},
		},
		ECN:                     ECT1,
		DatagramPayloadChecksum: datagramPayloadChecksum,
	})

	require.Equal(t, "transport:packet_received", name)
	var checksum string
	if datagramPayloadChecksum != 0 {
		checksum = fmt.Sprintf(`"datagram_payload_checksum": %d,`, datagramPayloadChecksum)
	}
	require.JSONEq(t, fmt.Sprintf(`{
		%s
		"header": {
			"packet_type": "1RTT",
			"packet_number": 1337,
			"dcil": 8,
			"dcid": "0102030405060708",
			"key_phase_bit": "0"
		},
		"raw": {"length": 789, "payload_length": 1234},
		"frames": [
			{"frame_type": "max_stream_data", "stream_id": 42, "maximum": 987},
			{"frame_type": "stream", "stream_id": 123, "offset": 1234, "length": 6, "fin": true}
		],
		"ecn": "ECT(1)"
	}`, checksum), ev)
}

func TestPacketReceivedRetry(t *testing.T) {
	name, ev := testEventEncoding(t, &PacketReceived{
		Header: PacketHeader{
			PacketType:       PacketTypeRetry,
			Version:          protocol.Version1,
			SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			Token:            &Token{Raw: []byte{0xde, 0xad, 0xbe, 0xef}},
		},
		Raw: RawInfo{Length: 123},
	})

	require.Equal(t, "transport:packet_received", name)
	require.JSONEq(t, `{
		"header": {
			"packet_type": "retry",
			"version": "1",
			"scil": 4,
			"scid": "04030201",
			"dcil": 8,
			"dcid": "0102030405060708",
			"token": {"data": "deadbeef"}
		},
		"raw": {"length": 123}
	}`, ev)
}

func TestVersionNegotiationReceived(t *testing.T) {
	name, ev := testEventEncoding(t, &VersionNegotiationReceived{
		Header: PacketHeaderVersionNegotiation{
			SrcConnectionID:  ArbitraryLenConnectionID{4, 3, 2, 1},
			DestConnectionID: ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
		},
		SupportedVersions: []Version{0xdeadbeef, 0xdecafbad},
	})

	require.Equal(t, "transport:packet_received", name)
	require.JSONEq(t, `{
		"header": {
			"packet_type": "version_negotiation",
			"scil": 4,
			"scid": "04030201",
			"dcil": 8,
			"dcid": "0102030405060708"
		},
		"supported_versions": ["deadbeef", "decafbad"]
	}`, ev)
}

func TestPacketBuffered(t *testing.T) {
	name, ev := testEventEncoding(t, &PacketBuffered{
		Header: PacketHeader{
			PacketType:       PacketTypeHandshake,
			PacketNumber:     protocol.InvalidPacketNumber,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
		},
		Raw:                     RawInfo{Length: 1337},
		DatagramPayloadChecksum: 42,
	})

	require.Equal(t, "transport:packet_buffered", name)
	require.JSONEq(t, `{
		"header": {"packet_type": "handshake", "scil": 4, "scid": "04030201", "dcil": 8, "dcid": "0102030405060708"},
		"raw": {"length": 1337},
		"datagram_payload_checksum": 42,
		"trigger": "keys_unavailable"
	}`, ev)
}

func TestPacketDropped(t *testing.T) {
	name, ev := testEventEncoding(t, &PacketDropped{
		Header:                  PacketHeader{PacketType: PacketTypeRetry},
		Raw:                     RawInfo{Length: 1337},
		DatagramPayloadChecksum: 42,
		Trigger:                 PacketDropPayloadDecryptError,
	})

	require.Equal(t, "transport:packet_dropped", name)
	require.JSONEq(t, `{
		"header": {"packet_type": "retry", "scil": 0, "dcil": 0},
		"raw": {"length": 1337},
		"datagram_payload_checksum": 42,
		"trigger": "payload_decrypt_error"
	}`, ev)
}

func TestMetricsUpdated(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(15*time.Millisecond, 0)
	rttStats.UpdateRTT(20*time.Millisecond, 0)
	rttStats.UpdateRTT(25*time.Millisecond, 0)
	name, data := testEventEncoding(t, &MetricsUpdated{
		MinRTT:           rttStats.MinRTT(),
		SmoothedRTT:      rttStats.SmoothedRTT(),
		LatestRTT:        rttStats.LatestRTT(),
		RTTVariance:      rttStats.MeanDeviation(),
		CongestionWindow: 4321,
		BytesInFlight:    1234,
		PacketsInFlight:  42,
	})

	require.Equal(t, "recovery:metrics_updated", name)
	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(data), &ev))
	require.Equal(t, float64(15), ev["min_rtt"])
	require.Equal(t, float64(25), ev["latest_rtt"])
	require.Contains(t, ev, "smoothed_rtt")
	require.InDelta(t, rttStats.SmoothedRTT().Milliseconds(), ev["smoothed_rtt"], float64(1))
	require.Contains(t, ev, "rtt_variance")
	require.InDelta(t, rttStats.MeanDeviation().Milliseconds(), ev["rtt_variance"], float64(1))
	require.Equal(t, float64(4321), ev["congestion_window"])
	require.Equal(t, float64(1234), ev["bytes_in_flight"])
	require.Equal(t, float64(42), ev["packets_in_flight"])
}

func TestPacketLost(t *testing.T) {
	name, ev := testEventEncoding(t, &PacketLost{
		Header:  PacketHeader{PacketType: PacketTypeHandshake, PacketNumber: 42},
		Trigger: PacketLossReorderingThreshold,
	})

	require.Equal(t, "recovery:packet_lost", name)
	require.JSONEq(t, `{
		"header": {"packet_type": "handshake", "packet_number": 42, "scil": 0, "dcil": 0},
		"trigger": "reordering_threshold"
	}`, ev)
}

func TestSpuriousLoss(t *testing.T) {
	name, data := testEventEncoding(t, &SpuriousLoss{
		EncryptionLevel:  protocol.Encryption1RTT,
		PacketNumber:     42,
		PacketReordering: 1,
		TimeReordering:   1337 * time.Millisecond,
	})

	require.Equal(t, "recovery:spurious_loss", name)
	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(data), &ev))
	require.Contains(t, ev, "packet_number")
	require.Equal(t, float64(42), ev["packet_number"])
	require.Contains(t, ev, "reordering_packets")
	require.Equal(t, float64(1), ev["reordering_packets"])
	require.Contains(t, ev, "reordering_time")
	require.InDelta(t, 1337, ev["reordering_time"], float64(1))
}

func TestMTUUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &MTUUpdated{
		Value: 1337,
		Done:  true,
	})

	require.Equal(t, "recovery:mtu_updated", name)
	require.JSONEq(t, `{
		"mtu": 1337,
		"done": true
	}`, ev)
}

func TestCongestionStateUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &CongestionStateUpdated{
		State: CongestionStateCongestionAvoidance,
	})

	require.Equal(t, "recovery:congestion_state_updated", name)
	require.JSONEq(t, `{"new": "congestion_avoidance"}`, ev)
}

func TestPTOCountUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &PTOCountUpdated{PTOCount: 42})

	require.Equal(t, "recovery:metrics_updated", name)
	require.JSONEq(t, `{"pto_count": 42}`, ev)
}

func TestKeyUpdatedTLS(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyUpdated{
		Trigger:  KeyUpdateTLS,
		KeyType:  KeyTypeClientHandshake,
		KeyPhase: 0,
	})

	require.Equal(t, "security:key_updated", name)
	require.JSONEq(t, `{
		"key_type": "client_handshake_secret",
		"trigger": "tls"
	}`, ev)
}

func TestKeyUpdatedTLS1RTT(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyUpdated{
		Trigger:  KeyUpdateTLS,
		KeyType:  KeyTypeServer1RTT,
		KeyPhase: 0,
	})

	require.Equal(t, "security:key_updated", name)
	require.JSONEq(t, `{
		"key_type": "server_1rtt_secret",
		"trigger": "tls",
		"key_phase": 0
	}`, ev)
}

func TestKeyUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyUpdated{
		Trigger:  KeyUpdateRemote,
		KeyType:  KeyTypeClient1RTT,
		KeyPhase: 1337,
	})

	require.Equal(t, "security:key_updated", name)
	require.JSONEq(t, `{
		"key_type": "client_1rtt_secret",
		"trigger": "remote_update",
		"key_phase": 1337
	}`, ev)
}

func TestKeyDiscarded0RTT(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyDiscarded{
		KeyType:  KeyTypeServer0RTT,
		KeyPhase: 0,
	})

	require.Equal(t, "security:key_discarded", name)
	require.JSONEq(t, `{
		"key_type": "server_0rtt_secret",
		"trigger": "tls"
	}`, ev)
}

func TestKeyDiscarded(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyDiscarded{
		KeyType:  KeyTypeClient1RTT,
		KeyPhase: 42,
	})

	require.Equal(t, "security:key_discarded", name)
	require.JSONEq(t, `{
		"key_type": "client_1rtt_secret",
		"key_phase": 42
	}`, ev)
}

func TestLossTimerUpdated(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var buf bytes.Buffer
		tr := qlogwriter.NewConnectionFileSeq(
			nopWriteCloser(&buf),
			true,
			protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			[]string{EventSchema},
		)
		go tr.Run()
		producer := tr.AddProducer()

		synctest.Wait()
		time.Sleep(42 * time.Second)

		producer.RecordEvent(&LossTimerUpdated{
			Type:      LossTimerUpdateTypeSet,
			TimerType: TimerTypePTO,
			EncLevel:  protocol.EncryptionHandshake,
			Time:      time.Now().Add(1337 * time.Second),
		})
		producer.Close()

		name, ev := decode(t, buf.String())
		require.Equal(t, "recovery:loss_timer_updated", name)
		require.JSONEq(t, `{
			"event_type": "set",
			"timer_type": "pto",
			"packet_number_space": "handshake",
			"delta": 1337000
		}`, ev)
	})
}

func TestLossTimerUpdatedExpired(t *testing.T) {
	name, ev := testEventEncoding(t, &LossTimerUpdated{
		Type:      LossTimerUpdateTypeExpired,
		TimerType: TimerTypeACK,
		EncLevel:  protocol.Encryption1RTT,
	})

	require.Equal(t, "recovery:loss_timer_updated", name)
	require.JSONEq(t, `{
		"event_type": "expired",
		"timer_type": "ack",
		"packet_number_space": "application_data"
	}`, ev)
}

func TestLossTimerUpdatedCanceled(t *testing.T) {
	name, ev := testEventEncoding(t, &eventLossTimerCanceled{})

	require.Equal(t, "recovery:loss_timer_updated", name)
	require.JSONEq(t, `{"event_type": "cancelled"}`, ev)
}

func TestECNStateUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &ECNStateUpdated{
		State:   ECNStateUnknown,
		Trigger: "",
	})

	require.Equal(t, "recovery:ecn_state_updated", name)
	require.JSONEq(t, `{"new": "unknown"}`, ev)
}

func TestECNStateUpdatedWithTrigger(t *testing.T) {
	name, ev := testEventEncoding(t, &ECNStateUpdated{
		State:   ECNStateFailed,
		Trigger: "ACK doesn't contain ECN marks",
	})

	require.Equal(t, "recovery:ecn_state_updated", name)
	require.JSONEq(t, `{
		"new": "failed",
		"trigger": "ACK doesn't contain ECN marks"
	}`, ev)
}

func TestALPNInformation(t *testing.T) {
	name, ev := testEventEncoding(t, &ALPNInformation{
		ChosenALPN: "h3",
	})

	require.Equal(t, "transport:alpn_information", name)
	require.JSONEq(t, `{"chosen_alpn": "h3"}`, ev)
}

func TestDebugEvent(t *testing.T) {
	t.Run("default name", func(t *testing.T) {
		name, ev := testEventEncoding(t, &DebugEvent{Message: "hello world"})
		require.Equal(t, "transport:debug", name)
		require.JSONEq(t, `{"message": "hello world"}`, ev)
	})

	t.Run("custom name", func(t *testing.T) {
		name, ev := testEventEncoding(t, &DebugEvent{EventName: "foo", Message: "bar"})
		require.Equal(t, "transport:foo", name)
		require.JSONEq(t, `{"message": "bar"}`, ev)
	})
}
