package qlog

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/stretchr/testify/require"
)

func testEventEncoding(t *testing.T, ev qlogwriter.Event) (string, map[string]any) {
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

func decode(t *testing.T, data string) (string, map[string]any) {
	t.Helper()

	var result map[string]any

	lines := bytes.Split([]byte(data), []byte{'\n'})
	require.Len(t, lines, 3) // the first line is the trace header, the second line is the event, the third line is empty
	require.Empty(t, lines[2])
	require.Equal(t, qlogwriter.RecordSeparator, lines[1][0], "expected record separator at start of line")
	require.NoError(t, json.Unmarshal(lines[1][1:], &result))
	require.Equal(t, 42*time.Second, time.Duration(result["time"].(float64)*1e6)*time.Nanosecond)

	return result["name"].(string), result["data"].(map[string]any)
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

	local, ok := ev["local"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "192.168.13.37", local["ip_v4"])
	require.Equal(t, float64(42), local["port_v4"])

	remote, ok := ev["remote"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "2001:db8::1", remote["ip_v6"])
	require.Equal(t, float64(24), remote["port_v6"])
}

func TestVersionInformation(t *testing.T) {
	name, ev := testEventEncoding(t, &VersionInformation{ChosenVersion: 0x1337})

	require.Equal(t, "transport:version_information", name)
	require.Len(t, ev, 1)
	require.Equal(t, "1337", ev["chosen_version"])
}

func TestVersionInformationWithNegotiation(t *testing.T) {
	name, ev := testEventEncoding(t, &VersionInformation{
		ChosenVersion:  0x1337,
		ClientVersions: []Version{1, 2, 3},
		ServerVersions: []Version{4, 5, 6},
	})

	require.Equal(t, "transport:version_information", name)
	require.Len(t, ev, 3)
	require.Equal(t, "1337", ev["chosen_version"])
	require.Equal(t, []any{"1", "2", "3"}, ev["client_versions"])
	require.Equal(t, []any{"4", "5", "6"}, ev["server_versions"])
}

func TestIdleTimeouts(t *testing.T) {
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator: InitiatorLocal,
		Trigger:   ConnectionCloseTriggerIdleTimeout,
	})

	require.Equal(t, "transport:connection_closed", name)
	require.Len(t, ev, 2)
	require.Equal(t, "local", ev["initiator"])
	require.Equal(t, "idle_timeout", ev["trigger"])
}

func TestReceivedStatelessResetPacket(t *testing.T) {
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator: InitiatorRemote,
		Trigger:   ConnectionCloseTriggerStatelessReset,
	})

	require.Equal(t, "transport:connection_closed", name)
	require.Len(t, ev, 2)
	require.Equal(t, "remote", ev["initiator"])
	require.Equal(t, "stateless_reset", ev["trigger"])
}

func TestVersionNegotiationFailure(t *testing.T) {
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator: InitiatorLocal,
		Trigger:   ConnectionCloseTriggerVersionMismatch,
	})

	require.Equal(t, "transport:connection_closed", name)
	require.Len(t, ev, 2)
	require.Equal(t, "local", ev["initiator"])
	require.Equal(t, "version_mismatch", ev["trigger"])
}

func TestApplicationErrors(t *testing.T) {
	code := qerr.ApplicationErrorCode(1337)
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator:        InitiatorRemote,
		ApplicationError: &code,
		Reason:           "foobar",
	})

	require.Equal(t, "transport:connection_closed", name)
	require.Len(t, ev, 4)
	require.Equal(t, "remote", ev["initiator"])
	require.Equal(t, "unknown", ev["application_error"])
	require.Equal(t, float64(1337), ev["error_code"])
	require.Equal(t, "foobar", ev["reason"])
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
			code := tt.code
			name, ev := testEventEncoding(t, &ConnectionClosed{
				Initiator:       InitiatorLocal,
				ConnectionError: &code,
				Reason:          "foobar",
			})

			require.Equal(t, "transport:connection_closed", name)
			require.Equal(t, "local", ev["initiator"])
			require.Equal(t, tt.want, ev["connection_error"])
			require.Equal(t, "foobar", ev["reason"])
			require.NotContains(t, ev, "error_code")
		})
	}
}

func TestTransportCryptoError(t *testing.T) {
	code := qerr.TransportErrorCode(0x100 + 0x2a)
	name, ev := testEventEncoding(t, &ConnectionClosed{
		Initiator:       InitiatorLocal,
		ConnectionError: &code,
		Reason:          "foobar",
	})

	require.Equal(t, "transport:connection_closed", name)
	require.Equal(t, "local", ev["initiator"])
	require.Equal(t, "crypto_error_0x12a", ev["connection_error"])
	require.Equal(t, "foobar", ev["reason"])
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
	require.Equal(t, "local", ev["initiator"])
	require.Equal(t, "deadc0de", ev["original_destination_connection_id"])
	require.Equal(t, "deadbeef", ev["initial_source_connection_id"])
	require.Equal(t, "decafbad", ev["retry_source_connection_id"])
	require.Equal(t, "112233445566778899aabbccddeeff00", ev["stateless_reset_token"])
	require.Equal(t, float64(321), ev["max_idle_timeout"])
	require.Equal(t, float64(1234), ev["max_udp_payload_size"])
	require.Equal(t, float64(12), ev["ack_delay_exponent"])
	require.Equal(t, float64(7), ev["active_connection_id_limit"])
	require.Equal(t, float64(4000), ev["initial_max_data"])
	require.Equal(t, float64(1000), ev["initial_max_stream_data_bidi_local"])
	require.Equal(t, float64(2000), ev["initial_max_stream_data_bidi_remote"])
	require.Equal(t, float64(3000), ev["initial_max_stream_data_uni"])
	require.Equal(t, float64(10), ev["initial_max_streams_bidi"])
	require.Equal(t, float64(20), ev["initial_max_streams_uni"])
	require.True(t, ev["reset_stream_at"].(bool))
	require.NotContains(t, ev, "preferred_address")
	require.NotContains(t, ev, "max_datagram_frame_size")
}

func TestServerTransportParametersWithoutStatelessResetToken(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator:                       InitiatorLocal,
		SentBy:                          protocol.PerspectiveServer,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}),
		ActiveConnectionIDLimit:         7,
	})

	require.Equal(t, "transport:parameters_set", name)
	require.NotContains(t, ev, "stateless_reset_token")
}

func TestTransportParametersWithoutRetrySourceConnectionID(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator:           InitiatorLocal,
		SentBy:              protocol.PerspectiveServer,
		StatelessResetToken: &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
	})

	require.Equal(t, "transport:parameters_set", name)
	require.Equal(t, "local", ev["initiator"])
	require.NotContains(t, ev, "retry_source_connection_id")
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
	require.Equal(t, "local", ev["initiator"])
	require.Contains(t, ev, "preferred_address")
	pa := ev["preferred_address"].(map[string]any)
	if hasIPv4 {
		require.Equal(t, "12.34.56.78", pa["ip_v4"])
		require.Equal(t, float64(123), pa["port_v4"])
	} else {
		require.NotContains(t, pa, "ip_v4")
		require.NotContains(t, pa, "port_v4")
	}
	if hasIPv6 {
		require.Equal(t, "102:304:506:708:90a:b0c:d0e:f10", pa["ip_v6"])
		require.Equal(t, float64(456), pa["port_v6"])
	} else {
		require.NotContains(t, pa, "ip_v6")
		require.NotContains(t, pa, "port_v6")
	}
	require.Equal(t, "0807060504030201", pa["connection_id"])
	require.Equal(t, "0f0e0d0c0b0a09080706050403020100", pa["stateless_reset_token"])
}

func TestTransportParametersWithDatagramExtension(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator:            InitiatorLocal,
		SentBy:               protocol.PerspectiveServer,
		MaxDatagramFrameSize: 1337,
	})

	require.Equal(t, "transport:parameters_set", name)
	require.Equal(t, float64(1337), ev["max_datagram_frame_size"])
}

func TestReceivedTransportParameters(t *testing.T) {
	name, ev := testEventEncoding(t, &ParametersSet{
		Initiator: InitiatorRemote,
		SentBy:    protocol.PerspectiveClient,
	})

	require.Equal(t, "transport:parameters_set", name)
	require.Equal(t, "remote", ev["initiator"])
	require.NotContains(t, ev, "original_destination_connection_id")
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
	require.NotContains(t, ev, "initiator")
	require.NotContains(t, ev, "original_destination_connection_id")
	require.NotContains(t, ev, "stateless_reset_token")
	require.NotContains(t, ev, "retry_source_connection_id")
	require.NotContains(t, ev, "initial_source_connection_id")
	require.Equal(t, float64(123), ev["max_idle_timeout"])
	require.Equal(t, float64(400), ev["initial_max_data"])
	require.Equal(t, float64(100), ev["initial_max_stream_data_bidi_local"])
	require.Equal(t, float64(200), ev["initial_max_stream_data_bidi_remote"])
	require.Equal(t, float64(300), ev["initial_max_stream_data_uni"])
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
	require.Contains(t, ev, "raw")
	raw := ev["raw"].(map[string]any)
	require.Equal(t, float64(987), raw["length"])
	require.Equal(t, float64(1337), raw["payload_length"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]any)
	require.Equal(t, "handshake", hdr["packet_type"])
	require.Equal(t, float64(1337), hdr["packet_number"])
	require.Equal(t, "04030201", hdr["scid"])
	require.Contains(t, ev, "frames")
	require.Equal(t, "CE", ev["ecn"])
	frames := ev["frames"].([]any)
	require.Len(t, frames, 2)
	require.Equal(t, "max_stream_data", frames[0].(map[string]any)["frame_type"])
	require.Equal(t, "stream", frames[1].(map[string]any)["frame_type"])
}

func TestPacketSentShort(t *testing.T) {
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
		ECN: ECNUnsupported,
	})

	require.Equal(t, "transport:packet_sent", name)
	raw := ev["raw"].(map[string]any)
	require.Equal(t, float64(123), raw["length"])
	require.NotContains(t, raw, "payload_length")
	require.Contains(t, ev, "header")
	require.NotContains(t, ev, "ecn")
	hdr := ev["header"].(map[string]any)
	require.Equal(t, "1RTT", hdr["packet_type"])
	require.Equal(t, float64(1337), hdr["packet_number"])
	require.Contains(t, ev, "frames")
	frames := ev["frames"].([]any)
	require.Len(t, frames, 2)
	require.Equal(t, "ack", frames[0].(map[string]any)["frame_type"])
	require.Equal(t, "max_data", frames[1].(map[string]any)["frame_type"])
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
		ECN: ECT0,
	})

	require.Equal(t, "transport:packet_received", name)
	require.Contains(t, ev, "raw")
	raw := ev["raw"].(map[string]any)
	require.Equal(t, float64(789), raw["length"])
	require.Equal(t, float64(1234), raw["payload_length"])
	require.Equal(t, "ECT(0)", ev["ecn"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]any)
	require.Equal(t, "initial", hdr["packet_type"])
	require.Equal(t, float64(1337), hdr["packet_number"])
	require.Equal(t, "04030201", hdr["scid"])
	require.Contains(t, hdr, "token")
	token := hdr["token"].(map[string]any)
	require.Equal(t, "deadbeef", token["data"])
	require.Contains(t, ev, "frames")
	require.Len(t, ev["frames"].([]any), 2)
}

func TestPacketReceived1RTT(t *testing.T) {
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
		ECN: ECT1,
	})

	require.Equal(t, "transport:packet_received", name)
	require.Contains(t, ev, "raw")
	raw := ev["raw"].(map[string]any)
	require.Equal(t, float64(789), raw["length"])
	require.Equal(t, float64(1234), raw["payload_length"])
	require.Equal(t, "ECT(1)", ev["ecn"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]any)
	require.Equal(t, "1RTT", hdr["packet_type"])
	require.Equal(t, float64(1337), hdr["packet_number"])
	require.Equal(t, "0", hdr["key_phase_bit"])
	require.Contains(t, ev, "frames")
	require.Len(t, ev["frames"].([]any), 2)
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
	require.Contains(t, ev, "raw")
	raw := ev["raw"].(map[string]any)
	require.Len(t, raw, 1)
	require.Equal(t, float64(123), raw["length"])
	require.Contains(t, ev, "header")
	header := ev["header"].(map[string]any)
	require.Equal(t, "retry", header["packet_type"])
	require.NotContains(t, header, "packet_number")
	require.Contains(t, header, "version")
	require.Contains(t, header, "dcid")
	require.Contains(t, header, "scid")
	require.Contains(t, header, "token")
	token := header["token"].(map[string]any)
	require.Equal(t, "deadbeef", token["data"])
	require.NotContains(t, ev, "frames")
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
	require.Contains(t, ev, "header")
	require.NotContains(t, ev, "frames")
	require.Contains(t, ev, "supported_versions")
	require.Equal(t, []any{"deadbeef", "decafbad"}, ev["supported_versions"])
	header := ev["header"].(map[string]any)
	require.Equal(t, "version_negotiation", header["packet_type"])
	require.NotContains(t, header, "packet_number")
	require.NotContains(t, header, "version")
	require.Equal(t, "0102030405060708", header["dcid"])
	require.Equal(t, "04030201", header["scid"])
}

func TestPacketBuffered(t *testing.T) {
	name, ev := testEventEncoding(t, &PacketBuffered{
		Header: PacketHeader{
			PacketType:       PacketTypeHandshake,
			PacketNumber:     protocol.InvalidPacketNumber,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
		},
		Raw: RawInfo{Length: 1337},
	})

	require.Equal(t, "transport:packet_buffered", name)
	require.Contains(t, ev, "header")
	require.Contains(t, ev, "raw")
	require.Equal(t, float64(1337), ev["raw"].(map[string]any)["length"])
	require.Contains(t, ev, "trigger")
	require.Equal(t, "keys_unavailable", ev["trigger"])
}

func TestPacketDropped(t *testing.T) {
	name, ev := testEventEncoding(t, &PacketDropped{
		Header:  PacketHeader{PacketType: PacketTypeRetry},
		Raw:     RawInfo{Length: 1337},
		Trigger: PacketDropPayloadDecryptError,
	})

	require.Equal(t, "transport:packet_dropped", name)
	require.Contains(t, ev, "raw")
	require.Equal(t, float64(1337), ev["raw"].(map[string]any)["length"])
	require.Contains(t, ev, "header")
	require.Equal(t, "payload_decrypt_error", ev["trigger"])
}

func TestMetricsUpdated(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(15*time.Millisecond, 0)
	rttStats.UpdateRTT(20*time.Millisecond, 0)
	rttStats.UpdateRTT(25*time.Millisecond, 0)
	name, ev := testEventEncoding(t, &MetricsUpdated{
		MinRTT:           rttStats.MinRTT(),
		SmoothedRTT:      rttStats.SmoothedRTT(),
		LatestRTT:        rttStats.LatestRTT(),
		RTTVariance:      rttStats.MeanDeviation(),
		CongestionWindow: 4321,
		BytesInFlight:    1234,
		PacketsInFlight:  42,
	})

	require.Equal(t, "recovery:metrics_updated", name)
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
	require.Contains(t, ev, "header")
	require.Equal(t, "reordering_threshold", ev["trigger"])
}

func TestSpuriousLoss(t *testing.T) {
	name, ev := testEventEncoding(t, &SpuriousLoss{
		EncryptionLevel:  protocol.Encryption1RTT,
		PacketNumber:     42,
		PacketReordering: 1,
		TimeReordering:   1337 * time.Millisecond,
	})

	require.Equal(t, "recovery:spurious_loss", name)
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
	require.Equal(t, float64(1337), ev["mtu"])
	require.Equal(t, true, ev["done"])
}

func TestCongestionStateUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &CongestionStateUpdated{
		State: CongestionStateCongestionAvoidance,
	})

	require.Equal(t, "recovery:congestion_state_updated", name)
	require.Equal(t, "congestion_avoidance", ev["new"])
}

func TestPTOCountUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &PTOCountUpdated{PTOCount: 42})

	require.Equal(t, "recovery:metrics_updated", name)
	require.Equal(t, float64(42), ev["pto_count"])
}

func TestKeyUpdatedTLS(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyUpdated{
		Trigger:  KeyUpdateTLS,
		KeyType:  KeyTypeClientHandshake,
		KeyPhase: 0,
	})

	require.Equal(t, "security:key_updated", name)
	require.Equal(t, "client_handshake_secret", ev["key_type"])
	require.Equal(t, "tls", ev["trigger"])
	require.NotContains(t, ev, "key_phase")
	require.NotContains(t, ev, "old")
	require.NotContains(t, ev, "new")
}

func TestKeyUpdatedTLS1RTT(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyUpdated{
		Trigger:  KeyUpdateTLS,
		KeyType:  KeyTypeServer1RTT,
		KeyPhase: 0,
	})

	require.Equal(t, "security:key_updated", name)
	require.Equal(t, "server_1rtt_secret", ev["key_type"])
	require.Equal(t, "tls", ev["trigger"])
	require.Equal(t, float64(0), ev["key_phase"])
	require.NotContains(t, ev, "old")
	require.NotContains(t, ev, "new")
}

func TestKeyUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyUpdated{
		Trigger:  KeyUpdateRemote,
		KeyType:  KeyTypeClient1RTT,
		KeyPhase: 1337,
	})

	require.Equal(t, "security:key_updated", name)
	require.Equal(t, float64(1337), ev["key_phase"])
	require.Equal(t, "remote_update", ev["trigger"])
	require.Contains(t, ev, "key_type")
	require.Equal(t, "client_1rtt_secret", ev["key_type"])
}

func TestKeyDiscarded0RTT(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyDiscarded{
		KeyType:  KeyTypeServer0RTT,
		KeyPhase: 0,
	})

	require.Equal(t, "security:key_discarded", name)
	require.Equal(t, "tls", ev["trigger"])
	require.Equal(t, "server_0rtt_secret", ev["key_type"])
}

func TestKeyDiscarded(t *testing.T) {
	name, ev := testEventEncoding(t, &KeyDiscarded{
		KeyType:  KeyTypeClient1RTT,
		KeyPhase: 42,
	})

	require.Equal(t, "security:key_discarded", name)
	require.Equal(t, float64(42), ev["key_phase"])
	require.NotContains(t, ev, "trigger")
	require.Contains(t, ev, "key_type")
	require.Equal(t, "client_1rtt_secret", ev["key_type"])
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
		require.Len(t, ev, 4)
		require.Equal(t, "set", ev["event_type"])
		require.Equal(t, "pto", ev["timer_type"])
		require.Equal(t, "handshake", ev["packet_number_space"])
		require.Contains(t, ev, "delta")
		delta := time.Duration(ev["delta"].(float64)*1e6) * time.Nanosecond
		require.Equal(t, 1337*time.Second, delta)
	})
}

func TestLossTimerUpdatedExpired(t *testing.T) {
	name, ev := testEventEncoding(t, &LossTimerUpdated{
		Type:      LossTimerUpdateTypeExpired,
		TimerType: TimerTypeACK,
		EncLevel:  protocol.Encryption1RTT,
	})

	require.Equal(t, "recovery:loss_timer_updated", name)
	require.Len(t, ev, 3)
	require.Equal(t, "expired", ev["event_type"])
	require.Equal(t, "ack", ev["timer_type"])
	require.Equal(t, "application_data", ev["packet_number_space"])
}

func TestLossTimerUpdatedCanceled(t *testing.T) {
	name, ev := testEventEncoding(t, &eventLossTimerCanceled{})

	require.Equal(t, "recovery:loss_timer_updated", name)
	require.Len(t, ev, 1)
	require.Equal(t, "cancelled", ev["event_type"])
}

func TestECNStateUpdated(t *testing.T) {
	name, ev := testEventEncoding(t, &ECNStateUpdated{
		State:   ECNStateUnknown,
		Trigger: "",
	})

	require.Equal(t, "recovery:ecn_state_updated", name)
	require.Len(t, ev, 1)
	require.Equal(t, "unknown", ev["new"])
}

func TestECNStateUpdatedWithTrigger(t *testing.T) {
	name, ev := testEventEncoding(t, &ECNStateUpdated{
		State:   ECNStateFailed,
		Trigger: "ACK doesn't contain ECN marks",
	})

	require.Equal(t, "recovery:ecn_state_updated", name)
	require.Len(t, ev, 2)
	require.Equal(t, "failed", ev["new"])
	require.Equal(t, "ACK doesn't contain ECN marks", ev["trigger"])
}

func TestALPNInformation(t *testing.T) {
	name, ev := testEventEncoding(t, &ALPNInformation{
		ChosenALPN: "h3",
	})

	require.Equal(t, "transport:alpn_information", name)
	require.Len(t, ev, 1)
	require.Equal(t, "h3", ev["chosen_alpn"])
}

func TestDebugEvent(t *testing.T) {
	t.Run("default name", func(t *testing.T) {
		name, ev := testEventEncoding(t, &DebugEvent{Message: "hello world"})
		require.Equal(t, "transport:debug", name)
		require.Len(t, ev, 1)
		require.Equal(t, "hello world", ev["message"])
	})

	t.Run("custom name", func(t *testing.T) {
		name, ev := testEventEncoding(t, &DebugEvent{EventName: "foo", Message: "bar"})
		require.Equal(t, "transport:foo", name)
		require.Len(t, ev, 1)
		require.Equal(t, "bar", ev["message"])
	})
}
