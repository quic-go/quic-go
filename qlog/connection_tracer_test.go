package qlog

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

func newConnectionTracer() (*logging.ConnectionTracer, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	tracer := NewConnectionTracer(
		nopWriteCloser(buf),
		logging.PerspectiveServer,
		protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
	)
	return tracer, buf
}

func TestConnectionTraceMetadata(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.Close()

	m := make(map[string]interface{})
	require.NoError(t, unmarshal(buf.Bytes(), &m))
	require.Equal(t, "0.3", m["qlog_version"])
	require.Contains(t, m, "title")
	require.Contains(t, m, "trace")
	trace := m["trace"].(map[string]interface{})
	require.Contains(t, trace, "common_fields")
	commonFields := trace["common_fields"].(map[string]interface{})
	require.Equal(t, "deadbeef", commonFields["ODCID"])
	require.Equal(t, "deadbeef", commonFields["group_id"])
	require.Contains(t, commonFields, "reference_time")
	referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
	require.WithinDuration(t, time.Now(), referenceTime, scaleDuration(10*time.Millisecond))
	require.Equal(t, "relative", commonFields["time_format"])
	require.Contains(t, trace, "vantage_point")
	vantagePoint := trace["vantage_point"].(map[string]interface{})
	require.Equal(t, "server", vantagePoint["type"])
}

func TestConnectionStarts(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.StartedConnection(
		&net.UDPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 42},
		&net.UDPAddr{IP: net.IPv4(192, 168, 12, 34), Port: 24},
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		protocol.ParseConnectionID([]byte{5, 6, 7, 8}),
	)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:connection_started", entry.Name)
	ev := entry.Event
	require.Equal(t, "ipv4", ev["ip_version"])
	require.Equal(t, "192.168.13.37", ev["src_ip"])
	require.Equal(t, float64(42), ev["src_port"])
	require.Equal(t, "192.168.12.34", ev["dst_ip"])
	require.Equal(t, float64(24), ev["dst_port"])
	require.Equal(t, "01020304", ev["src_cid"])
	require.Equal(t, "05060708", ev["dst_cid"])
}

func TestVersionNegotiation(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.NegotiatedVersion(0x1337, nil, nil)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:version_information", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 1)
	require.Equal(t, "1337", ev["chosen_version"])
}

func TestVersionNegotiationWithPriorAttempts(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.NegotiatedVersion(0x1337, []logging.Version{1, 2, 3}, []logging.Version{4, 5, 6})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:version_information", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 3)
	require.Equal(t, "1337", ev["chosen_version"])
	require.Equal(t, []interface{}{"1", "2", "3"}, ev["client_versions"])
	require.Equal(t, []interface{}{"4", "5", "6"}, ev["server_versions"])
}

func TestIdleTimeouts(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ClosedConnection(&quic.IdleTimeoutError{})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:connection_closed", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 2)
	require.Equal(t, "local", ev["owner"])
	require.Equal(t, "idle_timeout", ev["trigger"])
}

func TestHandshakeTimeouts(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ClosedConnection(&quic.HandshakeTimeoutError{})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:connection_closed", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 2)
	require.Equal(t, "local", ev["owner"])
	require.Equal(t, "handshake_timeout", ev["trigger"])
}

func TestReceivedStatelessResetPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ClosedConnection(&quic.StatelessResetError{})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:connection_closed", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 2)
	require.Equal(t, "remote", ev["owner"])
	require.Equal(t, "stateless_reset", ev["trigger"])
}

func TestVersionNegotiationFailure(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ClosedConnection(&quic.VersionNegotiationError{})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:connection_closed", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 1)
	require.Equal(t, "version_mismatch", ev["trigger"])
}

func TestApplicationErrors(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ClosedConnection(&quic.ApplicationError{
		Remote:       true,
		ErrorCode:    1337,
		ErrorMessage: "foobar",
	})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:connection_closed", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 3)
	require.Equal(t, "remote", ev["owner"])
	require.Equal(t, float64(1337), ev["application_code"])
	require.Equal(t, "foobar", ev["reason"])
}

func TestTransportErrors(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ClosedConnection(&quic.TransportError{
		ErrorCode:    qerr.AEADLimitReached,
		ErrorMessage: "foobar",
	})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:connection_closed", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 3)
	require.Equal(t, "local", ev["owner"])
	require.Equal(t, "aead_limit_reached", ev["connection_code"])
	require.Equal(t, "foobar", ev["reason"])
}

func TestSentTransportParameters(t *testing.T) {
	rcid := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})
	tracer, buf := newConnectionTracer()
	tracer.SentTransportParameters(&logging.TransportParameters{
		InitialMaxStreamDataBidiLocal:   1000,
		InitialMaxStreamDataBidiRemote:  2000,
		InitialMaxStreamDataUni:         3000,
		InitialMaxData:                  4000,
		MaxBidiStreamNum:                10,
		MaxUniStreamNum:                 20,
		MaxAckDelay:                     123 * time.Millisecond,
		AckDelayExponent:                12,
		DisableActiveMigration:          true,
		MaxUDPPayloadSize:               1234,
		MaxIdleTimeout:                  321 * time.Millisecond,
		StatelessResetToken:             &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		RetrySourceConnectionID:         &rcid,
		ActiveConnectionIDLimit:         7,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
	})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:parameters_set", entry.Name)
	ev := entry.Event
	require.Equal(t, "local", ev["owner"])
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
	require.NotContains(t, ev, "preferred_address")
	require.NotContains(t, ev, "max_datagram_frame_size")
}

func TestServerTransportParametersWithoutStatelessResetToken(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.SentTransportParameters(&logging.TransportParameters{
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}),
		ActiveConnectionIDLimit:         7,
	})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:parameters_set", entry.Name)
	ev := entry.Event
	require.NotContains(t, ev, "stateless_reset_token")
}

func TestTransportParametersWithoutRetrySourceConnectionID(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.SentTransportParameters(&logging.TransportParameters{
		StatelessResetToken: &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
	})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:parameters_set", entry.Name)
	ev := entry.Event
	require.Equal(t, "local", ev["owner"])
	require.NotContains(t, ev, "retry_source_connection_id")
}

func TestTransportParametersWithPreferredAddress(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.SentTransportParameters(&logging.TransportParameters{
		PreferredAddress: &logging.PreferredAddress{
			IPv4:                netip.AddrPortFrom(netip.AddrFrom4([4]byte{12, 34, 56, 78}), 123),
			IPv6:                netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 456),
			ConnectionID:        protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
			StatelessResetToken: protocol.StatelessResetToken{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		},
	})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:parameters_set", entry.Name)
	ev := entry.Event
	require.Equal(t, "local", ev["owner"])
	require.Contains(t, ev, "preferred_address")
	pa := ev["preferred_address"].(map[string]interface{})
	require.Equal(t, "12.34.56.78", pa["ip_v4"])
	require.Equal(t, float64(123), pa["port_v4"])
	require.Equal(t, "102:304:506:708:90a:b0c:d0e:f10", pa["ip_v6"])
	require.Equal(t, float64(456), pa["port_v6"])
	require.Equal(t, "0807060504030201", pa["connection_id"])
	require.Equal(t, "0f0e0d0c0b0a09080706050403020100", pa["stateless_reset_token"])
}

func TestTransportParametersWithDatagramExtension(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.SentTransportParameters(&logging.TransportParameters{
		MaxDatagramFrameSize: 1337,
	})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:parameters_set", entry.Name)
	ev := entry.Event
	require.Equal(t, float64(1337), ev["max_datagram_frame_size"])
}

func TestReceivedTransportParameters(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ReceivedTransportParameters(&logging.TransportParameters{})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:parameters_set", entry.Name)
	ev := entry.Event
	require.Equal(t, "remote", ev["owner"])
	require.NotContains(t, ev, "original_destination_connection_id")
}

func TestRestoredTransportParameters(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.RestoredTransportParameters(&logging.TransportParameters{
		InitialMaxStreamDataBidiLocal:  100,
		InitialMaxStreamDataBidiRemote: 200,
		InitialMaxStreamDataUni:        300,
		InitialMaxData:                 400,
		MaxIdleTimeout:                 123 * time.Millisecond,
	})
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:parameters_restored", entry.Name)
	ev := entry.Event
	require.NotContains(t, ev, "owner")
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

func TestSentLongHeaderPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.SentLongHeaderPacket(
		&logging.ExtendedHeader{
			Header: logging.Header{
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
				SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
				Length:           1337,
				Version:          protocol.Version1,
			},
			PacketNumber: 1337,
		},
		987,
		logging.ECNCE,
		nil,
		[]logging.Frame{
			&logging.MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987},
			&logging.StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true},
		},
	)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_sent", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "raw")
	raw := ev["raw"].(map[string]interface{})
	require.Equal(t, float64(987), raw["length"])
	require.Equal(t, float64(1337), raw["payload_length"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]interface{})
	require.Equal(t, "handshake", hdr["packet_type"])
	require.Equal(t, float64(1337), hdr["packet_number"])
	require.Equal(t, "04030201", hdr["scid"])
	require.Contains(t, ev, "frames")
	require.Equal(t, "CE", ev["ecn"])
	frames := ev["frames"].([]interface{})
	require.Len(t, frames, 2)
	require.Equal(t, "max_stream_data", frames[0].(map[string]interface{})["frame_type"])
	require.Equal(t, "stream", frames[1].(map[string]interface{})["frame_type"])
}

func TestSentShortHeaderPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.SentShortHeaderPacket(
		&logging.ShortHeader{
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			PacketNumber:     1337,
		},
		123,
		logging.ECNUnsupported,
		&logging.AckFrame{AckRanges: []logging.AckRange{{Smallest: 1, Largest: 10}}},
		[]logging.Frame{&logging.MaxDataFrame{MaximumData: 987}},
	)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	ev := entry.Event
	raw := ev["raw"].(map[string]interface{})
	require.Equal(t, float64(123), raw["length"])
	require.NotContains(t, raw, "payload_length")
	require.Contains(t, ev, "header")
	require.NotContains(t, ev, "ecn")
	hdr := ev["header"].(map[string]interface{})
	require.Equal(t, "1RTT", hdr["packet_type"])
	require.Equal(t, float64(1337), hdr["packet_number"])
	require.Contains(t, ev, "frames")
	frames := ev["frames"].([]interface{})
	require.Len(t, frames, 2)
	require.Equal(t, "ack", frames[0].(map[string]interface{})["frame_type"])
	require.Equal(t, "max_data", frames[1].(map[string]interface{})["frame_type"])
}

func TestReceivedLongHeaderPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ReceivedLongHeaderPacket(
		&logging.ExtendedHeader{
			Header: logging.Header{
				Type:             protocol.PacketTypeInitial,
				DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
				SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
				Token:            []byte{0xde, 0xad, 0xbe, 0xef},
				Length:           1234,
				Version:          protocol.Version1,
			},
			PacketNumber: 1337,
		},
		789,
		logging.ECT0,
		[]logging.Frame{
			&logging.MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987},
			&logging.StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true},
		},
	)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_received", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "raw")
	raw := ev["raw"].(map[string]interface{})
	require.Equal(t, float64(789), raw["length"])
	require.Equal(t, float64(1234), raw["payload_length"])
	require.Equal(t, "ECT(0)", ev["ecn"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]interface{})
	require.Equal(t, "initial", hdr["packet_type"])
	require.Equal(t, float64(1337), hdr["packet_number"])
	require.Equal(t, "04030201", hdr["scid"])
	require.Contains(t, hdr, "token")
	token := hdr["token"].(map[string]interface{})
	require.Equal(t, "deadbeef", token["data"])
	require.Contains(t, ev, "frames")
	require.Len(t, ev["frames"].([]interface{}), 2)
}

func TestReceivedShortHeaderPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	shdr := &logging.ShortHeader{
		DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		PacketNumber:     1337,
		PacketNumberLen:  protocol.PacketNumberLen3,
		KeyPhase:         protocol.KeyPhaseZero,
	}
	tracer.ReceivedShortHeaderPacket(
		shdr,
		789,
		logging.ECT1,
		[]logging.Frame{
			&logging.MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987},
			&logging.StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true},
		},
	)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_received", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "raw")
	raw := ev["raw"].(map[string]interface{})
	require.Equal(t, float64(789), raw["length"])
	require.Equal(t, float64(789-(1+8+3)), raw["payload_length"])
	require.Equal(t, "ECT(1)", ev["ecn"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]interface{})
	require.Equal(t, "1RTT", hdr["packet_type"])
	require.Equal(t, float64(1337), hdr["packet_number"])
	require.Equal(t, "0", hdr["key_phase_bit"])
	require.Contains(t, ev, "frames")
	require.Len(t, ev["frames"].([]interface{}), 2)
}

func TestReceivedRetryPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ReceivedRetry(
		&logging.Header{
			Type:             protocol.PacketTypeRetry,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
			Token:            []byte{0xde, 0xad, 0xbe, 0xef},
			Version:          protocol.Version1,
		},
	)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_received", entry.Name)
	ev := entry.Event
	require.NotContains(t, ev, "raw")
	require.Contains(t, ev, "header")
	header := ev["header"].(map[string]interface{})
	require.Equal(t, "retry", header["packet_type"])
	require.NotContains(t, header, "packet_number")
	require.Contains(t, header, "version")
	require.Contains(t, header, "dcid")
	require.Contains(t, header, "scid")
	require.Contains(t, header, "token")
	token := header["token"].(map[string]interface{})
	require.Equal(t, "deadbeef", token["data"])
	require.NotContains(t, ev, "frames")
}

func TestReceivedVersionNegotiationPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ReceivedVersionNegotiationPacket(
		protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
		protocol.ArbitraryLenConnectionID{4, 3, 2, 1},
		[]protocol.Version{0xdeadbeef, 0xdecafbad},
	)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_received", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "header")
	require.NotContains(t, ev, "frames")
	require.Contains(t, ev, "supported_versions")
	require.Equal(t, []interface{}{"deadbeef", "decafbad"}, ev["supported_versions"])
	header := ev["header"].(map[string]interface{})
	require.Equal(t, "version_negotiation", header["packet_type"])
	require.NotContains(t, header, "packet_number")
	require.NotContains(t, header, "version")
	require.Equal(t, "0102030405060708", header["dcid"])
	require.Equal(t, "04030201", header["scid"])
}

func TestBufferedPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.BufferedPacket(logging.PacketTypeHandshake, 1337)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_buffered", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]interface{})
	require.Len(t, hdr, 1)
	require.Equal(t, "handshake", hdr["packet_type"])
	require.Contains(t, ev, "raw")
	require.Equal(t, float64(1337), ev["raw"].(map[string]interface{})["length"])
	require.Equal(t, "keys_unavailable", ev["trigger"])
}

func TestDroppedPacket(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.DroppedPacket(logging.PacketTypeRetry, protocol.InvalidPacketNumber, 1337, logging.PacketDropPayloadDecryptError)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_dropped", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "raw")
	require.Equal(t, float64(1337), ev["raw"].(map[string]interface{})["length"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]interface{})
	require.Len(t, hdr, 1)
	require.Equal(t, "retry", hdr["packet_type"])
	require.Equal(t, "payload_decrypt_error", ev["trigger"])
}

func TestDroppedPacketWithPacketNumber(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.DroppedPacket(logging.PacketTypeHandshake, 42, 1337, logging.PacketDropDuplicate)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_dropped", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "raw")
	require.Equal(t, float64(1337), ev["raw"].(map[string]interface{})["length"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]interface{})
	require.Len(t, hdr, 2)
	require.Equal(t, "handshake", hdr["packet_type"])
	require.Equal(t, float64(42), hdr["packet_number"])
	require.Equal(t, "duplicate", ev["trigger"])
}

func TestUpdatedMetrics(t *testing.T) {
	var rttStats utils.RTTStats
	rttStats.UpdateRTT(15*time.Millisecond, 0)
	rttStats.UpdateRTT(20*time.Millisecond, 0)
	rttStats.UpdateRTT(25*time.Millisecond, 0)
	tracer, buf := newConnectionTracer()
	tracer.UpdatedMetrics(&rttStats, 4321, 1234, 42)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:metrics_updated", entry.Name)
	ev := entry.Event
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

func TestUpdatedMetricsDiff(t *testing.T) {
	var rttStats utils.RTTStats
	rttStats.UpdateRTT(15*time.Millisecond, 0)
	rttStats.UpdateRTT(20*time.Millisecond, 0)
	rttStats.UpdateRTT(25*time.Millisecond, 0)

	var rttStats2 utils.RTTStats
	rttStats2.UpdateRTT(15*time.Millisecond, 0)
	rttStats2.UpdateRTT(15*time.Millisecond, 0)
	rttStats2.UpdateRTT(15*time.Millisecond, 0)

	tracer, buf := newConnectionTracer()
	tracer.UpdatedMetrics(&rttStats, 4321, 1234, 42)
	tracer.UpdatedMetrics(&rttStats2, 4321, 12345 /* changed */, 42)
	tracer.UpdatedMetrics(&rttStats2, 0, 0, 0)
	tracer.Close()
	entries := exportAndParse(t, buf)
	require.Len(t, entries, 3)
	require.WithinDuration(t, time.Now(), entries[0].Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:metrics_updated", entries[0].Name)
	require.Len(t, entries[0].Event, 7)
	require.WithinDuration(t, time.Now(), entries[1].Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:metrics_updated", entries[1].Name)
	ev := entries[1].Event
	require.NotContains(t, ev, "min_rtt")
	require.NotContains(t, ev, "congestion_window")
	require.NotContains(t, ev, "packets_in_flight")
	require.Equal(t, float64(12345), ev["bytes_in_flight"])
	require.Equal(t, float64(15), ev["smoothed_rtt"])
	ev = entries[2].Event
	require.Contains(t, ev, "congestion_window")
	require.Contains(t, ev, "packets_in_flight")
	require.Contains(t, ev, "bytes_in_flight")
	require.Zero(t, ev["bytes_in_flight"])
	require.Zero(t, ev["packets_in_flight"])
	require.Zero(t, ev["congestion_window"])
}

func TestLostPackets(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.LostPacket(protocol.EncryptionHandshake, 42, logging.PacketLossReorderingThreshold)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:packet_lost", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]interface{})
	require.Len(t, hdr, 2)
	require.Equal(t, "handshake", hdr["packet_type"])
	require.Equal(t, float64(42), hdr["packet_number"])
	require.Equal(t, "reordering_threshold", ev["trigger"])
}

func TestMTUUpdates(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.UpdatedMTU(1337, true)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:mtu_updated", entry.Name)
	ev := entry.Event
	require.Equal(t, float64(1337), ev["mtu"])
	require.Equal(t, true, ev["done"])
}

func TestCongestionStateUpdates(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.UpdatedCongestionState(logging.CongestionStateCongestionAvoidance)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:congestion_state_updated", entry.Name)
	ev := entry.Event
	require.Equal(t, "congestion_avoidance", ev["new"])
}

func TestPTOChanges(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.UpdatedPTOCount(42)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:metrics_updated", entry.Name)
	require.Equal(t, float64(42), entry.Event["pto_count"])
}

func TestTLSKeyUpdates(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.UpdatedKeyFromTLS(protocol.EncryptionHandshake, protocol.PerspectiveClient)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "security:key_updated", entry.Name)
	ev := entry.Event
	require.Equal(t, "client_handshake_secret", ev["key_type"])
	require.Equal(t, "tls", ev["trigger"])
	require.NotContains(t, ev, "key_phase")
	require.NotContains(t, ev, "old")
	require.NotContains(t, ev, "new")
}

func TestTLSKeyUpdatesFor1RTTKeys(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.UpdatedKeyFromTLS(protocol.Encryption1RTT, protocol.PerspectiveServer)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "security:key_updated", entry.Name)
	ev := entry.Event
	require.Equal(t, "server_1rtt_secret", ev["key_type"])
	require.Equal(t, "tls", ev["trigger"])
	require.Equal(t, float64(0), ev["key_phase"])
	require.NotContains(t, ev, "old")
	require.NotContains(t, ev, "new")
}

func TestQUICKeyUpdates(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.UpdatedKey(1337, true)
	tracer.Close()
	entries := exportAndParse(t, buf)
	require.Len(t, entries, 2)
	var keyTypes []string
	for _, entry := range entries {
		require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
		require.Equal(t, "security:key_updated", entry.Name)
		ev := entry.Event
		require.Equal(t, float64(1337), ev["key_phase"])
		require.Equal(t, "remote_update", ev["trigger"])
		require.Contains(t, ev, "key_type")
		keyTypes = append(keyTypes, ev["key_type"].(string))
	}
	require.Contains(t, keyTypes, "server_1rtt_secret")
	require.Contains(t, keyTypes, "client_1rtt_secret")
}

func TestDroppedEncryptionLevels(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.DroppedEncryptionLevel(protocol.EncryptionInitial)
	tracer.Close()
	entries := exportAndParse(t, buf)
	require.Len(t, entries, 2)
	var keyTypes []string
	for _, entry := range entries {
		require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
		require.Equal(t, "security:key_discarded", entry.Name)
		ev := entry.Event
		require.Equal(t, "tls", ev["trigger"])
		require.Contains(t, ev, "key_type")
		keyTypes = append(keyTypes, ev["key_type"].(string))
	}
	require.Contains(t, keyTypes, "server_initial_secret")
	require.Contains(t, keyTypes, "client_initial_secret")
}

func TestDropped0RTTKeys(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
	tracer.Close()
	entries := exportAndParse(t, buf)
	require.Len(t, entries, 1)
	entry := entries[0]
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "security:key_discarded", entry.Name)
	ev := entry.Event
	require.Equal(t, "tls", ev["trigger"])
	require.Equal(t, "server_0rtt_secret", ev["key_type"])
}

func TestDroppedKeys(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.DroppedKey(42)
	tracer.Close()
	entries := exportAndParse(t, buf)
	require.Len(t, entries, 2)
	var keyTypes []string
	for _, entry := range entries {
		require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
		require.Equal(t, "security:key_discarded", entry.Name)
		ev := entry.Event
		require.Equal(t, float64(42), ev["key_phase"])
		require.NotContains(t, ev, "trigger")
		require.Contains(t, ev, "key_type")
		keyTypes = append(keyTypes, ev["key_type"].(string))
	}
	require.Contains(t, keyTypes, "server_1rtt_secret")
	require.Contains(t, keyTypes, "client_1rtt_secret")
}

func TestSetLossTimer(t *testing.T) {
	tracer, buf := newConnectionTracer()
	timeout := time.Now().Add(137 * time.Millisecond)
	tracer.SetLossTimer(logging.TimerTypePTO, protocol.EncryptionHandshake, timeout)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:loss_timer_updated", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 4)
	require.Equal(t, "set", ev["event_type"])
	require.Equal(t, "pto", ev["timer_type"])
	require.Equal(t, "handshake", ev["packet_number_space"])
	require.Contains(t, ev, "delta")
	delta := time.Duration(ev["delta"].(float64)*1e6) * time.Nanosecond
	require.WithinDuration(t, timeout, entry.Time.Add(delta), scaleDuration(10*time.Microsecond))
}

func TestExpiredLossTimer(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.LossTimerExpired(logging.TimerTypeACK, protocol.Encryption1RTT)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:loss_timer_updated", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 3)
	require.Equal(t, "expired", ev["event_type"])
	require.Equal(t, "ack", ev["timer_type"])
	require.Equal(t, "application_data", ev["packet_number_space"])
}

func TestCanceledLossTimer(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.LossTimerCanceled()
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:loss_timer_updated", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 1)
	require.Equal(t, "cancelled", ev["event_type"])
}

func TestECNStateTransitionWithoutTrigger(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ECNStateUpdated(logging.ECNStateUnknown, logging.ECNTriggerNoTrigger)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:ecn_state_updated", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 1)
	require.Equal(t, "unknown", ev["new"])
}

func TestECNStateTransitionWithTrigger(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedNoECNCounts)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "recovery:ecn_state_updated", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 2)
	require.Equal(t, "failed", ev["new"])
	require.Equal(t, "ACK doesn't contain ECN marks", ev["trigger"])
}

func TestGenericConnectionTracerEvent(t *testing.T) {
	tracer, buf := newConnectionTracer()
	tracer.Debug("foo", "bar")
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:foo", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 1)
	require.Equal(t, "bar", ev["details"])
}
