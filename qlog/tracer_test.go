package qlog

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/Noooste/quic-go/internal/protocol"
	"github.com/Noooste/quic-go/logging"
	"github.com/stretchr/testify/require"
)

func newTracer() (*logging.Tracer, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	tracer := NewTracer(nopWriteCloser(buf))
	return tracer, buf
}

func TestTraceMetadata(t *testing.T) {
	tracer, buf := newTracer()
	tracer.Close()

	var m map[string]interface{}
	err := unmarshal(buf.Bytes(), &m)
	require.NoError(t, err)
	require.Equal(t, "0.3", m["qlog_version"])
	require.Contains(t, m, "title")
	require.Contains(t, m, "trace")
	trace := m["trace"].(map[string]interface{})
	require.Contains(t, trace, "common_fields")
	commonFields := trace["common_fields"].(map[string]interface{})
	require.NotContains(t, commonFields, "ODCID")
	require.NotContains(t, commonFields, "group_id")
	require.Contains(t, commonFields, "reference_time")
	referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
	require.WithinDuration(t, time.Now(), referenceTime, scaleDuration(10*time.Millisecond))
	require.Equal(t, "relative", commonFields["time_format"])
	require.Contains(t, trace, "vantage_point")
	vantagePoint := trace["vantage_point"].(map[string]interface{})
	require.Equal(t, "transport", vantagePoint["type"])
}

func TestTracerSentLongHeaderPacket(t *testing.T) {
	tracer, buf := newTracer()
	tracer.SentPacket(
		nil,
		&logging.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
			Length:           1337,
			Version:          protocol.Version1,
		},
		1234,
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
	require.Equal(t, float64(1234), raw["length"])
	require.Contains(t, ev, "header")
	hdr := ev["header"].(map[string]interface{})
	require.Equal(t, "handshake", hdr["packet_type"])
	require.Equal(t, "04030201", hdr["scid"])
	require.Contains(t, ev, "frames")
	frames := ev["frames"].([]interface{})
	require.Len(t, frames, 2)
	require.Equal(t, "max_stream_data", frames[0].(map[string]interface{})["frame_type"])
	require.Equal(t, "stream", frames[1].(map[string]interface{})["frame_type"])
}

func TestSendingVersionNegotiationPacket(t *testing.T) {
	tracer, buf := newTracer()
	tracer.SentVersionNegotiationPacket(
		nil,
		protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
		protocol.ArbitraryLenConnectionID{4, 3, 2, 1},
		[]protocol.Version{0xdeadbeef, 0xdecafbad},
	)
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:packet_sent", entry.Name)
	ev := entry.Event
	require.Contains(t, ev, "header")
	require.NotContains(t, ev, "frames")
	require.Contains(t, ev, "supported_versions")
	require.Equal(t, []interface{}{"deadbeef", "decafbad"}, ev["supported_versions"].([]interface{}))
	header := ev["header"]
	require.Equal(t, "version_negotiation", header.(map[string]interface{})["packet_type"])
	require.NotContains(t, header, "packet_number")
	require.NotContains(t, header, "version")
	require.Equal(t, "0102030405060708", header.(map[string]interface{})["dcid"])
	require.Equal(t, "04030201", header.(map[string]interface{})["scid"])
}

func TestDroppedPackets(t *testing.T) {
	tracer, buf := newTracer()
	addr := net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
	tracer.DroppedPacket(&addr, logging.PacketTypeInitial, 1337, logging.PacketDropPayloadDecryptError)
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
	require.Equal(t, "initial", hdr["packet_type"])
	require.Equal(t, "payload_decrypt_error", ev["trigger"])
}

func TestGenericTracerEvent(t *testing.T) {
	tracer, buf := newTracer()
	tracer.Debug("foo", "bar")
	tracer.Close()
	entry := exportAndParseSingle(t, buf)
	require.WithinDuration(t, time.Now(), entry.Time, scaleDuration(10*time.Millisecond))
	require.Equal(t, "transport:foo", entry.Name)
	ev := entry.Event
	require.Len(t, ev, 1)
	require.Equal(t, "bar", ev["details"])
}
