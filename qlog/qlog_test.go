package qlog

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

var _ = Describe("Tracer", func() {
	var (
		tracer Tracer
		buf    *bytes.Buffer
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		tracer = NewTracer(
			nopWriteCloser(buf),
			protocol.PerspectiveServer,
			protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
		)
	})

	It("exports a trace that has the right metadata", func() {
		Expect(tracer.Export()).To(Succeed())

		m := make(map[string]interface{})
		Expect(json.Unmarshal(buf.Bytes(), &m)).To(Succeed())
		Expect(m).To(HaveKeyWithValue("qlog_version", "draft-02-wip"))
		Expect(m).To(HaveKey("title"))
		Expect(m).To(HaveKey("traces"))
		traces := m["traces"].([]interface{})
		Expect(traces).To(HaveLen(1))
		trace := traces[0].(map[string]interface{})
		Expect(trace).To(HaveKey(("common_fields")))
		commonFields := trace["common_fields"].(map[string]interface{})
		Expect(commonFields).To(HaveKeyWithValue("ODCID", "deadbeef"))
		Expect(commonFields).To(HaveKeyWithValue("group_id", "deadbeef"))
		Expect(trace).To(HaveKey("event_fields"))
		for i, ef := range trace["event_fields"].([]interface{}) {
			Expect(ef.(string)).To(Equal(eventFields[i]))
		}
		Expect(trace).To(HaveKey("vantage_point"))
		vantagePoint := trace["vantage_point"].(map[string]interface{})
		Expect(vantagePoint).To(HaveKeyWithValue("type", "server"))
	})

	Context("Events", func() {
		exportAndParse := func() (time.Time, string /* category */, string /* event */, map[string]interface{}) {
			Expect(tracer.Export()).To(Succeed())

			m := make(map[string]interface{})
			Expect(json.Unmarshal(buf.Bytes(), &m)).To(Succeed())
			Expect(m).To(HaveKey("traces"))
			traces := m["traces"].([]interface{})
			Expect(traces).To(HaveLen(1))
			trace := traces[0].(map[string]interface{})
			Expect(trace).To(HaveKey("events"))
			events := trace["events"].([]interface{})
			Expect(events).To(HaveLen(1))
			ev := events[0].([]interface{})
			Expect(ev).To(HaveLen(4))
			return time.Unix(0, int64(1e6*ev[0].(float64))), ev[1].(string), ev[2].(string), ev[3].(map[string]interface{})
		}

		It("records connection starts", func() {
			now := time.Now()
			tracer.StartedConnection(
				now,
				&net.UDPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 42},
				&net.UDPAddr{IP: net.IPv4(192, 168, 12, 34), Port: 24},
				0xdeadbeef,
				protocol.ConnectionID{1, 2, 3, 4},
				protocol.ConnectionID{5, 6, 7, 8},
			)
			t, category, eventName, ev := exportAndParse()
			Expect(t).To(BeTemporally("~", now, time.Millisecond))
			Expect(category).To(Equal("transport"))
			Expect(eventName).To(Equal("connection_started"))
			Expect(ev).To(HaveKeyWithValue("ip_version", "ipv4"))
			Expect(ev).To(HaveKeyWithValue("src_ip", "192.168.13.37"))
			Expect(ev).To(HaveKeyWithValue("src_port", float64(42)))
			Expect(ev).To(HaveKeyWithValue("dst_ip", "192.168.12.34"))
			Expect(ev).To(HaveKeyWithValue("dst_port", float64(24)))
			Expect(ev).To(HaveKeyWithValue("quic_version", "deadbeef"))
			Expect(ev).To(HaveKeyWithValue("src_cid", "01020304"))
			Expect(ev).To(HaveKeyWithValue("dst_cid", "05060708"))
		})

		It("records a sent packet, without an ACK", func() {
			now := time.Now()
			tracer.SentPacket(
				now,
				&wire.ExtendedHeader{
					Header: wire.Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeHandshake,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
						SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
						Version:          protocol.VersionTLS,
					},
					PacketNumber: 1337,
				},
				987,
				nil,
				[]wire.Frame{
					&wire.MaxStreamDataFrame{StreamID: 42, ByteOffset: 987},
					&wire.StreamFrame{StreamID: 123, Offset: 1234, Data: []byte("foobar"), FinBit: true},
				},
			)
			t, category, eventName, ev := exportAndParse()
			Expect(t).To(BeTemporally("~", now, time.Millisecond))
			Expect(category).To(Equal("transport"))
			Expect(eventName).To(Equal("packet_sent"))
			Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
			Expect(ev).To(HaveKey("header"))
			hdr := ev["header"].(map[string]interface{})
			Expect(hdr).To(HaveKeyWithValue("packet_size", float64(987)))
			Expect(hdr).To(HaveKeyWithValue("packet_number", "1337"))
			Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
			Expect(ev).To(HaveKey("frames"))
			frames := ev["frames"].([]interface{})
			Expect(frames).To(HaveLen(2))
			Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_stream_data"))
			Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "stream"))
		})

		It("records a sent packet, without an ACK", func() {
			tracer.SentPacket(
				time.Now(),
				&wire.ExtendedHeader{
					Header:       wire.Header{DestConnectionID: protocol.ConnectionID{1, 2, 3, 4}},
					PacketNumber: 1337,
				},
				123,
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 10}}},
				[]wire.Frame{&wire.MaxDataFrame{ByteOffset: 987}},
			)
			_, _, _, ev := exportAndParse()
			Expect(ev).To(HaveKeyWithValue("packet_type", "1RTT"))
			Expect(ev).To(HaveKey("header"))
			Expect(ev).To(HaveKey("frames"))
			frames := ev["frames"].([]interface{})
			Expect(frames).To(HaveLen(2))
			Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "ack"))
			Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_data"))
		})

		It("records a received packet", func() {
			now := time.Now()
			tracer.ReceivedPacket(
				now,
				&wire.ExtendedHeader{
					Header: wire.Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeInitial,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
						SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
						Version:          protocol.VersionTLS,
					},
					PacketNumber: 1337,
				},
				789,
				[]wire.Frame{
					&wire.MaxStreamDataFrame{StreamID: 42, ByteOffset: 987},
					&wire.StreamFrame{StreamID: 123, Offset: 1234, Data: []byte("foobar"), FinBit: true},
				},
			)
			t, category, eventName, ev := exportAndParse()
			Expect(t).To(BeTemporally("~", now, time.Millisecond))
			Expect(category).To(Equal("transport"))
			Expect(eventName).To(Equal("packet_received"))
			Expect(ev).To(HaveKeyWithValue("packet_type", "initial"))
			Expect(ev).To(HaveKey("header"))
			hdr := ev["header"].(map[string]interface{})
			Expect(hdr).To(HaveKeyWithValue("packet_size", float64(789)))
			Expect(hdr).To(HaveKeyWithValue("packet_number", "1337"))
			Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
			Expect(ev).To(HaveKey("frames"))
			Expect(ev["frames"].([]interface{})).To(HaveLen(2))
		})

		It("records a received Retry packet", func() {
			now := time.Now()
			tracer.ReceivedRetry(
				now,
				&wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeRetry,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
					Version:          protocol.VersionTLS,
				},
			)
			t, category, eventName, ev := exportAndParse()
			Expect(t).To(BeTemporally("~", now, time.Millisecond))
			Expect(category).To(Equal("transport"))
			Expect(eventName).To(Equal("packet_received"))
			Expect(ev).To(HaveKeyWithValue("packet_type", "retry"))
			Expect(ev).To(HaveKey("header"))
			Expect(ev).ToNot(HaveKey("frames"))
		})

		It("records metrics updates", func() {
			now := time.Now()
			rttStats := congestion.NewRTTStats()
			rttStats.UpdateRTT(15*time.Millisecond, 0, now)
			rttStats.UpdateRTT(20*time.Millisecond, 0, now)
			rttStats.UpdateRTT(25*time.Millisecond, 0, now)
			Expect(rttStats.MinRTT()).To(Equal(15 * time.Millisecond))
			Expect(rttStats.SmoothedRTT()).To(And(
				BeNumerically(">", 15*time.Millisecond),
				BeNumerically("<", 25*time.Millisecond),
			))
			Expect(rttStats.LatestRTT()).To(Equal(25 * time.Millisecond))
			tracer.UpdatedMetrics(
				now,
				rttStats,
				4321,
				1234,
				42,
			)
			t, category, eventName, ev := exportAndParse()
			Expect(t).To(BeTemporally("~", now, time.Millisecond))
			Expect(category).To(Equal("recovery"))
			Expect(eventName).To(Equal("metrics_updated"))
			Expect(ev).To(HaveKeyWithValue("min_rtt", float64(15)))
			Expect(ev).To(HaveKeyWithValue("latest_rtt", float64(25)))
			Expect(ev).To(HaveKey("smoothed_rtt"))
			Expect(time.Duration(ev["smoothed_rtt"].(float64)) * time.Millisecond).To(BeNumerically("~", rttStats.SmoothedRTT(), time.Millisecond))
			Expect(ev).To(HaveKey("rtt_variance"))
			Expect(time.Duration(ev["rtt_variance"].(float64)) * time.Millisecond).To(BeNumerically("~", rttStats.MeanDeviation(), time.Millisecond))
			Expect(ev).To(HaveKeyWithValue("congestion_window", float64(4321)))
			Expect(ev).To(HaveKeyWithValue("bytes_in_flight", float64(1234)))
			Expect(ev).To(HaveKeyWithValue("packets_in_flight", float64(42)))
		})

		It("records lost packets", func() {
			now := time.Now()
			tracer.LostPacket(now, protocol.EncryptionHandshake, 42, PacketLossReorderingThreshold)
			t, category, eventName, ev := exportAndParse()
			Expect(t).To(BeTemporally("~", now, time.Millisecond))
			Expect(category).To(Equal("recovery"))
			Expect(eventName).To(Equal("packet_lost"))
			Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
			Expect(ev).To(HaveKeyWithValue("packet_number", "42"))
			Expect(ev).To(HaveKeyWithValue("trigger", "reordering_threshold"))
		})
	})
})
