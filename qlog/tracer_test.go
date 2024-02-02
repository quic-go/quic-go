package qlog

import (
	"bytes"
	"encoding/json"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Tracing", func() {
	var (
		tracer *logging.Tracer
		buf    *bytes.Buffer
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		tracer = NewTracer(nopWriteCloser(buf))
	})

	It("exports a trace that has the right metadata", func() {
		tracer.Close()

		m := make(map[string]interface{})
		Expect(json.Unmarshal(buf.Bytes(), &m)).To(Succeed())
		Expect(m).To(HaveKeyWithValue("qlog_version", "draft-02"))
		Expect(m).To(HaveKey("title"))
		Expect(m).To(HaveKey("trace"))
		trace := m["trace"].(map[string]interface{})
		Expect(trace).To(HaveKey(("common_fields")))
		commonFields := trace["common_fields"].(map[string]interface{})
		Expect(commonFields).ToNot(HaveKey("ODCID"))
		Expect(commonFields).ToNot(HaveKey("group_id"))
		Expect(commonFields).To(HaveKey("reference_time"))
		referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
		Expect(referenceTime).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
		Expect(commonFields).To(HaveKeyWithValue("time_format", "relative"))
		Expect(trace).To(HaveKey("vantage_point"))
		vantagePoint := trace["vantage_point"].(map[string]interface{})
		Expect(vantagePoint).To(HaveKeyWithValue("type", "transport"))
	})

	Context("Events", func() {
		It("records a sent long header packet, without an ACK", func() {
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
			entry := exportAndParseSingle(buf)
			Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
			Expect(entry.Name).To(Equal("transport:packet_sent"))
			ev := entry.Event
			Expect(ev).To(HaveKey("raw"))
			raw := ev["raw"].(map[string]interface{})
			Expect(raw).To(HaveKeyWithValue("length", float64(1234)))
			Expect(ev).To(HaveKey("header"))
			hdr := ev["header"].(map[string]interface{})
			Expect(hdr).To(HaveKeyWithValue("packet_type", "handshake"))
			Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
			Expect(ev).To(HaveKey("frames"))
			frames := ev["frames"].([]interface{})
			Expect(frames).To(HaveLen(2))
			Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_stream_data"))
			Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "stream"))
		})

		It("records sending of a Version Negotiation packet", func() {
			tracer.SentVersionNegotiationPacket(
				nil,
				protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				protocol.ArbitraryLenConnectionID{4, 3, 2, 1},
				[]protocol.Version{0xdeadbeef, 0xdecafbad},
			)
			tracer.Close()
			entry := exportAndParseSingle(buf)
			Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
			Expect(entry.Name).To(Equal("transport:packet_sent"))
			ev := entry.Event
			Expect(ev).To(HaveKey("header"))
			Expect(ev).ToNot(HaveKey("frames"))
			Expect(ev).To(HaveKey("supported_versions"))
			Expect(ev["supported_versions"].([]interface{})).To(Equal([]interface{}{"deadbeef", "decafbad"}))
			header := ev["header"]
			Expect(header).To(HaveKeyWithValue("packet_type", "version_negotiation"))
			Expect(header).ToNot(HaveKey("packet_number"))
			Expect(header).ToNot(HaveKey("version"))
			Expect(header).To(HaveKeyWithValue("dcid", "0102030405060708"))
			Expect(header).To(HaveKeyWithValue("scid", "04030201"))
		})

		It("records dropped packets", func() {
			addr := net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
			tracer.DroppedPacket(&addr, logging.PacketTypeInitial, 1337, logging.PacketDropPayloadDecryptError)
			tracer.Close()
			entry := exportAndParseSingle(buf)
			Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
			Expect(entry.Name).To(Equal("transport:packet_dropped"))
			ev := entry.Event
			Expect(ev).To(HaveKey("raw"))
			Expect(ev["raw"].(map[string]interface{})).To(HaveKeyWithValue("length", float64(1337)))
			Expect(ev).To(HaveKey("header"))
			hdr := ev["header"].(map[string]interface{})
			Expect(hdr).To(HaveLen(1))
			Expect(hdr).To(HaveKeyWithValue("packet_type", "initial"))
			Expect(ev).To(HaveKeyWithValue("trigger", "payload_decrypt_error"))
		})

		It("records a generic event", func() {
			tracer.Debug("foo", "bar")
			tracer.Close()
			entry := exportAndParseSingle(buf)
			Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
			Expect(entry.Name).To(Equal("transport:foo"))
			ev := entry.Event
			Expect(ev).To(HaveLen(1))
			Expect(ev).To(HaveKeyWithValue("details", "bar"))
		})
	})
})
