package qlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

type limitedWriter struct {
	io.WriteCloser
	N       int
	written int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.N {
		return 0, errors.New("writer full")
	}
	n, err := w.WriteCloser.Write(p)
	w.written += n
	return n, err
}

type entry struct {
	Time  time.Time
	Name  string
	Event map[string]interface{}
}

var _ = Describe("Tracing", func() {
	It("stops writing when encountering an error", func() {
		buf := &bytes.Buffer{}
		t := NewConnectionTracer(
			&limitedWriter{WriteCloser: nopWriteCloser(buf), N: 250},
			protocol.PerspectiveServer,
			protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		)
		for i := uint32(0); i < 1000; i++ {
			t.UpdatedPTOCount(i)
		}

		b := &bytes.Buffer{}
		log.SetOutput(b)
		defer log.SetOutput(os.Stdout)
		t.Close()
		Expect(b.String()).To(ContainSubstring("writer full"))
	})

	Context("connection tracer", func() {
		var (
			tracer *logging.ConnectionTracer
			buf    *bytes.Buffer
		)

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			tracer = NewConnectionTracer(
				nopWriteCloser(buf),
				logging.PerspectiveServer,
				protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			)
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
			Expect(commonFields).To(HaveKeyWithValue("ODCID", "deadbeef"))
			Expect(commonFields).To(HaveKeyWithValue("group_id", "deadbeef"))
			Expect(commonFields).To(HaveKey("reference_time"))
			referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
			Expect(referenceTime).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
			Expect(commonFields).To(HaveKeyWithValue("time_format", "relative"))
			Expect(trace).To(HaveKey("vantage_point"))
			vantagePoint := trace["vantage_point"].(map[string]interface{})
			Expect(vantagePoint).To(HaveKeyWithValue("type", "server"))
		})

		Context("Events", func() {
			exportAndParse := func() []entry {
				tracer.Close()

				m := make(map[string]interface{})
				line, err := buf.ReadBytes('\n')
				Expect(err).ToNot(HaveOccurred())
				Expect(json.Unmarshal(line, &m)).To(Succeed())
				Expect(m).To(HaveKey("trace"))
				var entries []entry
				trace := m["trace"].(map[string]interface{})
				Expect(trace).To(HaveKey("common_fields"))
				commonFields := trace["common_fields"].(map[string]interface{})
				Expect(commonFields).To(HaveKey("reference_time"))
				referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
				Expect(trace).ToNot(HaveKey("events"))

				for buf.Len() > 0 {
					line, err := buf.ReadBytes('\n')
					Expect(err).ToNot(HaveOccurred())
					ev := make(map[string]interface{})
					Expect(json.Unmarshal(line, &ev)).To(Succeed())
					Expect(ev).To(HaveLen(3))
					Expect(ev).To(HaveKey("time"))
					Expect(ev).To(HaveKey("name"))
					Expect(ev).To(HaveKey("data"))
					entries = append(entries, entry{
						Time:  referenceTime.Add(time.Duration(ev["time"].(float64)*1e6) * time.Nanosecond),
						Name:  ev["name"].(string),
						Event: ev["data"].(map[string]interface{}),
					})
				}
				return entries
			}

			exportAndParseSingle := func() entry {
				entries := exportAndParse()
				Expect(entries).To(HaveLen(1))
				return entries[0]
			}

			It("records connection starts", func() {
				tracer.StartedConnection(
					&net.UDPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 42},
					&net.UDPAddr{IP: net.IPv4(192, 168, 12, 34), Port: 24},
					protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
					protocol.ParseConnectionID([]byte{5, 6, 7, 8}),
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_started"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("ip_version", "ipv4"))
				Expect(ev).To(HaveKeyWithValue("src_ip", "192.168.13.37"))
				Expect(ev).To(HaveKeyWithValue("src_port", float64(42)))
				Expect(ev).To(HaveKeyWithValue("dst_ip", "192.168.12.34"))
				Expect(ev).To(HaveKeyWithValue("dst_port", float64(24)))
				Expect(ev).To(HaveKeyWithValue("src_cid", "01020304"))
				Expect(ev).To(HaveKeyWithValue("dst_cid", "05060708"))
			})

			It("records the version, if no version negotiation happened", func() {
				tracer.NegotiatedVersion(0x1337, nil, nil)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:version_information"))
				ev := entry.Event
				Expect(ev).To(HaveLen(1))
				Expect(ev).To(HaveKeyWithValue("chosen_version", "1337"))
			})

			It("records the version, if version negotiation happened", func() {
				tracer.NegotiatedVersion(0x1337, []logging.VersionNumber{1, 2, 3}, []logging.VersionNumber{4, 5, 6})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:version_information"))
				ev := entry.Event
				Expect(ev).To(HaveLen(3))
				Expect(ev).To(HaveKeyWithValue("chosen_version", "1337"))
				Expect(ev).To(HaveKey("client_versions"))
				Expect(ev["client_versions"].([]interface{})).To(Equal([]interface{}{"1", "2", "3"}))
				Expect(ev).To(HaveKey("server_versions"))
				Expect(ev["server_versions"].([]interface{})).To(Equal([]interface{}{"4", "5", "6"}))
			})

			It("records idle timeouts", func() {
				tracer.ClosedConnection(&quic.IdleTimeoutError{})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(2))
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKeyWithValue("trigger", "idle_timeout"))
			})

			It("records handshake timeouts", func() {
				tracer.ClosedConnection(&quic.HandshakeTimeoutError{})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(2))
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKeyWithValue("trigger", "handshake_timeout"))
			})

			It("records a received stateless reset packet", func() {
				tracer.ClosedConnection(&quic.StatelessResetError{
					Token: protocol.StatelessResetToken{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(3))
				Expect(ev).To(HaveKeyWithValue("owner", "remote"))
				Expect(ev).To(HaveKeyWithValue("trigger", "stateless_reset"))
				Expect(ev).To(HaveKeyWithValue("stateless_reset_token", "00112233445566778899aabbccddeeff"))
			})

			It("records connection closing due to version negotiation failure", func() {
				tracer.ClosedConnection(&quic.VersionNegotiationError{})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(1))
				Expect(ev).To(HaveKeyWithValue("trigger", "version_mismatch"))
			})

			It("records application errors", func() {
				tracer.ClosedConnection(&quic.ApplicationError{
					Remote:       true,
					ErrorCode:    1337,
					ErrorMessage: "foobar",
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(3))
				Expect(ev).To(HaveKeyWithValue("owner", "remote"))
				Expect(ev).To(HaveKeyWithValue("application_code", float64(1337)))
				Expect(ev).To(HaveKeyWithValue("reason", "foobar"))
			})

			It("records transport errors", func() {
				tracer.ClosedConnection(&quic.TransportError{
					ErrorCode:    qerr.AEADLimitReached,
					ErrorMessage: "foobar",
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(3))
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKeyWithValue("connection_code", "aead_limit_reached"))
				Expect(ev).To(HaveKeyWithValue("reason", "foobar"))
			})

			It("records sent transport parameters", func() {
				rcid := protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad})
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
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKeyWithValue("original_destination_connection_id", "deadc0de"))
				Expect(ev).To(HaveKeyWithValue("initial_source_connection_id", "deadbeef"))
				Expect(ev).To(HaveKeyWithValue("retry_source_connection_id", "decafbad"))
				Expect(ev).To(HaveKeyWithValue("stateless_reset_token", "112233445566778899aabbccddeeff00"))
				Expect(ev).To(HaveKeyWithValue("max_idle_timeout", float64(321)))
				Expect(ev).To(HaveKeyWithValue("max_udp_payload_size", float64(1234)))
				Expect(ev).To(HaveKeyWithValue("ack_delay_exponent", float64(12)))
				Expect(ev).To(HaveKeyWithValue("active_connection_id_limit", float64(7)))
				Expect(ev).To(HaveKeyWithValue("initial_max_data", float64(4000)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_bidi_local", float64(1000)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_bidi_remote", float64(2000)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_uni", float64(3000)))
				Expect(ev).To(HaveKeyWithValue("initial_max_streams_bidi", float64(10)))
				Expect(ev).To(HaveKeyWithValue("initial_max_streams_uni", float64(20)))
				Expect(ev).ToNot(HaveKey("preferred_address"))
				Expect(ev).ToNot(HaveKey("max_datagram_frame_size"))
			})

			It("records the server's transport parameters, without a stateless reset token", func() {
				tracer.SentTransportParameters(&logging.TransportParameters{
					OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde}),
					ActiveConnectionIDLimit:         7,
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).ToNot(HaveKey("stateless_reset_token"))
			})

			It("records transport parameters without retry_source_connection_id", func() {
				tracer.SentTransportParameters(&logging.TransportParameters{
					StatelessResetToken: &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).ToNot(HaveKey("retry_source_connection_id"))
			})

			It("records transport parameters with a preferred address", func() {
				tracer.SentTransportParameters(&logging.TransportParameters{
					PreferredAddress: &logging.PreferredAddress{
						IPv4:                net.IPv4(12, 34, 56, 78),
						IPv4Port:            123,
						IPv6:                net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
						IPv6Port:            456,
						ConnectionID:        protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1}),
						StatelessResetToken: protocol.StatelessResetToken{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
					},
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKey("preferred_address"))
				pa := ev["preferred_address"].(map[string]interface{})
				Expect(pa).To(HaveKeyWithValue("ip_v4", "12.34.56.78"))
				Expect(pa).To(HaveKeyWithValue("port_v4", float64(123)))
				Expect(pa).To(HaveKeyWithValue("ip_v6", "102:304:506:708:90a:b0c:d0e:f10"))
				Expect(pa).To(HaveKeyWithValue("port_v6", float64(456)))
				Expect(pa).To(HaveKeyWithValue("connection_id", "0807060504030201"))
				Expect(pa).To(HaveKeyWithValue("stateless_reset_token", "0f0e0d0c0b0a09080706050403020100"))
			})

			It("records transport parameters that enable the datagram extension", func() {
				tracer.SentTransportParameters(&logging.TransportParameters{
					MaxDatagramFrameSize: 1337,
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("max_datagram_frame_size", float64(1337)))
			})

			It("records received transport parameters", func() {
				tracer.ReceivedTransportParameters(&logging.TransportParameters{})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("owner", "remote"))
				Expect(ev).ToNot(HaveKey("original_destination_connection_id"))
			})

			It("records restored transport parameters", func() {
				tracer.RestoredTransportParameters(&logging.TransportParameters{
					InitialMaxStreamDataBidiLocal:  100,
					InitialMaxStreamDataBidiRemote: 200,
					InitialMaxStreamDataUni:        300,
					InitialMaxData:                 400,
					MaxIdleTimeout:                 123 * time.Millisecond,
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_restored"))
				ev := entry.Event
				Expect(ev).ToNot(HaveKey("owner"))
				Expect(ev).ToNot(HaveKey("original_destination_connection_id"))
				Expect(ev).ToNot(HaveKey("stateless_reset_token"))
				Expect(ev).ToNot(HaveKey("retry_source_connection_id"))
				Expect(ev).ToNot(HaveKey("initial_source_connection_id"))
				Expect(ev).To(HaveKeyWithValue("max_idle_timeout", float64(123)))
				Expect(ev).To(HaveKeyWithValue("initial_max_data", float64(400)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_bidi_local", float64(100)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_bidi_remote", float64(200)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_uni", float64(300)))
			})

			It("records a sent long header packet, without an ACK", func() {
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
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_sent"))
				ev := entry.Event
				Expect(ev).To(HaveKey("raw"))
				raw := ev["raw"].(map[string]interface{})
				Expect(raw).To(HaveKeyWithValue("length", float64(987)))
				Expect(raw).To(HaveKeyWithValue("payload_length", float64(1337)))
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "handshake"))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
				Expect(ev).To(HaveKey("frames"))
				Expect(ev).To(HaveKeyWithValue("ecn", "CE"))
				frames := ev["frames"].([]interface{})
				Expect(frames).To(HaveLen(2))
				Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_stream_data"))
				Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "stream"))
			})

			It("records a sent short header packet, without an ACK", func() {
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
				entry := exportAndParseSingle()
				ev := entry.Event
				raw := ev["raw"].(map[string]interface{})
				Expect(raw).To(HaveKeyWithValue("length", float64(123)))
				Expect(raw).ToNot(HaveKey("payload_length"))
				Expect(ev).To(HaveKey("header"))
				Expect(ev).ToNot(HaveKey("ecn"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "1RTT"))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(ev).To(HaveKey("frames"))
				frames := ev["frames"].([]interface{})
				Expect(frames).To(HaveLen(2))
				Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "ack"))
				Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_data"))
			})

			It("records a received Long Header packet", func() {
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
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_received"))
				ev := entry.Event
				Expect(ev).To(HaveKey("raw"))
				raw := ev["raw"].(map[string]interface{})
				Expect(raw).To(HaveKeyWithValue("length", float64(789)))
				Expect(raw).To(HaveKeyWithValue("payload_length", float64(1234)))
				Expect(ev).To(HaveKeyWithValue("ecn", "ECT(0)"))
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "initial"))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
				Expect(hdr).To(HaveKey("token"))
				token := hdr["token"].(map[string]interface{})
				Expect(token).To(HaveKeyWithValue("data", "deadbeef"))
				Expect(ev).To(HaveKey("frames"))
				Expect(ev["frames"].([]interface{})).To(HaveLen(2))
			})

			It("records a received Short Header packet", func() {
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
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_received"))
				ev := entry.Event
				Expect(ev).To(HaveKey("raw"))
				raw := ev["raw"].(map[string]interface{})
				Expect(raw).To(HaveKeyWithValue("length", float64(789)))
				Expect(raw).To(HaveKeyWithValue("payload_length", float64(789-(1+8+3))))
				Expect(ev).To(HaveKeyWithValue("ecn", "ECT(1)"))
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "1RTT"))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(hdr).To(HaveKeyWithValue("key_phase_bit", "0"))
				Expect(ev).To(HaveKey("frames"))
				Expect(ev["frames"].([]interface{})).To(HaveLen(2))
			})

			It("records a received Retry packet", func() {
				tracer.ReceivedRetry(
					&logging.Header{
						Type:             protocol.PacketTypeRetry,
						DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
						SrcConnectionID:  protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
						Token:            []byte{0xde, 0xad, 0xbe, 0xef},
						Version:          protocol.Version1,
					},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_received"))
				ev := entry.Event
				Expect(ev).ToNot(HaveKey("raw"))
				Expect(ev).To(HaveKey("header"))
				header := ev["header"].(map[string]interface{})
				Expect(header).To(HaveKeyWithValue("packet_type", "retry"))
				Expect(header).ToNot(HaveKey("packet_number"))
				Expect(header).To(HaveKey("version"))
				Expect(header).To(HaveKey("dcid"))
				Expect(header).To(HaveKey("scid"))
				Expect(header).To(HaveKey("token"))
				token := header["token"].(map[string]interface{})
				Expect(token).To(HaveKeyWithValue("data", "deadbeef"))
				Expect(ev).ToNot(HaveKey("frames"))
			})

			It("records a received Version Negotiation packet", func() {
				tracer.ReceivedVersionNegotiationPacket(
					protocol.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					protocol.ArbitraryLenConnectionID{4, 3, 2, 1},
					[]protocol.VersionNumber{0xdeadbeef, 0xdecafbad},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_received"))
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

			It("records buffered packets", func() {
				tracer.BufferedPacket(logging.PacketTypeHandshake, 1337)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_buffered"))
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveLen(1))
				Expect(hdr).To(HaveKeyWithValue("packet_type", "handshake"))
				Expect(ev).To(HaveKey("raw"))
				Expect(ev["raw"].(map[string]interface{})).To(HaveKeyWithValue("length", float64(1337)))
				Expect(ev).To(HaveKeyWithValue("trigger", "keys_unavailable"))
			})

			It("records dropped packets", func() {
				tracer.DroppedPacket(logging.PacketTypeHandshake, 1337, logging.PacketDropPayloadDecryptError)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_dropped"))
				ev := entry.Event
				Expect(ev).To(HaveKey("raw"))
				Expect(ev["raw"].(map[string]interface{})).To(HaveKeyWithValue("length", float64(1337)))
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveLen(1))
				Expect(hdr).To(HaveKeyWithValue("packet_type", "handshake"))
				Expect(ev).To(HaveKeyWithValue("trigger", "payload_decrypt_error"))
			})

			It("records metrics updates", func() {
				now := time.Now()
				rttStats := utils.NewRTTStats()
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
					rttStats,
					4321,
					1234,
					42,
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:metrics_updated"))
				ev := entry.Event
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

			It("only logs the diff between two metrics updates", func() {
				now := time.Now()
				rttStats := utils.NewRTTStats()
				rttStats.UpdateRTT(15*time.Millisecond, 0, now)
				rttStats.UpdateRTT(20*time.Millisecond, 0, now)
				rttStats.UpdateRTT(25*time.Millisecond, 0, now)
				Expect(rttStats.MinRTT()).To(Equal(15 * time.Millisecond))

				rttStats2 := utils.NewRTTStats()
				rttStats2.UpdateRTT(15*time.Millisecond, 0, now)
				rttStats2.UpdateRTT(15*time.Millisecond, 0, now)
				rttStats2.UpdateRTT(15*time.Millisecond, 0, now)
				Expect(rttStats2.MinRTT()).To(Equal(15 * time.Millisecond))

				Expect(rttStats.LatestRTT()).To(Equal(25 * time.Millisecond))
				tracer.UpdatedMetrics(
					rttStats,
					4321,
					1234,
					42,
				)
				tracer.UpdatedMetrics(
					rttStats2,
					4321,
					12345, // changed
					42,
				)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(2))
				Expect(entries[0].Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entries[0].Name).To(Equal("recovery:metrics_updated"))
				Expect(entries[0].Event).To(HaveLen(7))
				Expect(entries[1].Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entries[1].Name).To(Equal("recovery:metrics_updated"))
				ev := entries[1].Event
				Expect(ev).ToNot(HaveKey("min_rtt"))
				Expect(ev).ToNot(HaveKey("congestion_window"))
				Expect(ev).ToNot(HaveKey("packets_in_flight"))
				Expect(ev).To(HaveKeyWithValue("bytes_in_flight", float64(12345)))
				Expect(ev).To(HaveKeyWithValue("smoothed_rtt", float64(15)))
			})

			It("records lost packets", func() {
				tracer.LostPacket(protocol.EncryptionHandshake, 42, logging.PacketLossReorderingThreshold)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:packet_lost"))
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveLen(2))
				Expect(hdr).To(HaveKeyWithValue("packet_type", "handshake"))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(42)))
				Expect(ev).To(HaveKeyWithValue("trigger", "reordering_threshold"))
			})

			It("records congestion state updates", func() {
				tracer.UpdatedCongestionState(logging.CongestionStateCongestionAvoidance)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:congestion_state_updated"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("new", "congestion_avoidance"))
			})

			It("records PTO changes", func() {
				tracer.UpdatedPTOCount(42)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:metrics_updated"))
				Expect(entry.Event).To(HaveKeyWithValue("pto_count", float64(42)))
			})

			It("records TLS key updates", func() {
				tracer.UpdatedKeyFromTLS(protocol.EncryptionHandshake, protocol.PerspectiveClient)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("security:key_updated"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("key_type", "client_handshake_secret"))
				Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
				Expect(ev).ToNot(HaveKey("generation"))
				Expect(ev).ToNot(HaveKey("old"))
				Expect(ev).ToNot(HaveKey("new"))
			})

			It("records TLS key updates, for 1-RTT keys", func() {
				tracer.UpdatedKeyFromTLS(protocol.Encryption1RTT, protocol.PerspectiveServer)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("security:key_updated"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("key_type", "server_1rtt_secret"))
				Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
				Expect(ev).To(HaveKeyWithValue("generation", float64(0)))
				Expect(ev).ToNot(HaveKey("old"))
				Expect(ev).ToNot(HaveKey("new"))
			})

			It("records QUIC key updates", func() {
				tracer.UpdatedKey(1337, true)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(2))
				var keyTypes []string
				for _, entry := range entries {
					Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
					Expect(entry.Name).To(Equal("security:key_updated"))
					ev := entry.Event
					Expect(ev).To(HaveKeyWithValue("generation", float64(1337)))
					Expect(ev).To(HaveKeyWithValue("trigger", "remote_update"))
					Expect(ev).To(HaveKey("key_type"))
					keyTypes = append(keyTypes, ev["key_type"].(string))
				}
				Expect(keyTypes).To(ContainElement("server_1rtt_secret"))
				Expect(keyTypes).To(ContainElement("client_1rtt_secret"))
			})

			It("records dropped encryption levels", func() {
				tracer.DroppedEncryptionLevel(protocol.EncryptionInitial)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(2))
				var keyTypes []string
				for _, entry := range entries {
					Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
					Expect(entry.Name).To(Equal("security:key_discarded"))
					ev := entry.Event
					Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
					Expect(ev).To(HaveKey("key_type"))
					keyTypes = append(keyTypes, ev["key_type"].(string))
				}
				Expect(keyTypes).To(ContainElement("server_initial_secret"))
				Expect(keyTypes).To(ContainElement("client_initial_secret"))
			})

			It("records dropped 0-RTT keys", func() {
				tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(1))
				entry := entries[0]
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("security:key_discarded"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
				Expect(ev).To(HaveKeyWithValue("key_type", "server_0rtt_secret"))
			})

			It("records dropped keys", func() {
				tracer.DroppedKey(42)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(2))
				var keyTypes []string
				for _, entry := range entries {
					Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
					Expect(entry.Name).To(Equal("security:key_discarded"))
					ev := entry.Event
					Expect(ev).To(HaveKeyWithValue("generation", float64(42)))
					Expect(ev).ToNot(HaveKey("trigger"))
					Expect(ev).To(HaveKey("key_type"))
					keyTypes = append(keyTypes, ev["key_type"].(string))
				}
				Expect(keyTypes).To(ContainElement("server_1rtt_secret"))
				Expect(keyTypes).To(ContainElement("client_1rtt_secret"))
			})

			It("records when the timer is set", func() {
				timeout := time.Now().Add(137 * time.Millisecond)
				tracer.SetLossTimer(logging.TimerTypePTO, protocol.EncryptionHandshake, timeout)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:loss_timer_updated"))
				ev := entry.Event
				Expect(ev).To(HaveLen(4))
				Expect(ev).To(HaveKeyWithValue("event_type", "set"))
				Expect(ev).To(HaveKeyWithValue("timer_type", "pto"))
				Expect(ev).To(HaveKeyWithValue("packet_number_space", "handshake"))
				Expect(ev).To(HaveKey("delta"))
				delta := time.Duration(ev["delta"].(float64)*1e6) * time.Nanosecond
				Expect(entry.Time.Add(delta)).To(BeTemporally("~", timeout, scaleDuration(10*time.Microsecond)))
			})

			It("records when the loss timer expires", func() {
				tracer.LossTimerExpired(logging.TimerTypeACK, protocol.Encryption1RTT)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:loss_timer_updated"))
				ev := entry.Event
				Expect(ev).To(HaveLen(3))
				Expect(ev).To(HaveKeyWithValue("event_type", "expired"))
				Expect(ev).To(HaveKeyWithValue("timer_type", "ack"))
				Expect(ev).To(HaveKeyWithValue("packet_number_space", "application_data"))
			})

			It("records when the timer is canceled", func() {
				tracer.LossTimerCanceled()
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:loss_timer_updated"))
				ev := entry.Event
				Expect(ev).To(HaveLen(1))
				Expect(ev).To(HaveKeyWithValue("event_type", "cancelled"))
			})

			It("records an ECN state transition, without a trigger", func() {
				tracer.ECNStateUpdated(logging.ECNStateUnknown, logging.ECNTriggerNoTrigger)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:ecn_state_updated"))
				ev := entry.Event
				Expect(ev).To(HaveLen(1))
				Expect(ev).To(HaveKeyWithValue("new", "unknown"))
			})

			It("records an ECN state transition, with a trigger", func() {
				tracer.ECNStateUpdated(logging.ECNStateFailed, logging.ECNFailedNoECNCounts)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:ecn_state_updated"))
				ev := entry.Event
				Expect(ev).To(HaveLen(2))
				Expect(ev).To(HaveKeyWithValue("new", "failed"))
				Expect(ev).To(HaveKeyWithValue("trigger", "ACK doesn't contain ECN marks"))
			})

			It("records a generic event", func() {
				tracer.Debug("foo", "bar")
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:foo"))
				ev := entry.Event
				Expect(ev).To(HaveLen(1))
				Expect(ev).To(HaveKeyWithValue("details", "bar"))
			})
		})
	})
})
