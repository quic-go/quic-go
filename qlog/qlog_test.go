package qlog

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"

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
})
