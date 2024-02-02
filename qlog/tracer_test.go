package qlog

import (
	"bytes"
	"encoding/json"
	"time"

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
