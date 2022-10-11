package qlog

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/francoispqt/gojay"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type mevent struct{}

var _ eventDetails = mevent{}

func (mevent) Category() category                   { return categoryConnectivity }
func (mevent) Name() string                         { return "mevent" }
func (mevent) IsNil() bool                          { return false }
func (mevent) MarshalJSONObject(enc *gojay.Encoder) { enc.StringKey("event", "details") }

var _ = Describe("Events", func() {
	It("marshals the fields before the event details", func() {
		buf := &bytes.Buffer{}
		enc := gojay.NewEncoder(buf)
		Expect(enc.Encode(event{
			RelativeTime: 1337 * time.Microsecond,
			eventDetails: mevent{},
		})).To(Succeed())

		var decoded interface{}
		Expect(json.Unmarshal(buf.Bytes(), &decoded)).To(Succeed())
		Expect(decoded).To(HaveLen(3))

		Expect(decoded).To(HaveKeyWithValue("time", 1.337))
		Expect(decoded).To(HaveKeyWithValue("name", "connectivity:mevent"))
		Expect(decoded).To(HaveKey("data"))
		data := decoded.(map[string]interface{})["data"].(map[string]interface{})
		Expect(data).To(HaveLen(1))
		Expect(data).To(HaveKeyWithValue("event", "details"))
	})
})
