package fjson

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Encoder", func() {
	var (
		buf bytes.Buffer
		enc *Encoder
	)

	BeforeEach(func() {
		buf.Reset()
		enc = NewEncoder(&buf)
	})

	It("encodes an empty object", func() {
		enc.StartObject()
		enc.EndObject()
		Expect(buf.String()).To(Equal("{}"))
	})

	It("encodes an empty array", func() {
		enc.StartArray()
		enc.EndArray()
		Expect(buf.String()).To(Equal("[]"))
	})

	It("encodes a key/value pair", func() {
		enc.StartObject()
		enc.WriteKeyRaw("foo")
		enc.WriteStringRaw("bar")
		enc.EndObject()
		Expect(buf.String()).To(Equal(`{"foo":"bar"}`))
	})

	It("encodes a list", func() {
		enc.StartArray()
		enc.WriteBool(true)
		enc.WriteUint64(1337)
		enc.WriteStringRaw("foobar")
		enc.EndArray()
		Expect(buf.String()).To(Equal(`[true,1337,"foobar"]`))
	})

	It("encodes a list of lists", func() {
		enc.StartArray()
		enc.StartArray()
		enc.WriteStringRaw("foo")
		enc.WriteStringRaw("bar")
		enc.EndArray()
		enc.StartArray()
		enc.WriteInt(13)
		enc.WriteInt(37)
		enc.EndArray()
		enc.EndArray()
		Expect(buf.String()).To(Equal(`[["foo","bar"],[13,37]]`))
	})

	It("encodes a list of objects", func() {
		enc.StartArray()
		enc.StartObject()
		enc.WriteKeyRaw("foo")
		enc.WriteStringRaw("bar")
		enc.EndObject()
		enc.StartObject()
		enc.WriteKeyRaw("value")
		enc.WriteInt(1337)
		enc.EndObject()
		enc.EndArray()
		Expect(buf.String()).To(Equal(`[{"foo":"bar"},{"value":1337}]`))
	})

	It("encodes a nested object", func() {
		enc.StartObject()
		enc.WriteKeyRaw("foo")
		enc.WriteStringRaw("bar")
		enc.WriteKeyRaw("details")
		enc.StartObject()
		enc.WriteKeyRaw("value")
		enc.WriteInt(1337)
		enc.EndObject()
		enc.EndObject()
		Expect(buf.String()).To(Equal(`{"foo":"bar","details":{"value":1337}}`))
	})
})
