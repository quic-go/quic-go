package wire

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pool", func() {
	It("gets and puts STREAM frames", func() {
		f := GetStreamFrame()
		putStreamFrame(f)
	})

	It("panics when putting a STREAM frame with a wrong capacity", func() {
		f := GetStreamFrame()
		f.Data = []byte("foobar")
		Expect(func() { putStreamFrame(f) }).To(Panic())
	})

	It("accepts STREAM frames not from the buffer, but ignores them", func() {
		f := &StreamFrame{Data: []byte("foobar")}
		putStreamFrame(f)
	})
})
