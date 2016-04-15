package quic

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckFrame", func() {
	Context("when writing", func() {
		It("writes simple frames", func() {
			b := &bytes.Buffer{}
			(&AckFrame{
				Entropy:         2,
				LargestObserved: 1,
			}).Write(b)
			Expect(b.Bytes()).To(Equal([]byte{0x48, 0x02, 0x01, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0}))
		})
	})
})
