package quic

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AckFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x40, 0xA4, 0x03, 0x23, 0x45, 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC})
			frame, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.Entropy).To(Equal(byte(0xA4)))
			Expect(frame.LargestObserved).To(Equal(uint64(0x03)))
			Expect(frame.DelayTime).To(Equal(uint16(0x4523)))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame with a 48 bit packet number", func() {
			b := bytes.NewReader([]byte{0x4C, 0xA4, 0x37, 0x13, 0xAD, 0xFB, 0xCA, 0xDE, 0x23, 0x45, 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC})
			frame, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.LargestObserved).To(Equal(uint64(0xDECAFBAD1337)))
			Expect(b.Len()).To(Equal(0))
		})

		It("completely parses a frame with multiple timestamps", func() {
			b := bytes.NewReader([]byte{0x40, 0xA4, 0x03, 0x23, 0x45, 0x03, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0x12, 0x34, 0x56, 0x78, 0x90, 0xA0})
			_, err := ParseAckFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(0))
		})
	})

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
