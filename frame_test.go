package quic

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0xa0, 0x1, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.DataLengthPresent).To(BeTrue())
			Expect(frame.OffsetLength).To(BeZero())
			Expect(frame.StreamIDLength).To(Equal(uint8(1)))
			Expect(frame.StreamID).To(Equal(uint32(1)))
			Expect(frame.Offset).To(BeZero())
			Expect(frame.DataLength).To(Equal(uint16(6)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
		})

		It("accepts frame without datalength", func() {
			b := bytes.NewReader([]byte{0x80, 0x1, 'f', 'o', 'o', 'b', 'a', 'r'})
			frame, err := ParseStreamFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.FinBit).To(BeFalse())
			Expect(frame.DataLengthPresent).To(BeFalse())
			Expect(frame.OffsetLength).To(BeZero())
			Expect(frame.StreamIDLength).To(Equal(uint8(1)))
			Expect(frame.StreamID).To(Equal(uint32(1)))
			Expect(frame.Offset).To(BeZero())
			Expect(frame.DataLength).To(Equal(uint16(0)))
			Expect(frame.Data).To(Equal([]byte("foobar")))
		})
	})
})
